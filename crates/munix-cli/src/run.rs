//! `munix run`: one task, one sandboxed agent, behind the Gate.
//!
//! ```text
//! munix run [--plan <plan.yaml>] --prompt <text> [--image <image>] [--agent-dir <dir>] [--ledger <file>]
//!           -- <agent command...>
//! ```
//!
//! Without `--plan`, the Supervisor's planner writes and signs the plan from the prompt, the catalog and the
//! operator stores. With `--plan`, a hand-written plan file is rewritten for this run and signed here. The prompt
//! goes to Munix separately from the agent's own command line (design spec, Ingress).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use munix_adapters::{
    GuardDetector, MetaAdapter, ModelAdapter, Pricing, ReasoningEffort, Role, Usage,
};
use munix_core::crypto::{Digest, Purpose, Signed, SigningKey};
use munix_core::detect::{DEFAULT_THRESHOLD, DetectorConfig};
use munix_core::ids::{PlanId, SessionId, TaskId};
use munix_core::label::Confidential;
use munix_core::manifest::{Catalog, ToolManifest};
use munix_core::plan::Plan;
use munix_core::prompt::PromptEnvelope;
use munix_core::validate::Scalar;
use munix_gate::gate::{
    Gate, PlanNote, QuarantineNote, RecoverError, Store, StoreValue, TripReason,
};
use munix_gate::policy::DenyCode;
use munix_gate::quarantine::Cause;
use munix_gate::seal::{Root, Seal, SealCheck, SealGuard, SealWatch, Tamper};
use munix_gate::tool::Tool;
use munix_gate::vault::{Credential, Vault};
use munix_ledger::Ledger;
use munix_runtime::gateway::{ApiKey, Gateway, GatewayConfig};
use munix_runtime::mcp::{ServeEnd, serve};
use munix_runtime::sandbox::{Sandbox, SandboxSpec};
use munix_runtime::watchdog::{Limits, Snapshot, SystemClock, Trip, Watchdog};
use munix_supervisor::memory::PlanMemory;
use munix_supervisor::planner::{self, Planner};
use munix_supervisor::reviewer::Reviewer;
use munix_tools::email::SmtpEmail;
use munix_tools::site::SiteTemplates;
use munix_tools::webspeed::{WebSpeedConfig, WebSpeedOpen};

use crate::confirm::TerminalConfirmer;
use crate::front::{FrontProgress, GateFront, code_text};
use crate::term::terminal_safe;

const USAGE: &str = "usage: munix run [--plan <plan.yaml>] --prompt <text> [--image <image>] \
                     [--agent-dir <dir>] [--ledger <file>] -- <agent command...>";
const DEFAULT_IMAGE: &str = "munix-demo-agent";
const DEFAULT_AGENT_DIR: &str = "demo/agent";
pub(crate) const DEFAULT_MODEL: &str = "muse-spark-1.3";
const DEFAULT_BOSS: &str = "boss@corp.example";
const DEFAULT_HOST_GATEWAY: &str = "192.168.5.2";
const DEFAULT_WEBSPEED_DIR: &str = "../web-speed-oss";
const UPSTREAM: &str = "https://api.meta.ai/v1";
const GATEWAY_TIMEOUT: Duration = Duration::from_secs(120);
/// How often the Integrity Seal's watcher re-checks the sealed files.
const SEAL_POLL: Duration = Duration::from_millis(500);
/// What the vault holds for a manifest's credential. The local mail sink takes any login.
pub(crate) const PLACEHOLDER_CREDENTIAL: &str = "munix-placeholder-credential";
/// The defaults `SmtpEmail::from_env` uses, for when only one of the two variables is set.
const DEFAULT_SMTP: &str = "127.0.0.1:1025";
const DEFAULT_SMTP_FROM: &str = "agent@munix.example";

/// Why a run did not start or did not finish cleanly. The message is one line and never holds the API key or any
/// argument value.
#[derive(Debug)]
pub(crate) struct Failure {
    /// The process exit code: 2 for bad usage or config, 1 for a failure while running.
    pub(crate) code: u8,
    pub(crate) message: String,
}

impl Failure {
    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Failure {
            code: 2,
            message: message.into(),
        }
    }

    pub(crate) fn config(message: impl Into<String>) -> Self {
        Self::usage(message)
    }

    pub(crate) fn failed(message: impl Into<String>) -> Self {
        Failure {
            code: 1,
            message: message.into(),
        }
    }
}

/// What `munix run` was asked to do.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    plan: Option<PathBuf>,
    prompt: String,
    image: String,
    agent_dir: PathBuf,
    ledger: Option<PathBuf>,
    command: Vec<String>,
}

/// Parses `run [--plan <file>] --prompt <text> [...] -- <agent command...>`.
fn parse_args(args: &[String]) -> Result<Options, Failure> {
    let mut it = args.iter();
    if it.next().map(String::as_str) != Some("run") {
        return Err(Failure::usage(USAGE));
    }
    let mut plan = None;
    let mut prompt = None;
    let mut image = None;
    let mut agent_dir = None;
    let mut ledger = None;
    let mut command = Vec::new();
    while let Some(arg) = it.next() {
        if arg == "--" {
            command = it.by_ref().cloned().collect();
            break;
        }
        let slot = match arg.as_str() {
            "--plan" => &mut plan,
            "--prompt" => &mut prompt,
            "--image" => &mut image,
            "--agent-dir" => &mut agent_dir,
            "--ledger" => &mut ledger,
            _ => return Err(Failure::usage(USAGE)),
        };
        let Some(value) = it.next() else {
            return Err(Failure::usage(USAGE));
        };
        *slot = Some(value.clone());
    }
    let Some(prompt) = prompt else {
        return Err(Failure::usage(USAGE));
    };
    if command.is_empty() {
        return Err(Failure::usage(USAGE));
    }
    Ok(Options {
        plan: plan.map(PathBuf::from),
        prompt,
        image: image.unwrap_or_else(|| DEFAULT_IMAGE.to_owned()),
        agent_dir: PathBuf::from(agent_dir.unwrap_or_else(|| DEFAULT_AGENT_DIR.to_owned())),
        ledger: ledger.map(PathBuf::from),
        command,
    })
}

/// Reads `KEY=VALUE` lines: blank lines and `#` comments are skipped, `export ` is allowed, a value may be quoted,
/// and an unquoted value ends at ` #`. A later line for the same key wins.
fn parse_dotenv(text: &str) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let valid_key = key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !key.starts_with(|c: char| c.is_ascii_digit());
        if key.is_empty() || !valid_key {
            continue;
        }
        let value = value.trim();
        let quoted = ['"', '\'']
            .iter()
            .find_map(|q| value.strip_prefix(*q)?.strip_suffix(*q));
        let value = match quoted {
            Some(inner) => inner,
            None => value
                .split_once(" #")
                .map_or(value, |(before, _)| before.trim_end()),
        };
        vars.insert(key.to_owned(), value.to_owned());
    }
    vars
}

/// Configuration: the process environment, then `.env` for what the environment does not set.
pub(crate) struct Env {
    file: BTreeMap<String, String>,
    process: fn(&str) -> Option<String>,
}

impl Env {
    /// The real environment plus `path` if it exists.
    pub(crate) fn load(path: &Path) -> Result<Env, Failure> {
        let file = match std::fs::read_to_string(path) {
            Ok(text) => parse_dotenv(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(_) => return Err(Failure::config("cannot read .env")),
        };
        Ok(Env {
            file,
            process: |key| std::env::var(key).ok(),
        })
    }

    /// A variable already set in the environment wins over `.env`. An empty value counts as not set.
    pub(crate) fn get(&self, key: &str) -> Option<String> {
        (self.process)(key)
            .or_else(|| self.file.get(key).cloned())
            .filter(|v| !v.is_empty())
    }

    pub(crate) fn get_or(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or_else(|| default.to_owned())
    }
}

/// `bytes` random bytes from the operating system.
pub(crate) fn random_bytes(bytes: usize) -> Result<Vec<u8>, Failure> {
    let mut buf = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|_| Failure::failed("cannot read random bytes from /dev/urandom"))?;
    Ok(buf)
}

pub(crate) fn random_hex(bytes: usize) -> Result<String, Failure> {
    Ok(hex::encode(random_bytes(bytes)?))
}

/// The plan file's `task` and `plan` replaced by this run's ids, and its `prompt_hash` bound to the prompt.
pub(crate) fn rewrite_plan(
    mut plan: Plan,
    task: TaskId,
    plan_id: PlanId,
    prompt_hash: Digest,
) -> Plan {
    plan.task = task;
    plan.plan = plan_id;
    plan.prompt_hash = prompt_hash;
    plan
}

/// Every `*.yaml` in `dir`, in name order.
pub(crate) fn load_catalog(dir: &Path) -> Result<Catalog, Failure> {
    let entries = std::fs::read_dir(dir)
        .map_err(|_| Failure::config(format!("cannot read {}", dir.display())))?;
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml") && path.is_file())
        .collect();
    files.sort();
    let mut manifests = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path)
            .map_err(|_| Failure::config(format!("cannot read {}", path.display())))?;
        let manifest = ToolManifest::from_yaml(&text)
            .map_err(|e| Failure::config(format!("{}: {e}", path.display())))?;
        manifests.push(manifest);
    }
    Catalog::from_manifests(manifests)
        .map_err(|e| Failure::config(format!("{}: {e}", dir.display())))
}

/// The ledger name of the injection detector when none is given.
pub(crate) const DEFAULT_DETECTOR_NAME: &str = "Llama-Prompt-Guard-2-22M";
/// How long the Gate and the Readers wait for the detector sidecar before they count it as a flag.
const DETECTOR_TIMEOUT: Duration = Duration::from_secs(10);

/// A detector flag threshold: a finite number in `0.0..=1.0`.
pub(crate) fn parse_threshold(text: &str) -> Result<f32, Failure> {
    text.trim()
        .parse::<f32>()
        .ok()
        .filter(|t| t.is_finite() && (0.0..=1.0).contains(t))
        .ok_or_else(|| Failure::config("the detector threshold must be a number from 0 to 1"))
}

/// The injection detector for `url` (the loopback guard sidecar), recorded in the ledger as `name`. A URL that is
/// not `http://127.0.0.1:<port>/score` or `http://localhost:<port>/score`, or a bad name or threshold, is a
/// configuration error, so page text can't be sent off the machine by a typo.
pub(crate) fn detector_config(
    url: &str,
    name: &str,
    threshold: f32,
) -> Result<DetectorConfig, Failure> {
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err(Failure::config(
            "the detector name must be 1 to 64 printable characters",
        ));
    }
    let guard = GuardDetector::new(name, url, DETECTOR_TIMEOUT).ok_or_else(|| {
        Failure::config(
            "the detector URL must be http://127.0.0.1:<port>/score or http://localhost:<port>/score",
        )
    })?;
    DetectorConfig::new(Arc::new(guard), threshold)
        .ok_or_else(|| Failure::config("the detector threshold must be a number from 0 to 1"))
}

/// `MUNIX_DETECTOR_URL`, `MUNIX_DETECTOR_NAME` and `MUNIX_DETECTOR_THRESHOLD` from the environment then `.env`.
/// With no URL there is no detector (and a name or threshold alone is an error, so a typo can't silently turn
/// the detector off).
pub(crate) fn detector_from(env: &Env) -> Result<Option<DetectorConfig>, Failure> {
    let (url, name, threshold) = (
        env.get("MUNIX_DETECTOR_URL"),
        env.get("MUNIX_DETECTOR_NAME"),
        env.get("MUNIX_DETECTOR_THRESHOLD"),
    );
    let Some(url) = url else {
        if name.is_some() || threshold.is_some() {
            return Err(Failure::config(
                "MUNIX_DETECTOR_NAME and MUNIX_DETECTOR_THRESHOLD need MUNIX_DETECTOR_URL",
            ));
        }
        return Ok(None);
    };
    let threshold = match threshold {
        Some(text) => parse_threshold(&text)?,
        None => DEFAULT_THRESHOLD,
    };
    let name = name.unwrap_or_else(|| DEFAULT_DETECTOR_NAME.to_owned());
    detector_config(&url, &name, threshold).map(Some)
}

/// The Gate with the real tools registered at their manifests' digests.
fn build_gate(
    key: &SigningKey,
    catalog: &Catalog,
    ledger: Ledger,
    env: &Env,
    reader: Arc<dyn ModelAdapter>,
    detector: Option<DetectorConfig>,
) -> Result<Gate, Failure> {
    let web_config = || -> Result<WebSpeedConfig, Failure> {
        let mut config =
            WebSpeedConfig::from_dir(env.get_or("WEBSPEED_OSS_DIR", DEFAULT_WEBSPEED_DIR));
        config.allow_hosts = env.get("WEBSPEED_ALLOW_HOSTS");
        config.templates =
            SiteTemplates::load_dir("sites").map_err(|e| Failure::config(e.to_string()))?;
        Ok(config)
    };
    let mut vault = Vault::new();
    for (_, manifest) in catalog.iter() {
        if let Some(at) = &manifest.credentials {
            vault.insert(at.clone(), Credential::new(PLACEHOLDER_CREDENTIAL));
        }
    }
    let mut gate = Gate::new(key.clone(), catalog.clone(), vault, ledger);
    if let Some(config) = &detector {
        gate.set_detector(config.clone());
    }
    for (name, manifest) in catalog.iter() {
        let tool: Box<dyn Tool> = match name.as_str() {
            "web.open" => Box::new(
                WebSpeedOpen::new(web_config()?).map_err(|e| Failure::config(e.to_string()))?,
            ),
            // The Reader fetches with its own Web Speed child, so its reads never share state with the agent's.
            "reviews.read" => {
                let web =
                    WebSpeedOpen::new(web_config()?).map_err(|e| Failure::config(e.to_string()))?;
                Box::new(
                    munix_readers::reviews::ReviewReader::new(Arc::new(web), Arc::clone(&reader))
                        .with_detector(detector.clone()),
                )
            }
            "email.send" => Box::new(smtp_from(env)?),
            _ => continue,
        };
        let pinned = manifest
            .digest()
            .map_err(|e| Failure::config(e.to_string()))?;
        gate.register(name.clone(), pinned, tool)
            .map_err(|e| Failure::config(format!("registering {name}: {e}")))?;
    }
    Ok(gate)
}

/// `SmtpEmail::from_env`, but also reading `.env`.
fn smtp_from(env: &Env) -> Result<SmtpEmail, Failure> {
    let server = env.get("MUNIX_SMTP");
    let from = env.get("MUNIX_SMTP_FROM");
    let sink = if server.is_none() && from.is_none() {
        SmtpEmail::from_env()
    } else {
        SmtpEmail::new(
            &server.unwrap_or_else(|| DEFAULT_SMTP.to_owned()),
            &from.unwrap_or_else(|| DEFAULT_SMTP_FROM.to_owned()),
        )
    };
    sink.map_err(|e| Failure::config(e.to_string()))
}

enum Outcome {
    Finished,
    /// The agent was stopped; the string is the takeover code or the reason.
    Stopped(String),
}

/// What to do after one agent instance ends, given any takeover signal from the front and any trip from the
/// watchdog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NextStep {
    /// The agent finished without a takeover or a trip.
    Finish,
    /// The front saw a takeover (`Gate::submit` already halted the task): recover.
    RecoverFromTakeover,
    /// The watchdog tripped: call `Gate::trip` with this reason, then recover.
    TripAndRecover(TripReason),
}

fn trip_reason(trip: Trip) -> TripReason {
    match trip {
        Trip::Liveness => TripReason::Liveness,
        Trip::Deadline => TripReason::Deadline,
        Trip::SpinBudget => TripReason::SpinBudget,
    }
}

/// Decides what to do after one agent instance ends. A takeover recorded by the front takes precedence over a
/// watchdog trip because the Gate has already halted the task with the blocked values.
fn decide_after_instance(takeover: Option<DenyCode>, trip: Option<Trip>) -> NextStep {
    if takeover.is_some() {
        NextStep::RecoverFromTakeover
    } else if let Some(t) = trip {
        NextStep::TripAndRecover(trip_reason(t))
    } else {
        NextStep::Finish
    }
}

/// Words one quarantine note for the summary line, never including the item's text.
fn format_quarantine_note(note: &QuarantineNote) -> String {
    let where_it_was = match note.index {
        Some(idx) => format!("step {} {}[{idx}]", note.step, note.field),
        None => format!("step {} {}", note.step, note.field),
    };
    let why = match note.cause {
        Cause::TracedValue => "contained the destination of a blocked request",
        Cause::LowTrustFallback => "low-trust content read before a stall or off-plan call",
    };
    format!(
        "withheld: {where_it_was} ({}, trust {}): {why}",
        code_text(&note.region),
        note.trust.value()
    )
}

/// Container and network base name for one agent instance of `task`.
fn instance_sandbox_name(task: &TaskId, instance: u32) -> String {
    format!("{}-{instance}", task.as_str().to_lowercase())
}

/// Parses `args` (without the program name or the `run` word handled here) and runs. Exit codes: 0 when the agent
/// finished, 1 on a unrecovered takeover, paused recovery limit, or failure, 2 on bad usage or config. Errors are
/// one line on stderr and never contain the API key.
///
/// Steps:
/// 1. `run` as the first argument, then the flags above; `--` starts the agent command. Defaults: image
///    `munix-demo-agent`, agent dir `demo/agent`, ledger `runs/<task>.ledger.jsonl` (its directory is created).
/// 2. Read `.env` from the current directory if it exists (`KEY=VALUE` lines, `#` comments; variables already set
///    win). Require `MODEL_API_KEY`. Also read `MUNIX_WORKER_MODEL` (default `muse-spark-1.3`), `MUNIX_WORKER_EFFORT`,
///    `MUNIX_SUPERVISOR_MODEL` (default `muse-spark-1.3`), `MUNIX_BOSS_EMAIL` (default `boss@corp.example`),
///    `MUNIX_HOST_GATEWAY` (default `192.168.5.2`, Colima), `WEBSPEED_OSS_DIR` (default `../web-speed-oss`),
///    `WEBSPEED_ALLOW_HOSTS`, `MUNIX_SMTP`, `MUNIX_LIVENESS_SECS`, `MUNIX_DEADLINE_SECS`, and the optional injection
///    detector `MUNIX_DETECTOR_URL` (a loopback `/score` URL; unset means no detector), `MUNIX_DETECTOR_NAME`
///    (default `Llama-Prompt-Guard-2-22M`) and `MUNIX_DETECTOR_THRESHOLD` (default 0.5). The Gate and the review
///    Reader use it; it only lowers trust, and a failing detector flags.
/// 3. A fresh 32-byte signing key from `/dev/urandom`. Random hex ids: task `T-<8>`, session `S-<8>`, plan `P-<8>`,
///    nonce 32 hex characters.
/// 4. The catalog from `manifests/*.yaml`, the site templates from `sites/`, the tools (`web.open` through Web
///    Speed OSS with the allowlist and templates, `email.send` through `SmtpEmail::from_env`), a vault holding a
///    placeholder credential for each manifest's `credentials` ref (Mailpit takes any), a new ledger, and a `Gate`
///    with each tool registered at its manifest's digest.
/// 5. The prompt envelope, then either the `--plan` file (with its `task` and `plan` replaced by the new ids and its
///    `prompt_hash` set to the envelope's digest) or a plan written and signed by the Supervisor's `Planner`
///    (`MUNIX_SUPERVISOR_MODEL`, printing `munix: plan written by <model> (<n> steps)` to stderr). Sign the prompt,
///    build the Supervisor's `Reviewer`, and `start_task` with the store `contacts.boss = MUNIX_BOSS_EMAIL` (email,
///    internal).
/// 6. Start the model gateway on `127.0.0.1:0` for upstream `https://api.meta.ai/v1`, allowing only the worker
///    model, with a 120 s timeout.
/// 7. Loop over agent instances (1, 2, ...):
///    - Launch a fresh sandbox named `<task>-<instance>` (lowercase) with the image, the agent dir (absolute), the
///      command, env `MUNIX_WORKER_MODEL`, `MUNIX_WORKER_EFFORT` (if set), `MUNIX_BOSS_EMAIL`, the host gateway,
///      the gateway's port, and this crate's sibling `munix-runtime/relay/relay.py` and
///      `munix-runtime/shim/munix_shim.py`.
///    - Start a `Watchdog` polling the gateway's usage and activity together with the `GateFront`'s `FrontProgress`
///      (killing the agent container if a limit trips), and run `munix_runtime::mcp::serve` on the agent's stdout
///      and stdin with a fresh `GateFront` (with the current `TaskBrief`, `Reviewer`, and `FrontProgress`) and
///      `TerminalConfirmer`.
///    - After `serve` returns, stop the watchdog and kill the sandbox. On a takeover or watchdog trip, call
///      `Gate::trip` (when tripped) and `Gate::recover`: if recovered, print `munix: recovering (attempt N):
///      withheld K item(s)` and continue the loop with the recovery's brief; if `LimitReached`, print `munix:
///      paused: the task used its recoveries; the user must decide` and exit 1. Otherwise the agent finished and the
///      loop ends.
/// 8. Print a summary to stderr: the outcome, the context trust, any quarantined items (`gate.quarantined`, without
///    item text), the ledger path and entry count, and the gateway's token usage with an estimated cost.
pub fn main(args: Vec<String>) -> ExitCode {
    match run(&args) {
        Ok(Outcome::Finished) => ExitCode::SUCCESS,
        Ok(Outcome::Stopped(_)) => ExitCode::from(1),
        Err(failure) => {
            eprintln!("munix: {}", terminal_safe(&failure.message));
            ExitCode::from(failure.code)
        }
    }
}

/// A Meta adapter for one Supervisor role, configured from `munix run`'s own lookup (the environment, then `.env`)
/// rather than the process environment alone, so a key or effort set only in `.env` is used.
pub(crate) fn supervisor_adapter(
    env: &Env,
    model: &str,
    role: Role,
    api_key: &str,
) -> Result<Arc<dyn ModelAdapter>, Failure> {
    let effort = match env.get(role.env_var()) {
        Some(value) => value.parse::<ReasoningEffort>().map_err(|_| {
            Failure::config(format!(
                "{} must be minimal, low, medium, high, xhigh or max",
                role.env_var()
            ))
        })?,
        None => ReasoningEffort::default(),
    };
    let base_url = env.get_or("MUNIX_META_URL", "https://api.meta.ai/v1");
    let adapter = MetaAdapter::new(&base_url, model, api_key)
        .map_err(|e| Failure::config(e.to_string()))?
        .with_reasoning_effort(effort);
    Ok(Arc::new(adapter))
}

/// Prices for the cost estimate, from the environment then `.env` (defaults: the published Muse Spark 1.1 rates).
fn pricing_from(env: &Env) -> Result<Pricing, Failure> {
    let price = |key: &str, default: f64| -> Result<f64, Failure> {
        match env.get(key) {
            None => Ok(default),
            Some(v) => v
                .parse::<f64>()
                .ok()
                .filter(|p| p.is_finite() && *p >= 0.0)
                .ok_or_else(|| Failure::config(format!("{key} must be a non-negative number"))),
        }
    };
    Ok(Pricing {
        input_per_m: price("MUNIX_PRICE_INPUT_PER_M", 1.25)?,
        output_per_m: price("MUNIX_PRICE_OUTPUT_PER_M", 4.25)?,
    })
}

/// Watchdog limits from `watchdog::Limits::default()`, with `MUNIX_LIVENESS_SECS` and `MUNIX_DEADLINE_SECS`
/// overriding the two durations when set in the environment or `.env`.
fn limits_from(env: &Env) -> Result<Limits, Failure> {
    let secs = |key: &str, default: Duration| -> Result<Duration, Failure> {
        match env.get(key) {
            None => Ok(default),
            Some(v) => v
                .parse::<u64>()
                .ok()
                .filter(|s| *s > 0)
                .map(Duration::from_secs)
                .ok_or_else(|| Failure::config(format!("{key} must be a positive integer"))),
        }
    };
    let defaults = Limits::default();
    Ok(Limits {
        liveness: secs("MUNIX_LIVENESS_SECS", defaults.liveness)?,
        deadline: secs("MUNIX_DEADLINE_SECS", defaults.deadline)?,
        ..defaults
    })
}

/// What the Integrity Seal covers (invariant 11): the running binary; the workspace files and `crates/` where this
/// binary was built from; what `munix run` reads from the current directory (the manifests, site templates, example
/// plans, `.env` and the `--plan` file); and all of Web Speed OSS, which is spawned as a tool: its source tree and
/// its `venv` (the interpreter link, site-packages). Bytecode caches are skipped, and Web Speed is started with
/// `PYTHONPYCACHEPREFIX` pointing elsewhere so Python never reads them.
fn seal_roots(plan: Option<&Path>, webspeed_dir: &Path, plan_memory: Option<&Path>) -> Vec<Root> {
    // `crates/` and the workspace files are the source this binary was built from, wherever it is run.
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let mut roots = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        roots.push(Root::File(exe));
    }
    for file in ["Cargo.toml", "Cargo.lock", "clippy.toml"] {
        roots.push(Root::File(workspace.join(file)));
    }
    roots.push(Root::Tree(workspace.join("crates")));
    roots.push(Root::File(PathBuf::from(".env")));
    for dir in ["manifests", "sites", "examples"] {
        roots.push(Root::Tree(PathBuf::from(dir)));
    }
    if let Some(plan) = plan {
        roots.push(Root::File(plan.to_path_buf()));
    }
    // Stored plans are config like manifests: written only after a task, never while one runs.
    if let Some(dir) = plan_memory {
        roots.push(Root::Tree(dir.to_path_buf()));
    }
    // The tree skips `venv` by name (SKIP_DIRS), so the venv is its own root.
    roots.push(Root::Tree(webspeed_dir.to_path_buf()));
    roots.push(Root::Tree(webspeed_dir.join("venv")));
    roots
}

/// The stop message for a tamper, shown to the user and kept as the run's outcome.
fn tamper_message(tamper: &Tamper) -> String {
    format!(
        "Munix's own files changed during the task ({}); every task was stopped and nothing resumes. Start a new run",
        terminal_safe(&tamper.path)
    )
}

fn run(args: &[String]) -> Result<Outcome, Failure> {
    let opts = parse_args(args)?;
    let env = Env::load(Path::new(".env"))?;
    let api_key = env
        .get("MODEL_API_KEY")
        .ok_or_else(|| Failure::config("MODEL_API_KEY is not set (put it in .env)"))?;
    let worker_model = env.get_or("MUNIX_WORKER_MODEL", DEFAULT_MODEL);
    let worker_effort = env.get("MUNIX_WORKER_EFFORT");
    let supervisor_model = env.get_or("MUNIX_SUPERVISOR_MODEL", DEFAULT_MODEL);
    let boss_email = env.get_or("MUNIX_BOSS_EMAIL", DEFAULT_BOSS);
    let host_gateway = env.get_or("MUNIX_HOST_GATEWAY", DEFAULT_HOST_GATEWAY);
    let pricing = pricing_from(&env)?;
    let limits = limits_from(&env)?;

    // Plan memory (`docs/plan-memory.md`), only when the planner writes the plan.
    let plan_memory_dir = env
        .get("MUNIX_PLAN_MEMORY")
        .filter(|d| !d.is_empty() && opts.plan.is_none())
        .map(PathBuf::from);
    if let Some(dir) = &plan_memory_dir {
        std::fs::create_dir_all(dir)
            .map_err(|_| Failure::config("cannot create the plan memory directory"))?;
    }

    // The Integrity Seal, taken before anything it covers is read.
    let webspeed_dir = PathBuf::from(env.get_or("WEBSPEED_OSS_DIR", DEFAULT_WEBSPEED_DIR));
    let seal = Seal::take(seal_roots(
        opts.plan.as_deref(),
        &webspeed_dir,
        plan_memory_dir.as_deref(),
    ))
    .map_err(|e| Failure::config(format!("cannot seal Munix's files: {e}")))?;
    eprintln!(
        "munix: sealed {} files (digest {})",
        seal.file_count(),
        seal.digest().get(..12).unwrap_or(seal.digest())
    );
    let seal = Arc::new(SealGuard::new(seal));
    // `.env` was read just before the seal was taken; a change in between would become the sealed baseline.
    if Env::load(Path::new(".env"))?.file != env.file {
        return Err(Failure::config(
            ".env changed while munix run was starting; run it again",
        ));
    }

    // Identity: a fresh signing key and random ids for this run.
    let key =
        SigningKey::from_bytes(&random_bytes(32)?).map_err(|e| Failure::failed(e.to_string()))?;
    let task: TaskId = parse_id(&format!("T-{}", random_hex(4)?))?;
    let session: SessionId = parse_id(&format!("S-{}", random_hex(4)?))?;
    let plan_id: PlanId = parse_id(&format!("P-{}", random_hex(4)?))?;
    let nonce = random_hex(16)?;

    // The Gate.
    let catalog = load_catalog(Path::new("manifests"))?;
    let ledger_path = opts
        .ledger
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("runs/{task}.ledger.jsonl")));
    if let Some(dir) = ledger_path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .map_err(|_| Failure::config("cannot create the ledger directory"))?;
    }
    let ledger = Ledger::create(&ledger_path)
        .map_err(|e| Failure::config(format!("cannot create the ledger: {e}")))?;
    let reader_adapter = supervisor_adapter(&env, &supervisor_model, Role::Reader, &api_key)?;
    let detector = detector_from(&env)?;
    let mut gate = build_gate(&key, &catalog, ledger, &env, reader_adapter, detector)?;
    gate.set_seal(seal.clone());

    // The prompt and the plan, both signed here.
    let envelope = PromptEnvelope {
        task: task.clone(),
        session,
        nonce,
        text: opts.prompt.clone(),
        data: Vec::new(),
    };
    envelope
        .validate()
        .map_err(|e| Failure::config(format!("prompt: {e}")))?;
    let prompt_hash = envelope
        .digest()
        .map_err(|e| Failure::config(format!("prompt: {e}")))?;
    let sign_failed = |e: munix_core::error::Error| Failure::failed(e.to_string());
    let stores = BTreeMap::from([("contacts".to_owned(), vec!["boss".to_owned()])]);
    let memory = plan_memory_dir.as_ref().map(|dir| {
        let effort = env.get_or(Role::Planner.env_var(), "default");
        PlanMemory::open(dir, &catalog, &planner::version(&supervisor_model, &effort))
    });
    let mut reused = None;
    let plan = match &opts.plan {
        Some(plan_path) => {
            let plan_text = std::fs::read_to_string(plan_path)
                .map_err(|_| Failure::config(format!("cannot read {}", plan_path.display())))?;
            let plan = Plan::from_yaml(&plan_text)
                .map_err(|e| Failure::config(format!("{}: {e}", plan_path.display())))?;
            let plan = rewrite_plan(plan, task.clone(), plan_id, prompt_hash);
            Signed::sign(&key, Purpose::Plan, plan).map_err(sign_failed)?
        }
        None => {
            // A stored plan that matches and passes the planner's own checks replaces the planner call.
            let stored = memory.as_ref().and_then(|memory| {
                let (template, level) = memory.lookup(&envelope.text, &stores)?;
                let plan = PlanMemory::instantiate(
                    &template,
                    task.clone(),
                    plan_id.clone(),
                    prompt_hash.clone(),
                );
                planner::check_plan(&plan, &catalog, &stores).ok()?;
                Some((plan, template.key, level))
            });
            if let Some((plan, template, level)) = stored {
                eprintln!(
                    "munix: plan from plan memory ({} match, {} steps)",
                    level.as_str(),
                    plan.steps.len()
                );
                reused = Some((template, level));
                Signed::sign(&key, Purpose::Plan, plan).map_err(sign_failed)?
            } else {
                let adapter = supervisor_adapter(&env, &supervisor_model, Role::Planner, &api_key)?;
                let planner = Planner::new(adapter, key.clone());
                let plan = planner
                    .plan(&envelope, &catalog, &stores, plan_id)
                    .map_err(|e| Failure::config(e.to_string()))?;
                eprintln!(
                    "munix: plan written by {supervisor_model} ({} steps)",
                    plan.body.steps.len()
                );
                plan
            }
        }
    };
    let reviewer_adapter = supervisor_adapter(&env, &supervisor_model, Role::Reviewer, &api_key)?;
    let prompt = Signed::sign(&key, Purpose::Prompt, envelope.clone()).map_err(sign_failed)?;
    let store: Store = BTreeMap::from([(
        "contacts".to_owned(),
        BTreeMap::from([(
            "boss".to_owned(),
            StoreValue {
                value: boss_email.clone(),
                scalar: Scalar::Email,
                confidential: Confidential::Internal,
            },
        )]),
    )]);
    let mut brief = gate
        .start_task(&prompt, &plan, &store)
        .map_err(|e| Failure::config(format!("cannot start the task: {e}")))?;
    if let Some((template, level)) = &reused
        && !gate.log_plan_note(
            &task,
            PlanNote::Reused {
                template,
                level: level.as_str(),
            },
        )
    {
        return Err(Failure::failed("cannot write the ledger"));
    }

    // The model gateway: the only holder of the API key.
    let gateway = Arc::new(
        Gateway::start(GatewayConfig {
            upstream: UPSTREAM.to_owned(),
            api_key: ApiKey::new(api_key),
            models: BTreeSet::from([worker_model.clone()]),
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            timeout: GATEWAY_TIMEOUT,
        })
        .map_err(|e| Failure::failed(format!("cannot start the model gateway: {e}")))?,
    );

    // Sandbox configuration shared across instances.
    let agent_dir = std::path::absolute(&opts.agent_dir)
        .ok()
        .filter(|dir| dir.is_dir())
        .ok_or_else(|| {
            Failure::config(format!(
                "agent dir {} is not a directory",
                opts.agent_dir.display()
            ))
        })?;
    let runtime_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|crates| crates.join("munix-runtime"))
        .ok_or_else(|| Failure::config("cannot find the munix-runtime crate"))?;
    let mut sandbox_env = BTreeMap::from([
        ("MUNIX_WORKER_MODEL".to_owned(), worker_model),
        ("MUNIX_BOSS_EMAIL".to_owned(), boss_email),
    ]);
    if let Some(effort) = worker_effort {
        sandbox_env.insert("MUNIX_WORKER_EFFORT".to_owned(), effort);
    }
    eprintln!(
        "munix: task {task}, ledger {}, starting the sandbox",
        ledger_path.display()
    );

    // The seal's watcher spans every instance. On a change it records the tamper and kills the current agent.
    let current_container: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let tampered: Arc<Mutex<Option<Tamper>>> = Arc::new(Mutex::new(None));
    let seal_watch = {
        let container = Arc::clone(&current_container);
        let slot = Arc::clone(&tampered);
        SealWatch::start(
            seal.clone(),
            SEAL_POLL,
            Box::new(move |tamper| {
                eprintln!(
                    "munix: TAMPER: {} changed; stopping every task",
                    terminal_safe(&tamper.path)
                );
                *slot
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(tamper);
                let name = container
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                if !name.is_empty() {
                    let _ = Command::new("docker")
                        .args(["kill", &name])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
            }),
        )
    };

    let mut instance_num: u32 = 0;
    let (ended, killed, outcome) = loop {
        instance_num = instance_num.saturating_add(1);
        let spec = SandboxSpec {
            name: instance_sandbox_name(&task, instance_num),
            image: opts.image.clone(),
            agent_dir: agent_dir.clone(),
            command: opts.command.clone(),
            env: sandbox_env.clone(),
            host_gateway: host_gateway.clone(),
            gateway_port: gateway.addr().port(),
            relay_script: runtime_dir.join("relay").join("relay.py"),
            shim_script: runtime_dir.join("shim").join("munix_shim.py"),
        };
        let container_name = spec.network();
        current_container
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone_from(&container_name);
        // Check the seal before every new agent: the watcher may have tripped after the last check, while no agent
        // was running to be killed.
        if let Err(tamper) = seal.verify() {
            gate.tamper(&tamper);
            return Err(Failure::failed(tamper_message(&tamper)));
        }
        let mut sandbox = Sandbox::launch(spec)
            .map_err(|e| Failure::failed(format!("cannot start the sandbox: {e}")))?;
        let channel = (sandbox.child.stdout.take(), sandbox.child.stdin.take());
        let (Some(stdout), Some(mut stdin)) = channel else {
            let _ = sandbox.kill();
            return Err(Failure::failed("the sandbox has no stdio to serve"));
        };

        let progress = Arc::new(FrontProgress::new());
        let progress_for_watchdog = Arc::clone(&progress);
        let gateway_for_watchdog = Arc::clone(&gateway);
        let tripped: Arc<Mutex<Option<Trip>>> = Arc::new(Mutex::new(None));
        let tripped_slot = Arc::clone(&tripped);
        let watchdog = Watchdog::start(
            limits,
            Duration::from_secs(1),
            Arc::new(SystemClock),
            Arc::new(move || {
                let usage = gateway_for_watchdog.usage();
                let gw_last = gateway_for_watchdog.last_activity();
                let front_last = progress_for_watchdog.last_call();
                Snapshot {
                    last_activity: gw_last.max(front_last),
                    model_calls: usage.calls,
                    model_tokens: usage.prompt_tokens.saturating_add(usage.completion_tokens),
                    steps_completed: progress_for_watchdog.delivered(),
                }
            }),
            Box::new(move |trip| {
                *tripped_slot
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(trip);
                let _ = Command::new("docker")
                    .args(["kill", &container_name])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }),
        );

        let reviewer = Reviewer::new(Arc::clone(&reviewer_adapter), key.clone());
        let mut reader = BufReader::new(stdout);
        // The Console is always the person at the terminal. `confirm::SimulatedUser` is for the evaluation bridge
        // only and is never used by `munix run`.
        let mut front = GateFront::new(&mut gate, &key, brief.clone(), TerminalConfirmer)
            .with_reviewer(reviewer, envelope.clone())
            .with_progress(progress)
            .with_operator_log();
        let ended = serve(&mut reader, &mut stdin, &mut front);
        let takeover = front.takeover();
        drop(front);
        drop(stdin);
        drop(reader);
        watchdog.stop();
        let killed = sandbox.kill();
        let trip = *tripped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // A tamper (seen by the watcher, or by the Gate's check before a call) beats everything: every task stops
        // and nothing recovers.
        let tamper = tampered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .or_else(|| gate.tampered().cloned());
        if let Some(tamper) = tamper {
            gate.tamper(&tamper);
            // The watcher killed the agent, so its channel breaking is expected, not a separate failure.
            break (
                Ok(ServeEnd::Stopped),
                killed,
                Outcome::Stopped(tamper_message(&tamper)),
            );
        }

        match decide_after_instance(takeover, trip) {
            NextStep::Finish => {
                let outcome = match &ended {
                    Ok(ServeEnd::Closed) => Outcome::Finished,
                    Ok(ServeEnd::Stopped) => Outcome::Stopped("stopped by the Gate".to_owned()),
                    Err(_) => Outcome::Stopped("the agent's channel failed".to_owned()),
                };
                break (ended, killed, outcome);
            }
            NextStep::RecoverFromTakeover => {
                // A takeover the front saw before it could build a request leaves the task running; halt it so
                // recovery can start. Already halted (the usual case): no change.
                if let Some(code) = takeover {
                    gate.halt_for_takeover(&task, code);
                }
            }
            NextStep::TripAndRecover(reason) => {
                let _ = gate.trip(&task, reason);
            }
        }

        if let Err(e) = killed {
            return Err(Failure::failed(format!(
                "could not remove the sandbox: {e}"
            )));
        }
        if let Err(tamper) = seal.verify() {
            gate.tamper(&tamper);
            return Err(Failure::failed(tamper_message(&tamper)));
        }
        match gate.recover(&task) {
            Ok(recovery) => {
                eprintln!(
                    "munix: recovering (attempt {}): withheld {} item(s)",
                    recovery.attempt,
                    recovery.quarantined.len()
                );
                brief = recovery.brief;
            }
            Err(RecoverError::LimitReached) => {
                return Err(Failure::failed(
                    "paused: the task used its recoveries; the user must decide",
                ));
            }
            Err(e) => {
                return Err(Failure::failed(format!("cannot recover: {e}")));
            }
        }
    };

    seal_watch.stop();

    // Plan memory, now that the seal no longer watches: count a reuse, or keep the planner's plan from a clean run
    // (finished, no takeover, no off-plan denial).
    if let Some(memory) = &memory {
        if reused.is_some() {
            if let Err(e) = memory.record_use(&envelope.text, &stores) {
                eprintln!("munix: {e}");
            }
        } else if matches!(outcome, Outcome::Finished) && !crate::bridge::off_plan_in(&ledger_path)
        {
            match memory.remember(&plan.body, &envelope.text, &stores) {
                Ok(template) => {
                    let _ = gate.log_plan_note(
                        &task,
                        PlanNote::Remembered {
                            template: &template.key,
                        },
                    );
                    eprintln!("munix: plan kept in plan memory");
                }
                Err(e) => eprintln!("munix: {e}"),
            }
        }
    }

    // The summary.
    let trust = gate.context_trust(&task);
    let quarantined = gate.quarantined(&task);
    drop(gate);
    let usage = gateway.usage();
    let tokens = Usage {
        prompt_tokens: usage.prompt_tokens,
        completion_tokens: usage.completion_tokens,
        reasoning_tokens: usage.reasoning_tokens,
    };
    let result = match &outcome {
        Outcome::Finished => "finished".to_owned(),
        Outcome::Stopped(why) => format!("stopped: {why}"),
    };
    eprintln!("munix: {}", terminal_safe(&result));
    match trust {
        Some(trust) => eprintln!("munix: context trust {}", trust.value()),
        None => eprintln!("munix: context trust unknown"),
    }
    for note in &quarantined {
        eprintln!("munix: {}", format_quarantine_note(note));
    }
    match munix_ledger::verify_file(&ledger_path) {
        Ok(entries) => eprintln!(
            "munix: ledger {}: {entries} entries, chain verified",
            ledger_path.display()
        ),
        Err(e) => eprintln!("munix: ledger {}: check failed: {e}", ledger_path.display()),
    }
    eprintln!(
        "munix: model: {} calls, {} prompt and {} completion tokens ({} reasoning), about ${:.4}",
        usage.calls,
        tokens.prompt_tokens,
        tokens.completion_tokens,
        tokens.reasoning_tokens,
        pricing.cost_usd(&tokens)
    );
    if let Err(e) = ended {
        return Err(Failure::failed(format!("the agent's channel failed: {e}")));
    }
    if let Err(e) = killed {
        return Err(Failure::failed(format!(
            "could not remove the sandbox: {e}"
        )));
    }
    Ok(outcome)
}

pub(crate) fn parse_id<T: std::str::FromStr>(text: &str) -> Result<T, Failure> {
    text.parse()
        .map_err(|_| Failure::failed("generated an invalid id"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| (*p).to_owned()).collect()
    }

    fn code_of(result: Result<Options, Failure>) -> u8 {
        result.unwrap_err().code
    }

    #[test]
    fn arguments_parse_with_defaults() {
        let opts = parse_args(&args(&[
            "run",
            "--plan",
            "p.yaml",
            "--prompt",
            "Do it",
            "--",
            "python",
            "/agent/agent.py",
        ]))
        .unwrap();
        assert_eq!(
            opts,
            Options {
                plan: Some(PathBuf::from("p.yaml")),
                prompt: "Do it".to_owned(),
                image: "munix-demo-agent".to_owned(),
                agent_dir: PathBuf::from("demo/agent"),
                ledger: None,
                command: args(&["python", "/agent/agent.py"]),
            }
        );
    }

    #[test]
    fn missing_plan_is_accepted_by_parse_args() {
        let opts = parse_args(&args(&[
            "run",
            "--prompt",
            "Do it",
            "--",
            "python",
            "/agent/agent.py",
        ]))
        .unwrap();
        assert_eq!(opts.plan, None);
        assert_eq!(opts.prompt, "Do it");
        assert_eq!(opts.command, args(&["python", "/agent/agent.py"]));
    }

    #[test]
    fn every_flag_is_read_and_the_command_keeps_its_own_flags() {
        let opts = parse_args(&args(&[
            "run",
            "--prompt",
            "Hi",
            "--image",
            "img:1",
            "--plan",
            "p.yaml",
            "--agent-dir",
            "/a",
            "--ledger",
            "out/l.jsonl",
            "--",
            "agent",
            "--plan",
            "x",
            "--",
        ]))
        .unwrap();
        assert_eq!(opts.plan, Some(PathBuf::from("p.yaml")));
        assert_eq!(opts.image, "img:1");
        assert_eq!(opts.agent_dir, PathBuf::from("/a"));
        assert_eq!(opts.ledger, Some(PathBuf::from("out/l.jsonl")));
        assert_eq!(opts.command, args(&["agent", "--plan", "x", "--"]));
    }

    #[test]
    fn bad_usage_exits_with_2() {
        let cases: [&[&str]; 8] = [
            &[],
            &["--plan", "p", "--prompt", "x", "--", "a"],
            &["run", "--plan", "p", "--", "a"],
            &["run", "--plan", "p", "--prompt", "x"],
            &["run", "--plan", "p", "--prompt", "x", "--"],
            &["run", "--plan", "p", "--prompt"],
            &[
                "run", "--plan", "p", "--prompt", "x", "--wat", "1", "--", "a",
            ],
            &["run", "--plan", "p", "--prompt", "x", "agent"],
        ];
        for case in cases {
            assert_eq!(code_of(parse_args(&args(case))), 2, "{case:?}");
        }
    }

    #[test]
    fn usage_errors_do_not_echo_the_arguments() {
        let err = parse_args(&args(&["run", "--prompt", "secret-text", "--bogus"])).unwrap_err();
        assert!(!err.message.contains("secret-text") && !err.message.contains("bogus"));
    }

    #[test]
    fn dotenv_lines_are_parsed() {
        let vars = parse_dotenv(
            "# a comment\n\
             \n\
             MODEL_API_KEY=abc123\n\
             export MUNIX_WORKER_MODEL = muse-spark-1.3  \n\
             QUOTED=\"two words # not a comment\"\n\
             SINGLE='x'\n\
             TRAILING=value # a comment\n\
             EMPTY=\n\
             not a pair\n\
             1BAD=x\n\
             MODEL_API_KEY=later\n\
             URL=https://a.test/x?a=b\n",
        );
        assert_eq!(vars["MODEL_API_KEY"], "later");
        assert_eq!(vars["MUNIX_WORKER_MODEL"], "muse-spark-1.3");
        assert_eq!(vars["QUOTED"], "two words # not a comment");
        assert_eq!(vars["SINGLE"], "x");
        assert_eq!(vars["TRAILING"], "value");
        assert_eq!(vars["EMPTY"], "");
        assert_eq!(vars["URL"], "https://a.test/x?a=b");
        assert_eq!(vars.len(), 7);
        assert!(
            !vars
                .keys()
                .any(|k| k.starts_with('#') || k.starts_with('1'))
        );
    }

    #[test]
    fn variables_already_set_win_over_dotenv() {
        let env = Env {
            file: parse_dotenv("A=from_file\nB=from_file\nC=\nD=\n"),
            process: |key| match key {
                "A" => Some("from_process".to_owned()),
                "D" => Some("from_process".to_owned()),
                _ => None,
            },
        };
        assert_eq!(env.get("A").as_deref(), Some("from_process"));
        assert_eq!(env.get("B").as_deref(), Some("from_file"));
        assert_eq!(env.get("C"), None, "an empty value is not set");
        assert_eq!(env.get("D").as_deref(), Some("from_process"));
        assert_eq!(env.get("E"), None);
        assert_eq!(env.get_or("E", "dflt"), "dflt");
    }

    #[test]
    fn supervisor_settings_and_prices_come_from_dotenv_too() {
        let env = Env {
            file: parse_dotenv(
                "MUNIX_REVIEWER_EFFORT=minimal\nMUNIX_PRICE_INPUT_PER_M=2\nMUNIX_PRICE_OUTPUT_PER_M=8\n",
            ),
            process: |_| None,
        };
        let adapter =
            supervisor_adapter(&env, "muse-spark-1.3", Role::Reviewer, "test-key").unwrap();
        assert_eq!(adapter.name(), "meta:muse-spark-1.3");
        let pricing = pricing_from(&env).unwrap();
        assert_eq!((pricing.input_per_m, pricing.output_per_m), (2.0, 8.0));

        let bad = Env {
            file: parse_dotenv("MUNIX_PLANNER_EFFORT=turbo\nMUNIX_PRICE_INPUT_PER_M=-1\n"),
            process: |_| None,
        };
        assert!(supervisor_adapter(&bad, "muse-spark-1.3", Role::Planner, "test-key").is_err());
        assert!(pricing_from(&bad).is_err());
    }

    #[test]
    fn the_plan_is_rewritten_for_this_run() {
        let original = Plan::from_yaml(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/demo-plan.yaml"
        )))
        .unwrap();
        let hash = Digest::of_bytes(b"the prompt");
        let task: TaskId = "T-0a1b2c3d".parse().unwrap();
        let plan_id: PlanId = "P-4e5f6a7b".parse().unwrap();
        let plan = rewrite_plan(
            original.clone(),
            task.clone(),
            plan_id.clone(),
            hash.clone(),
        );
        assert_ne!(plan.prompt_hash, original.prompt_hash);
        assert_eq!(
            (plan.task, plan.plan, plan.prompt_hash),
            (task, plan_id, hash)
        );
        assert_eq!(plan.steps, original.steps);
        assert_eq!(plan.reads, original.reads);
        assert_eq!(plan.amendments, original.amendments);
    }

    #[test]
    fn random_ids_are_hex_and_differ() {
        let a = random_hex(16).unwrap();
        let b = random_hex(16).unwrap();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        assert_eq!(random_hex(4).unwrap().len(), 8);
    }

    #[test]
    fn the_real_manifests_load_into_a_catalog() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../manifests");
        let catalog = load_catalog(&dir).unwrap();
        assert!(catalog.get_str("web.open").is_some());
        assert!(catalog.get_str("email.send").is_some());
        assert!(load_catalog(Path::new("/no/such/dir")).is_err());
    }

    #[test]
    fn decide_after_instance_handles_takeover_trip_and_clean_finish() {
        assert_eq!(decide_after_instance(None, None), NextStep::Finish);
        assert_eq!(
            decide_after_instance(Some(DenyCode::UntrustedDestination), None),
            NextStep::RecoverFromTakeover
        );
        assert_eq!(
            decide_after_instance(None, Some(Trip::Liveness)),
            NextStep::TripAndRecover(TripReason::Liveness)
        );
        assert_eq!(
            decide_after_instance(None, Some(Trip::Deadline)),
            NextStep::TripAndRecover(TripReason::Deadline)
        );
        assert_eq!(
            decide_after_instance(None, Some(Trip::SpinBudget)),
            NextStep::TripAndRecover(TripReason::SpinBudget)
        );
        // If both happened (e.g. a trip raced with a takeover), the takeover already halted the task.
        assert_eq!(
            decide_after_instance(Some(DenyCode::OffPlan), Some(Trip::Liveness)),
            NextStep::RecoverFromTakeover
        );
    }

    #[test]
    fn quarantine_notes_are_worded_without_item_text() {
        use munix_core::label::{RegionType, Trust};

        let traced = QuarantineNote {
            step: 1,
            field: "reviews".to_owned(),
            index: Some(1),
            region: RegionType::UgcReview,
            trust: Trust::new(15),
            cause: Cause::TracedValue,
            hash: Digest::of_bytes(b"SECRET-INJECTION-TEXT"),
        };
        let line = format_quarantine_note(&traced);
        assert_eq!(
            line,
            "withheld: step 1 reviews[1] (ugc_review, trust 15): contained the destination of a blocked request"
        );
        assert!(!line.contains("SECRET"));

        let fallback = QuarantineNote {
            step: 2,
            field: "page".to_owned(),
            index: None,
            region: RegionType::Unclassified,
            trust: Trust::new(10),
            cause: Cause::LowTrustFallback,
            hash: Digest::of_bytes(b"OTHER-INJECTION-TEXT"),
        };
        let line = format_quarantine_note(&fallback);
        assert_eq!(
            line,
            "withheld: step 2 page (unclassified, trust 10): low-trust content read before a stall or off-plan call"
        );
        assert!(!line.contains("OTHER"));
    }

    #[test]
    fn instance_sandbox_names_include_task_and_instance_number() {
        let task: TaskId = "T-0a1b2c3d".parse().unwrap();
        assert_eq!(instance_sandbox_name(&task, 1), "t-0a1b2c3d-1");
        assert_eq!(instance_sandbox_name(&task, 2), "t-0a1b2c3d-2");
    }

    #[test]
    fn the_seal_covers_munix_and_the_plan_file() {
        let roots = seal_roots(
            Some(Path::new("my-plan.yaml")),
            Path::new("no-such-webspeed-dir"),
            Some(Path::new("my-plan-memory")),
        );
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let workspace = workspace.components().collect::<PathBuf>();
        let has_tree = |p: &Path| {
            roots
                .iter()
                .any(|r| matches!(r, Root::Tree(t) if t.components().eq(p.components())))
        };
        let has_file = |p: &Path| {
            roots
                .iter()
                .any(|r| matches!(r, Root::File(f) if f.components().eq(p.components())))
        };
        // The source tree is anchored where this binary was built from; what `munix run` reads is relative.
        assert!(
            roots
                .iter()
                .any(|r| matches!(r, Root::Tree(t) if t.ends_with("crates") && t.is_absolute()))
        );
        assert!(
            roots.iter().any(
                |r| matches!(r, Root::File(f) if f.ends_with("Cargo.lock") && f.is_absolute())
            )
        );
        let _ = workspace;
        for dir in ["manifests", "sites", "examples", "my-plan-memory"] {
            assert!(has_tree(Path::new(dir)), "{dir}");
        }
        for file in [".env", "my-plan.yaml"] {
            assert!(has_file(Path::new(file)), "{file}");
        }
        // All of Web Speed, venv included.
        assert!(has_tree(Path::new("no-such-webspeed-dir")));
        assert!(has_tree(Path::new("no-such-webspeed-dir/venv")));
        let tamper = Tamper {
            path: "manifests/email.send.yaml".into(),
            old: None,
            new: None,
        };
        assert!(tamper_message(&tamper).contains("manifests/email.send.yaml"));
    }

    #[test]
    fn watchdog_limits_default_and_override_from_env() {
        let defaults = Limits::default();
        let empty = Env {
            file: BTreeMap::new(),
            process: |_| None,
        };
        assert_eq!(limits_from(&empty).unwrap(), defaults);

        let custom = Env {
            file: parse_dotenv("MUNIX_LIVENESS_SECS=15\nMUNIX_DEADLINE_SECS=120\n"),
            process: |_| None,
        };
        assert_eq!(
            limits_from(&custom).unwrap(),
            Limits {
                liveness: Duration::from_secs(15),
                deadline: Duration::from_secs(120),
                ..defaults
            }
        );

        for bad_var in [
            "MUNIX_LIVENESS_SECS=0",
            "MUNIX_LIVENESS_SECS=abc",
            "MUNIX_DEADLINE_SECS=0",
        ] {
            let bad = Env {
                file: parse_dotenv(bad_var),
                process: |_| None,
            };
            assert!(limits_from(&bad).is_err(), "{bad_var}");
        }
    }
}
