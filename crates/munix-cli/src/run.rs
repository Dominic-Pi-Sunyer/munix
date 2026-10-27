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
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use munix_adapters::{MetaAdapter, ModelAdapter, Pricing, ReasoningEffort, Role, Usage};
use munix_core::crypto::{Digest, Purpose, Signed, SigningKey};
use munix_core::ids::{PlanId, SessionId, TaskId};
use munix_core::label::Confidential;
use munix_core::manifest::{Catalog, ToolManifest};
use munix_core::plan::Plan;
use munix_core::prompt::PromptEnvelope;
use munix_core::validate::Scalar;
use munix_gate::gate::{Gate, Store, StoreValue};
use munix_gate::tool::Tool;
use munix_gate::vault::{Credential, Vault};
use munix_ledger::Ledger;
use munix_runtime::gateway::{ApiKey, Gateway, GatewayConfig};
use munix_runtime::mcp::{ServeEnd, serve};
use munix_runtime::sandbox::{Sandbox, SandboxSpec};
use munix_supervisor::planner::Planner;
use munix_supervisor::reviewer::Reviewer;
use munix_tools::email::SmtpEmail;
use munix_tools::site::SiteTemplates;
use munix_tools::webspeed::{WebSpeedConfig, WebSpeedOpen};

use crate::confirm::TerminalConfirmer;
use crate::front::{GateFront, code_text};

const USAGE: &str = "usage: munix run [--plan <plan.yaml>] --prompt <text> [--image <image>] \
                     [--agent-dir <dir>] [--ledger <file>] -- <agent command...>";
const DEFAULT_IMAGE: &str = "munix-demo-agent";
const DEFAULT_AGENT_DIR: &str = "demo/agent";
const DEFAULT_MODEL: &str = "muse-spark-1.3";
const DEFAULT_BOSS: &str = "boss@corp.example";
const DEFAULT_HOST_GATEWAY: &str = "192.168.5.2";
const DEFAULT_WEBSPEED_DIR: &str = "../web-speed-oss";
const UPSTREAM: &str = "https://api.meta.ai/v1";
const GATEWAY_TIMEOUT: Duration = Duration::from_secs(120);
/// What the vault holds for a manifest's credential. The local mail sink takes any login.
const PLACEHOLDER_CREDENTIAL: &str = "munix-placeholder-credential";
/// The defaults `SmtpEmail::from_env` uses, for when only one of the two variables is set.
const DEFAULT_SMTP: &str = "127.0.0.1:1025";
const DEFAULT_SMTP_FROM: &str = "agent@munix.example";

/// Why a run did not start or did not finish cleanly. The message is one line and never holds the API key or any
/// argument value.
#[derive(Debug)]
struct Failure {
    /// The process exit code: 2 for bad usage or config, 1 for a failure while running.
    code: u8,
    message: String,
}

impl Failure {
    fn usage(message: impl Into<String>) -> Self {
        Failure {
            code: 2,
            message: message.into(),
        }
    }

    fn config(message: impl Into<String>) -> Self {
        Self::usage(message)
    }

    fn failed(message: impl Into<String>) -> Self {
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
struct Env {
    file: BTreeMap<String, String>,
    process: fn(&str) -> Option<String>,
}

impl Env {
    /// The real environment plus `path` if it exists.
    fn load(path: &Path) -> Result<Env, Failure> {
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
    fn get(&self, key: &str) -> Option<String> {
        (self.process)(key)
            .or_else(|| self.file.get(key).cloned())
            .filter(|v| !v.is_empty())
    }

    fn get_or(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or_else(|| default.to_owned())
    }
}

/// `bytes` random bytes from the operating system.
fn random_bytes(bytes: usize) -> Result<Vec<u8>, Failure> {
    let mut buf = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|_| Failure::failed("cannot read random bytes from /dev/urandom"))?;
    Ok(buf)
}

fn random_hex(bytes: usize) -> Result<String, Failure> {
    Ok(hex::encode(random_bytes(bytes)?))
}

/// The plan file's `task` and `plan` replaced by this run's ids, and its `prompt_hash` bound to the prompt.
fn rewrite_plan(mut plan: Plan, task: TaskId, plan_id: PlanId, prompt_hash: Digest) -> Plan {
    plan.task = task;
    plan.plan = plan_id;
    plan.prompt_hash = prompt_hash;
    plan
}

/// Every `*.yaml` in `dir`, in name order.
fn load_catalog(dir: &Path) -> Result<Catalog, Failure> {
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

/// The Gate with the real tools registered at their manifests' digests.
fn build_gate(
    key: &SigningKey,
    catalog: &Catalog,
    ledger: Ledger,
    env: &Env,
) -> Result<Gate, Failure> {
    let mut vault = Vault::new();
    for (_, manifest) in catalog.iter() {
        if let Some(at) = &manifest.credentials {
            vault.insert(at.clone(), Credential::new(PLACEHOLDER_CREDENTIAL));
        }
    }
    let mut gate = Gate::new(key.clone(), catalog.clone(), vault, ledger);
    for (name, manifest) in catalog.iter() {
        let tool: Box<dyn Tool> = match name.as_str() {
            "web.open" => {
                let mut config =
                    WebSpeedConfig::from_dir(env.get_or("WEBSPEED_OSS_DIR", DEFAULT_WEBSPEED_DIR));
                config.allow_hosts = env.get("WEBSPEED_ALLOW_HOSTS");
                config.templates =
                    SiteTemplates::load_dir("sites").map_err(|e| Failure::config(e.to_string()))?;
                Box::new(WebSpeedOpen::new(config).map_err(|e| Failure::config(e.to_string()))?)
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

/// Parses `args` (without the program name or the `run` word handled here) and runs. Exit codes: 0 when the agent
/// finished, 1 on a takeover or a failure, 2 on bad usage or config. Errors are one line on stderr and never
/// contain the API key.
///
/// Steps:
/// 1. `run` as the first argument, then the flags above; `--` starts the agent command. Defaults: image
///    `munix-demo-agent`, agent dir `demo/agent`, ledger `runs/<task>.ledger.jsonl` (its directory is created).
/// 2. Read `.env` from the current directory if it exists (`KEY=VALUE` lines, `#` comments; variables already set
///    win). Require `MODEL_API_KEY`. Also read `MUNIX_WORKER_MODEL` (default `muse-spark-1.3`), `MUNIX_WORKER_EFFORT`,
///    `MUNIX_SUPERVISOR_MODEL` (default `muse-spark-1.3`), `MUNIX_BOSS_EMAIL` (default `boss@corp.example`),
///    `MUNIX_HOST_GATEWAY` (default `192.168.5.2`, Colima), `WEBSPEED_OSS_DIR` (default `../web-speed-oss`),
///    `WEBSPEED_ALLOW_HOSTS`, `MUNIX_SMTP`.
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
/// 7. Launch the sandbox: name from the task id (lowercase), the image, the agent dir (absolute), the command,
///    env `MUNIX_WORKER_MODEL`, `MUNIX_WORKER_EFFORT` (if set), `MUNIX_BOSS_EMAIL`, the host gateway, the gateway's
///    port, and this crate's sibling `munix-runtime/relay/relay.py` and `munix-runtime/shim/munix_shim.py` (found
///    from `CARGO_MANIFEST_DIR` at build time).
/// 8. `munix_runtime::mcp::serve` on the agent's stdout and stdin with a `GateFront` (with the `Reviewer` attached)
///    and `TerminalConfirmer`.
/// 9. When it ends, kill the sandbox and print a summary to stderr: the outcome (finished, or the takeover code),
///    the context trust, the ledger path and entry count, and the gateway's token usage with an estimated cost
///    (`munix_adapters::Pricing::from_env`).
pub fn main(args: Vec<String>) -> ExitCode {
    match run(&args) {
        Ok(Outcome::Finished) => ExitCode::SUCCESS,
        Ok(Outcome::Stopped(_)) => ExitCode::from(1),
        Err(failure) => {
            eprintln!("munix: {}", failure.message);
            ExitCode::from(failure.code)
        }
    }
}

/// A Meta adapter for one Supervisor role, configured from `munix run`'s own lookup (the environment, then `.env`)
/// rather than the process environment alone, so a key or effort set only in `.env` is used.
fn supervisor_adapter(
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
    let mut gate = build_gate(&key, &catalog, ledger, &env)?;

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
            let adapter = supervisor_adapter(&env, &supervisor_model, Role::Planner, &api_key)?;
            let planner = Planner::new(adapter, key.clone());
            let stores = BTreeMap::from([("contacts".to_owned(), vec!["boss".to_owned()])]);
            let plan = planner
                .plan(&envelope, &catalog, &stores, plan_id)
                .map_err(|e| Failure::config(e.to_string()))?;
            eprintln!(
                "munix: plan written by {supervisor_model} ({} steps)",
                plan.body.steps.len()
            );
            plan
        }
    };
    let reviewer_adapter = supervisor_adapter(&env, &supervisor_model, Role::Reviewer, &api_key)?;
    let reviewer = Reviewer::new(reviewer_adapter, key.clone());
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
    let brief = gate
        .start_task(&prompt, &plan, &store)
        .map_err(|e| Failure::config(format!("cannot start the task: {e}")))?;

    // The model gateway: the only holder of the API key.
    let gateway = Gateway::start(GatewayConfig {
        upstream: UPSTREAM.to_owned(),
        api_key: ApiKey::new(api_key),
        models: BTreeSet::from([worker_model.clone()]),
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        timeout: GATEWAY_TIMEOUT,
    })
    .map_err(|e| Failure::failed(format!("cannot start the model gateway: {e}")))?;

    // The sandbox.
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
    let spec = SandboxSpec {
        name: task.as_str().to_lowercase(),
        image: opts.image.clone(),
        agent_dir,
        command: opts.command.clone(),
        env: sandbox_env,
        host_gateway,
        gateway_port: gateway.addr().port(),
        relay_script: runtime_dir.join("relay").join("relay.py"),
        shim_script: runtime_dir.join("shim").join("munix_shim.py"),
    };
    eprintln!(
        "munix: task {task}, ledger {}, starting the sandbox",
        ledger_path.display()
    );
    let mut sandbox = Sandbox::launch(spec)
        .map_err(|e| Failure::failed(format!("cannot start the sandbox: {e}")))?;
    let channel = (sandbox.child.stdout.take(), sandbox.child.stdin.take());
    let (Some(stdout), Some(mut stdin)) = channel else {
        let _ = sandbox.kill();
        return Err(Failure::failed("the sandbox has no stdio to serve"));
    };

    // The agent's MCP channel, served by the Gate.
    let mut reader = BufReader::new(stdout);
    let mut front =
        GateFront::new(&mut gate, &key, brief, TerminalConfirmer).with_reviewer(reviewer, envelope);
    let ended = serve(&mut reader, &mut stdin, &mut front);
    let takeover = front.takeover();
    drop(front);
    drop(stdin);
    drop(reader);
    let killed = sandbox.kill();

    // The summary.
    let trust = gate.context_trust(&task);
    drop(gate);
    let usage = gateway.usage();
    let tokens = Usage {
        prompt_tokens: usage.prompt_tokens,
        completion_tokens: usage.completion_tokens,
        reasoning_tokens: usage.reasoning_tokens,
    };
    let outcome = match (&ended, takeover) {
        (_, Some(code)) => Outcome::Stopped(format!("takeover ({})", code_text(&code))),
        (Ok(ServeEnd::Closed), None) => Outcome::Finished,
        (Ok(ServeEnd::Stopped), None) => Outcome::Stopped("stopped by the Gate".to_owned()),
        (Err(_), None) => Outcome::Stopped("the agent's channel failed".to_owned()),
    };
    let result = match &outcome {
        Outcome::Finished => "finished".to_owned(),
        Outcome::Stopped(why) => format!("stopped: {why}"),
    };
    eprintln!("munix: {result}");
    match trust {
        Some(trust) => eprintln!("munix: context trust {}", trust.value()),
        None => eprintln!("munix: context trust unknown"),
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

fn parse_id<T: std::str::FromStr>(text: &str) -> Result<T, Failure> {
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
}
