//! `munix bridge`: the Gate for one AgentDojo task, spoken to in JSON lines on stdin and stdout.
//!
//! ```text
//! munix bridge --manifests <dir> --ledger <file> [--plan <plan.yaml> [--no-reviewer]] [--simulated-user]
//! ```
//!
//! The Python side (`eval/agentdojo`) runs the agent in its own process and sends every tool call here. The same
//! `GateFront` that `munix run` serves decides each call; when it lets one run, the bridge hands the resolved
//! arguments back to Python (`run_tool`) and waits for the function's output (`tool_result`). Nothing here decides
//! anything itself: no Gate, policy or reviewer logic is duplicated, and the Console answers no to everything unless
//! `--simulated-user` selects the labeled stand-in for a careful user (`confirm::SimulatedUser`).
//!
//! There is no sandbox, model gateway, watchdog, recovery or Integrity Seal: the agent is AgentDojo's, not ours.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use munix_adapters::{Metered, ModelAdapter, Role};
use munix_core::crypto::{Purpose, Signed, SigningKey};
use munix_core::ids::{PlanId, SessionId, TaskId};
use munix_core::manifest::Catalog;
use munix_core::plan::Plan;
use munix_core::prompt::PromptEnvelope;
use munix_gate::gate::{Gate, PlanNote, Store};
use munix_gate::tool::{Tool, ToolFailure};
use munix_gate::vault::{Credential, Vault};
use munix_ledger::Ledger;
use munix_runtime::mcp::McpHandler;
use munix_supervisor::memory::{Level, PlanMemory};
use munix_supervisor::planner::{self, Planner};
use munix_supervisor::reviewer::Reviewer;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::confirm::{Confirmer, SimulatedUser};
use crate::front::{GateFront, code_text};
use crate::run::{
    DEFAULT_DETECTOR_NAME, DEFAULT_MODEL, Env, Failure, PLACEHOLDER_CREDENTIAL, detector_config,
    load_catalog, parse_id, parse_threshold, random_bytes, random_hex, rewrite_plan,
    supervisor_adapter,
};
use munix_core::detect::{DEFAULT_THRESHOLD, DetectorConfig};

const USAGE: &str = "usage: munix bridge --manifests <dir> --ledger <file> [--plan <plan.yaml> [--no-reviewer] | --plan-memory <dir>] [--simulated-user] [--detector-url <url> [--detector-name <name>] [--detector-threshold <0-1>]]";
/// What the model-facing diagnostics on stderr are cut to.
const MAX_DIAGNOSTIC: usize = 200;

/// `--detector-url` and its companions, already checked.
#[derive(Debug, PartialEq)]
struct DetectorOpts {
    url: String,
    name: String,
    threshold: f32,
}

/// What `munix bridge` was asked to do.
#[derive(Debug, PartialEq)]
struct Options {
    manifests: PathBuf,
    ledger: PathBuf,
    plan: Option<PathBuf>,
    /// No gray-zone reviewer: such requests go to the (always-no) Console and are denied, as in `munix run` with
    /// no reviewer. Needs `--plan`, so no model is called at all and `MODEL_API_KEY` is not required.
    no_reviewer: bool,
    /// The Console is `SimulatedUser` instead of a flat no. Evaluation only; its decisions are marked
    /// `console.simulated_user` in the ledger.
    simulated_user: bool,
    /// Plan memory's directory (`docs/plan-memory.md`). Only without `--plan`: a stored plan replaces a planner call.
    plan_memory: Option<PathBuf>,
    /// The injection detector (a loopback guard sidecar). Without it nothing is scored.
    detector: Option<DetectorOpts>,
}

/// Parses `bridge --manifests <dir> --ledger <file> [--plan <file> [--no-reviewer]] [--simulated-user]`.
fn parse_args(args: &[String]) -> Result<Options, Failure> {
    let mut it = args.iter();
    if it.next().map(String::as_str) != Some("bridge") {
        return Err(Failure::usage(USAGE));
    }
    let (mut manifests, mut ledger, mut plan, mut plan_memory) = (None, None, None, None);
    let (mut no_reviewer, mut simulated_user) = (false, false);
    let (mut detector_url, mut detector_name, mut detector_threshold) =
        (None::<String>, None::<String>, None::<String>);
    while let Some(arg) = it.next() {
        let text_slot = match arg.as_str() {
            "--detector-url" => Some(&mut detector_url),
            "--detector-name" => Some(&mut detector_name),
            "--detector-threshold" => Some(&mut detector_threshold),
            _ => None,
        };
        if let Some(slot) = text_slot {
            let Some(value) = it.next() else {
                return Err(Failure::usage(USAGE));
            };
            if slot.replace(value.clone()).is_some() {
                return Err(Failure::usage(USAGE));
            }
            continue;
        }
        if arg == "--no-reviewer" || arg == "--simulated-user" {
            let flag = if arg == "--no-reviewer" {
                &mut no_reviewer
            } else {
                &mut simulated_user
            };
            if std::mem::replace(flag, true) {
                return Err(Failure::usage(USAGE));
            }
            continue;
        }
        let slot = match arg.as_str() {
            "--manifests" => &mut manifests,
            "--ledger" => &mut ledger,
            "--plan" => &mut plan,
            "--plan-memory" => &mut plan_memory,
            _ => return Err(Failure::usage(USAGE)),
        };
        let Some(value) = it.next() else {
            return Err(Failure::usage(USAGE));
        };
        if slot.replace(PathBuf::from(value)).is_some() {
            return Err(Failure::usage(USAGE));
        }
    }
    let detector = match detector_url {
        Some(url) => {
            let name = detector_name.unwrap_or_else(|| DEFAULT_DETECTOR_NAME.to_owned());
            let threshold = match detector_threshold {
                Some(text) => parse_threshold(&text)?,
                None => DEFAULT_THRESHOLD,
            };
            // Checks the URL, name and threshold now, so a typo is a startup error.
            detector_config(&url, &name, threshold)?;
            Some(DetectorOpts {
                url,
                name,
                threshold,
            })
        }
        None if detector_name.is_some() || detector_threshold.is_some() => {
            return Err(Failure::usage(
                "--detector-name and --detector-threshold need --detector-url",
            ));
        }
        None => None,
    };
    match (manifests, ledger) {
        // Without a plan the planner needs a model, and the reviewer is part of the same setup.
        // Plan memory stands in for the planner, so it makes no sense with a given plan.
        (Some(manifests), Some(ledger))
            if (plan.is_some() || !no_reviewer) && !(plan.is_some() && plan_memory.is_some()) =>
        {
            Ok(Options {
                manifests,
                ledger,
                plan,
                no_reviewer,
                simulated_user,
                plan_memory,
                detector,
            })
        }
        _ => Err(Failure::usage(USAGE)),
    }
}

/// A Console that never approves anything: nobody is there to ask.
#[derive(Debug, Default)]
struct AlwaysNo;

impl Confirmer for AlwaysNo {
    fn confirm(&mut self, _view: &munix_gate::gate::PendingView) -> bool {
        false
    }
}

/// The bridge's Console: a flat no, or, with `--simulated-user`, the labeled stand-in for a careful user. This
/// file is the only place that constructs `SimulatedUser`; `munix run` never does.
enum BridgeConsole {
    AlwaysNo(AlwaysNo),
    Simulated(SimulatedUser),
}

impl BridgeConsole {
    fn new(simulated_user: bool) -> Self {
        if simulated_user {
            BridgeConsole::Simulated(SimulatedUser)
        } else {
            BridgeConsole::AlwaysNo(AlwaysNo)
        }
    }
}

impl Confirmer for BridgeConsole {
    fn confirm(&mut self, view: &munix_gate::gate::PendingView) -> bool {
        match self {
            BridgeConsole::AlwaysNo(c) => c.confirm(view),
            BridgeConsole::Simulated(c) => c.confirm(view),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            BridgeConsole::AlwaysNo(c) => c.label(),
            BridgeConsole::Simulated(c) => c.label(),
        }
    }
}

/// One line from Python.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Incoming {
    Start {
        prompt: String,
    },
    Call {
        name: String,
        #[serde(default)]
        arguments: Value,
    },
    ToolResult {
        ok: bool,
        #[serde(default)]
        output: Option<Value>,
        #[serde(default)]
        error: Option<String>,
    },
    End,
}

enum Received {
    Message(Incoming),
    /// Stdin closed.
    Eof,
    /// Not UTF-8, not JSON, not an object with a known `op` and exactly its fields.
    Malformed,
}

/// The two ends of the conversation with Python, shared by the main loop and the remote tools (a tool's `call`
/// runs while the main loop is inside `GateFront::call`, and needs the same lines).
struct Io {
    reader: Box<dyn BufRead + Send>,
    writer: Box<dyn Write + Send>,
    /// Python sent something the protocol does not allow while a tool was waiting for its result.
    broken: bool,
    /// Stdin closed, or stdout stopped taking lines.
    closed: bool,
}

impl Io {
    fn send(&mut self, message: &Value) {
        if self.closed {
            return;
        }
        let Ok(mut line) = serde_json::to_string(message) else {
            self.closed = true;
            return;
        };
        line.push('\n');
        if self.writer.write_all(line.as_bytes()).is_err() || self.writer.flush().is_err() {
            self.closed = true;
        }
    }

    fn recv(&mut self) -> Received {
        loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => {
                    self.closed = true;
                    return Received::Eof;
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    return Received::Malformed;
                }
                Err(_) => {
                    self.closed = true;
                    return Received::Eof;
                }
            }
            if line.trim().is_empty() {
                continue;
            }
            return match serde_json::from_str::<Incoming>(&line) {
                Ok(message) => Received::Message(message),
                Err(_) => Received::Malformed,
            };
        }
    }
}

fn lock(io: &Mutex<Io>) -> MutexGuard<'_, Io> {
    io.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A catalog tool that runs in Python: `call` sends `run_tool` and blocks for the matching `tool_result`.
struct RemoteTool {
    io: Arc<Mutex<Io>>,
    /// AgentDojo's name for the function (the manifest's tool name after the suite prefix).
    name: String,
}

impl Tool for RemoteTool {
    fn call(
        &self,
        args: &BTreeMap<String, Value>,
        _credential: Option<&Credential>,
    ) -> Result<BTreeMap<String, Value>, ToolFailure> {
        let mut io = lock(&self.io);
        io.send(&json!({"op": "run_tool", "name": self.name, "arguments": args}));
        if io.closed {
            return Err(ToolFailure::Unavailable);
        }
        match io.recv() {
            Received::Message(Incoming::ToolResult {
                ok: true,
                output: None,
                ..
            }) => Ok(BTreeMap::new()),
            Received::Message(Incoming::ToolResult {
                ok: true,
                output: Some(Value::Object(map)),
                ..
            }) => Ok(map.into_iter().collect()),
            Received::Message(Incoming::ToolResult { ok: true, .. }) => Err(ToolFailure::Internal),
            Received::Message(Incoming::ToolResult {
                ok: false, error, ..
            }) => {
                eprintln!(
                    "munix: bridge: {} failed: {}",
                    self.name,
                    diagnostic(error.as_deref().unwrap_or(""))
                );
                // AgentDojo's functions fail on bad arguments (an unknown id, a wrong format).
                Err(ToolFailure::BadInput)
            }
            Received::Message(_) | Received::Malformed => {
                io.broken = true;
                Err(ToolFailure::Internal)
            }
            Received::Eof => Err(ToolFailure::Unavailable),
        }
    }
}

/// Python's error text for stderr: one line, no control characters, cut short.
fn diagnostic(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_DIAGNOSTIC)
        .collect()
}

/// How the task's plan comes about.
enum PlanSource {
    /// A hand-written plan, rewritten with this run's ids and signed here.
    Given(Plan),
    /// The Supervisor's planner writes it from the prompt and the catalog (empty store).
    Planner(Arc<dyn ModelAdapter>),
}

/// Everything one bridge session needs, with the randomness already drawn.
struct Setup {
    catalog: Catalog,
    ledger_path: PathBuf,
    plan: PlanSource,
    /// The gray-zone reviewer's model; `None` sends gray-zone requests to the Console, which says no.
    reviewer: Option<Arc<dyn ModelAdapter>>,
    /// The Readers' model (`munix_readers::banking`); `None` withholds the third-party text they would read.
    reader: Option<Arc<dyn ModelAdapter>>,
    /// `--simulated-user`: the Console is `SimulatedUser`, not a flat no.
    simulated_user: bool,
    /// Plan memory, for a planner-written plan: a stored plan replaces the planner call when one matches.
    memory: Option<PlanMemory>,
    /// The injection detector for the Gate and the Readers; `None` scores nothing.
    detector: Option<DetectorConfig>,
    /// The planner's, reviewer's and Readers' adapters, metered, so `ended` can report what the Supervisor spent.
    meters: Vec<Metered>,
    key: SigningKey,
    task: TaskId,
    session: SessionId,
    plan_id: PlanId,
    nonce: String,
}

/// The suite every manifest in the catalog belongs to: the part of each tool name before its first dot.
fn suite_of(catalog: &Catalog) -> Result<String, Failure> {
    let mut suite: Option<&str> = None;
    for (name, _) in catalog.iter() {
        let Some((prefix, rest)) = name.as_str().split_once('.') else {
            return Err(Failure::config(format!(
                "tool {name} has no suite prefix (expected <suite>.<name>)"
            )));
        };
        if rest.is_empty() {
            return Err(Failure::config(format!("tool {name} has no function name")));
        }
        match suite {
            None => suite = Some(prefix),
            Some(first) if first == prefix => {}
            Some(_) => {
                return Err(Failure::config(
                    "the manifests belong to more than one suite",
                ));
            }
        }
    }
    suite
        .map(str::to_owned)
        .ok_or_else(|| Failure::config("no manifests found"))
}

/// The Gate with every manifest's tool registered as a remote tool at its manifest's digest.
fn build_gate(setup: &Setup, io: &Arc<Mutex<Io>>) -> Result<Gate, Failure> {
    if let Some(dir) = setup
        .ledger_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
    {
        std::fs::create_dir_all(dir)
            .map_err(|_| Failure::config("cannot create the ledger directory"))?;
    }
    let ledger = Ledger::create(&setup.ledger_path)
        .map_err(|e| Failure::config(format!("cannot create the ledger: {e}")))?;
    let mut vault = Vault::new();
    for (_, manifest) in setup.catalog.iter() {
        if let Some(at) = &manifest.credentials {
            vault.insert(at.clone(), Credential::new(PLACEHOLDER_CREDENTIAL));
        }
    }
    let mut gate = Gate::new(setup.key.clone(), setup.catalog.clone(), vault, ledger);
    if let Some(detector) = &setup.detector {
        gate.set_detector(detector.clone());
    }
    for (name, manifest) in setup.catalog.iter() {
        let function = name
            .as_str()
            .split_once('.')
            .map_or(name.as_str(), |(_, rest)| rest);
        let remote = RemoteTool {
            io: Arc::clone(io),
            name: function.to_owned(),
        };
        // Third-party text goes through a Reader, so the agent gets typed values instead.
        let tool = munix_readers::banking::wrap(
            name.as_str(),
            Box::new(remote),
            setup.reader.clone(),
            setup.detector.clone(),
        );
        let pinned = manifest
            .digest()
            .map_err(|e| Failure::config(e.to_string()))?;
        gate.register(name.clone(), pinned, tool)
            .map_err(|e| Failure::config(format!("registering {name}: {e}")))?;
    }
    Ok(gate)
}

/// Runs one bridge session over `reader` and `writer`. Returns `Ok` when the session ended with `end` or stdin
/// closed; a failure is also sent to Python as `{"op":"error",…}` (and carries its exit code).
fn serve_bridge<R, W>(reader: R, writer: W, setup: Setup) -> Result<(), Failure>
where
    R: BufRead + Send + 'static,
    W: Write + Send + 'static,
{
    let io = Arc::new(Mutex::new(Io {
        reader: Box::new(reader),
        writer: Box::new(writer),
        broken: false,
        closed: false,
    }));
    let result = session(&io, setup);
    if let Err(failure) = &result {
        lock(&io).send(&json!({"op": "error", "message": failure.message}));
    }
    result
}

fn malformed() -> Failure {
    Failure::usage("malformed input")
}

fn session(io: &Arc<Mutex<Io>>, setup: Setup) -> Result<(), Failure> {
    let suite = suite_of(&setup.catalog)?;
    let mut gate = build_gate(&setup, io)?;

    // `start`: the prompt, then the plan, both signed here.
    let prompt_text = match lock(io).recv() {
        Received::Message(Incoming::Start { prompt }) => prompt,
        Received::Eof => return Ok(()),
        Received::Message(_) | Received::Malformed => return Err(malformed()),
    };
    let key = &setup.key;
    let envelope = PromptEnvelope {
        task: setup.task.clone(),
        session: setup.session.clone(),
        nonce: setup.nonce.clone(),
        text: prompt_text,
        data: Vec::new(),
    };
    envelope
        .validate()
        .map_err(|e| Failure::config(format!("prompt: {e}")))?;
    let prompt_hash = envelope
        .digest()
        .map_err(|e| Failure::config(format!("prompt: {e}")))?;
    let sign_failed = |e: munix_core::error::Error| Failure::failed(e.to_string());
    // The bridge's task holds no stores, so the planner and plan memory both see none.
    let stores = BTreeMap::new();
    let prompt_text = envelope.text.clone();
    let mut origin = PlanOrigin::Given;
    let plan = match &setup.plan {
        PlanSource::Given(plan) => {
            let plan = rewrite_plan(
                plan.clone(),
                setup.task.clone(),
                setup.plan_id.clone(),
                prompt_hash,
            );
            Signed::sign(key, Purpose::Plan, plan).map_err(sign_failed)?
        }
        PlanSource::Planner(adapter) => {
            // A stored plan that matches and passes the planner's own checks replaces the planner call; anything
            // else is a miss.
            let stored = setup.memory.as_ref().and_then(|memory| {
                let (template, level) = memory.lookup(&prompt_text, &stores)?;
                let plan = PlanMemory::instantiate(
                    &template,
                    setup.task.clone(),
                    setup.plan_id.clone(),
                    prompt_hash.clone(),
                );
                planner::check_plan(&plan, &setup.catalog, &stores).ok()?;
                Some((plan, template.key, level))
            });
            match stored {
                Some((plan, template, level)) => {
                    origin = PlanOrigin::Memory(template, level);
                    Signed::sign(key, Purpose::Plan, plan).map_err(sign_failed)?
                }
                None => {
                    origin = PlanOrigin::Planner;
                    let planner = Planner::new(Arc::clone(adapter), key.clone());
                    planner
                        .plan(&envelope, &setup.catalog, &stores, setup.plan_id.clone())
                        .map_err(|e| Failure::config(e.to_string()))?
                }
            }
        }
    };
    let prompt = Signed::sign(key, Purpose::Prompt, envelope.clone()).map_err(sign_failed)?;
    let store = Store::new();
    let brief = gate
        .start_task(&prompt, &plan, &store)
        .map_err(|e| Failure::config(format!("cannot start the task: {e}")))?;
    let plan_steps = plan.body.steps.len();
    // For reading a run afterwards: the plan holds only what the planner saw (the prompt and the catalog), never
    // tool output, and stderr is the harness's local log.
    if let Ok(body) = serde_json::to_string(&plan.body) {
        eprintln!("munix bridge: plan {body}");
    }
    if let PlanOrigin::Memory(template, level) = &origin
        && !gate.log_plan_note(
            &setup.task,
            PlanNote::Reused {
                template,
                level: level.as_str(),
            },
        )
    {
        return Err(Failure::failed("cannot write the ledger"));
    }
    let mut front = GateFront::new(
        &mut gate,
        key,
        brief,
        BridgeConsole::new(setup.simulated_user),
    );
    if let Some(adapter) = &setup.reviewer {
        let reviewer = Reviewer::new(Arc::clone(adapter), key.clone());
        front = front.with_reviewer(reviewer, envelope);
    }
    lock(io).send(&json!({
        "op": "started",
        "task": setup.task.as_str(),
        "plan_steps": plan_steps,
    }));

    // `call`s until `end`.
    loop {
        let received = lock(io).recv();
        match received {
            Received::Eof => return Ok(()),
            Received::Message(Incoming::Call { name, arguments }) => {
                // The lock is not held here: the remote tools take it to talk to Python.
                let result = front.call(&format!("{suite}_{name}"), &arguments);
                let mut io = lock(io);
                if io.broken {
                    return Err(malformed());
                }
                io.send(&json!({
                    "op": "result",
                    "text": result.text,
                    "is_error": result.is_error,
                }));
                if io.closed {
                    return Ok(());
                }
            }
            Received::Message(Incoming::End) => break,
            Received::Message(_) | Received::Malformed => return Err(malformed()),
        }
    }

    let takeover = front.takeover();
    drop(front);
    // After the task: count a reuse, or keep a planner plan from a clean run (no takeover, no off-plan denial).
    if let Some(memory) = &setup.memory {
        match &origin {
            PlanOrigin::Memory(..) => {
                if let Err(e) = memory.record_use(&prompt_text, &stores) {
                    eprintln!("munix: {e}");
                }
            }
            PlanOrigin::Planner if takeover.is_none() && !off_plan_in(&setup.ledger_path) => {
                match memory.remember(&plan.body, &prompt_text, &stores) {
                    Ok(template) => {
                        let _ = gate.log_plan_note(
                            &setup.task,
                            PlanNote::Remembered {
                                template: &template.key,
                            },
                        );
                    }
                    Err(e) => eprintln!("munix: {e}"),
                }
            }
            PlanOrigin::Planner | PlanOrigin::Given => {}
        }
    }
    let context_trust = gate.context_trust(&setup.task).map(|t| t.value());
    drop(gate);
    let (entries, verified) = match munix_ledger::verify_file(&setup.ledger_path) {
        Ok(entries) => (entries, true),
        Err(_) => (0, false),
    };
    let (mut calls, mut prompt_tokens, mut completion_tokens) = (0u64, 0u64, 0u64);
    for meter in &setup.meters {
        let (n, usage) = meter.total();
        calls = calls.saturating_add(n);
        prompt_tokens = prompt_tokens.saturating_add(usage.prompt_tokens);
        completion_tokens = completion_tokens.saturating_add(usage.completion_tokens);
    }
    lock(io).send(&json!({
        "op": "ended",
        "context_trust": context_trust,
        "ledger_entries": entries,
        "ledger_verified": verified,
        "takeover": takeover.as_ref().map(code_text),
        "plan": origin.label(),
        "supervisor_usage": {
            "calls": calls,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
        },
    }));
    Ok(())
}

/// Where a session's plan came from.
enum PlanOrigin {
    /// `--plan`.
    Given,
    /// The Supervisor's planner, this session.
    Planner,
    /// Plan memory: the template's key, and how it matched.
    Memory(munix_core::crypto::Digest, Level),
}

impl PlanOrigin {
    /// What `ended` reports: `given`, `planner`, `memory:exact` or `memory:shape`.
    fn label(&self) -> String {
        match self {
            PlanOrigin::Given => "given".to_owned(),
            PlanOrigin::Planner => "planner".to_owned(),
            PlanOrigin::Memory(_, level) => format!("memory:{}", level.as_str()),
        }
    }
}

/// True when the ledger records an off-plan denial or a takeover: the plan missed something, so it isn't kept.
/// An unreadable or broken ledger counts as true.
pub(crate) fn off_plan_in(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return true;
    };
    let Ok(entries) = munix_ledger::verify_bytes(&bytes) else {
        return true;
    };
    entries.iter().any(|entry| {
        let event = &entry.event;
        event["event"] == "takeover" || (event["event"] == "ruling" && event["code"] == "off_plan")
    })
}

/// `munix bridge`. Exit codes: 0 after `end` or when stdin closes, 2 for bad usage, bad configuration or
/// malformed input, 1 for a failure while running.
pub fn main(args: Vec<String>) -> ExitCode {
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            if failure.message == USAGE {
                eprintln!("{USAGE}");
            } else {
                eprintln!("munix: {}", failure.message);
            }
            ExitCode::from(failure.code)
        }
    }
}

/// `.env` and the environment, the API key and the Supervisor's model.
fn model_config() -> Result<(Env, String, String), Failure> {
    let env = Env::load(Path::new(".env"))?;
    let api_key = env
        .get("MODEL_API_KEY")
        .ok_or_else(|| Failure::config("MODEL_API_KEY is not set (put it in .env)"))?;
    let model = env.get_or("MUNIX_SUPERVISOR_MODEL", DEFAULT_MODEL);
    Ok((env, api_key, model))
}

fn run(args: &[String]) -> Result<(), Failure> {
    let opts = parse_args(args)?;
    let catalog = load_catalog(&opts.manifests)?;
    let mut meters = Vec::new();
    let mut metered = |adapter: Arc<dyn ModelAdapter>| -> Arc<dyn ModelAdapter> {
        let meter = Metered::new(adapter);
        meters.push(meter.clone());
        Arc::new(meter)
    };
    let mut memory = None;
    let (plan, reviewer, reader) = match &opts.plan {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|_| Failure::config(format!("cannot read {}", path.display())))?;
            let given = PlanSource::Given(
                Plan::from_yaml(&text)
                    .map_err(|e| Failure::config(format!("{}: {e}", path.display())))?,
            );
            if opts.no_reviewer {
                // No model anywhere: no key needed, and the Readers withhold what they would read.
                (given, None, None)
            } else {
                let (env, api_key, model) = model_config()?;
                let reviewer = supervisor_adapter(&env, &model, Role::Reviewer, &api_key)?;
                let reader = supervisor_adapter(&env, &model, Role::Reader, &api_key)?;
                (given, Some(metered(reviewer)), Some(metered(reader)))
            }
        }
        None => {
            let (env, api_key, model) = model_config()?;
            let planner = supervisor_adapter(&env, &model, Role::Planner, &api_key)?;
            let reviewer = supervisor_adapter(&env, &model, Role::Reviewer, &api_key)?;
            let reader = supervisor_adapter(&env, &model, Role::Reader, &api_key)?;
            if let Some(dir) = &opts.plan_memory {
                let effort = env.get_or(Role::Planner.env_var(), "default");
                memory = Some(PlanMemory::open(
                    dir,
                    &catalog,
                    &planner::version(&model, &effort),
                ));
            }
            (
                PlanSource::Planner(metered(planner)),
                Some(metered(reviewer)),
                Some(metered(reader)),
            )
        }
    };
    let detector = match &opts.detector {
        Some(d) => Some(detector_config(&d.url, &d.name, d.threshold)?),
        None => None,
    };
    let setup = Setup {
        catalog,
        detector,
        ledger_path: opts.ledger,
        plan,
        reviewer,
        reader,
        simulated_user: opts.simulated_user,
        memory,
        meters,
        key: SigningKey::from_bytes(&random_bytes(32)?)
            .map_err(|e| Failure::failed(e.to_string()))?,
        task: parse_id(&format!("T-{}", random_hex(4)?))?,
        session: parse_id(&format!("S-{}", random_hex(4)?))?,
        plan_id: parse_id(&format!("P-{}", random_hex(4)?))?,
        nonce: random_hex(16)?,
    };
    serve_bridge(
        std::io::BufReader::new(std::io::stdin()),
        std::io::stdout(),
        setup,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use munix_adapters::MockAdapter;
    use munix_core::manifest::ToolManifest;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU32, Ordering};

    const READ: &str = "
tool: test.read
description: Read a note and some contacts.
tier: 1
output:
  note:     {type: text,      region: ugc_review, confidential: public}
  contacts: {type: 'email[]', region: ugc_review, confidential: public, max: 3}
";
    const NEWS: &str = "
tool: test.news
description: Read the headline of the day.
tier: 0
output:
  headline: {type: text, region: editorial, confidential: public}
";
    const SEND: &str = "
tool: test.send
description: Send a message.
tier: 3
egress: true
credentials: vault://mail/test
args:
  to:   {type: 'email[]', role: destination, max: 5}
  body: {type: text,      role: content,     max_len: 2000}
output:
  message_id: {type: id, region: operator_content, confidential: internal}
";
    const PLAN: &str = "
plan: P-test
task: T-test
prompt_hash: sha256:0000000000000000000000000000000000000000000000000000000000000000
reads: [ugc_review, editorial, operator_content]
steps:
  - id: 1
    tool: test.read
    args: {}
    budget: 3
  - id: 2
    tool: test.news
    args: {}
    budget: 3
  - id: 3
    tool: test.send
    args:
      to:   {from: [prompt]}
      body: {dlp: no_secret}
    budget: 3
amendments:
  auto_max_tier: 1
";
    const PROMPT: &str = "Send my status to boss@corp.example when you are done.";
    /// The same plan, but `send` may also take its recipient from step 1's contacts, so a low-trust recipient
    /// is a gray or confirm-user request rather than a takeover.
    fn plan_with_step_recipients() -> String {
        PLAN.replace(
            "to:   {from: [prompt]}",
            "to:   {from: [prompt, step.1.contacts], min_trust: 0}",
        )
    }

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Stdout captured in memory.
    #[derive(Clone, Default)]
    struct Out(Arc<Mutex<Vec<u8>>>);

    impl Write for Out {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Run {
        result: Result<(), Failure>,
        out: Vec<Value>,
        ledger: PathBuf,
        dir: PathBuf,
    }

    impl Drop for Run {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn setup(dir: &Path, reviewer: Option<Arc<dyn ModelAdapter>>) -> Setup {
        setup_with(dir, reviewer, PLAN, false)
    }

    fn setup_with(
        dir: &Path,
        reviewer: Option<Arc<dyn ModelAdapter>>,
        plan: &str,
        simulated_user: bool,
    ) -> Setup {
        let manifests: Vec<ToolManifest> = [READ, NEWS, SEND]
            .iter()
            .map(|y| ToolManifest::from_yaml(y).unwrap())
            .collect();
        // Metered as in `run`, so `ended` reports the reviewer's calls.
        let meters: Vec<Metered> = reviewer
            .iter()
            .map(|r| Metered::new(Arc::clone(r)))
            .collect();
        let reviewer = meters
            .first()
            .map(|m| Arc::new(m.clone()) as Arc<dyn ModelAdapter>);
        Setup {
            catalog: Catalog::from_manifests(manifests).unwrap(),
            ledger_path: dir.join("sub").join("ledger.jsonl"),
            plan: PlanSource::Given(Plan::from_yaml(plan).unwrap()),
            reviewer,
            reader: None,
            detector: None,
            simulated_user,
            memory: None,
            meters,
            key: SigningKey::from_bytes(&[9u8; 32]).unwrap(),
            task: "T-bridge1".parse().unwrap(),
            session: "S-bridge1".parse().unwrap(),
            plan_id: "P-bridge1".parse().unwrap(),
            nonce: "0123456789abcdef".to_owned(),
        }
    }

    /// Feeds `lines` to a bridge and returns what it wrote.
    fn drive(lines: &[Value], reviewer: Arc<dyn ModelAdapter>) -> Run {
        drive_with(lines, Some(reviewer))
    }

    fn drive_with(lines: &[Value], reviewer: Option<Arc<dyn ModelAdapter>>) -> Run {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("munix-bridge-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input: String = lines.iter().map(|l| format!("{l}\n")).collect();
        drive_raw(&input, setup(&dir, reviewer), dir)
    }

    fn drive_raw(input: &str, setup: Setup, dir: PathBuf) -> Run {
        let out = Out::default();
        let ledger = setup.ledger_path.clone();
        let result = serve_bridge(
            Cursor::new(input.to_owned().into_bytes()),
            out.clone(),
            setup,
        );
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        let out = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        Run {
            result,
            out,
            ledger,
            dir,
        }
    }

    /// Like `drive_with` and no reviewer, with the plan given and the simulated user as the Console.
    fn drive_simulated(lines: &[Value], plan: &str) -> Run {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("munix-bridge-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input: String = lines.iter().map(|l| format!("{l}\n")).collect();
        drive_raw(&input, setup_with(&dir, None, plan, true), dir)
    }

    fn no_reviewer() -> Arc<dyn ModelAdapter> {
        Arc::new(MockAdapter::new(Vec::new()))
    }

    fn start() -> Value {
        json!({"op": "start", "prompt": PROMPT})
    }

    fn call(name: &str, arguments: Value) -> Value {
        json!({"op": "call", "name": name, "arguments": arguments})
    }

    fn tool_ok(output: Value) -> Value {
        json!({"op": "tool_result", "ok": true, "output": output})
    }

    fn end() -> Value {
        json!({"op": "end"})
    }

    /// The `ref:` ids in a delivered `- item` list.
    fn refs_in(text: &str) -> Vec<String> {
        text.lines()
            .filter_map(|l| l.strip_prefix("- "))
            .filter(|item| item.starts_with("ref:"))
            .map(str::to_owned)
            .collect()
    }

    fn ops(run: &Run) -> Vec<&str> {
        run.out.iter().map(|m| m["op"].as_str().unwrap()).collect()
    }

    #[test]
    fn a_call_the_gate_allows_runs_in_python_and_the_result_comes_back() {
        let run = drive(
            &[
                start(),
                call("read", json!({})),
                tool_ok(json!({"note": "all quiet", "contacts": ["a@b.example"]})),
                end(),
            ],
            no_reviewer(),
        );
        run.result.as_ref().unwrap();
        assert_eq!(ops(&run), ["started", "run_tool", "result", "ended"]);
        assert_eq!(run.out[0]["plan_steps"], 3);
        assert!(run.out[0]["task"].as_str().unwrap().starts_with("T-"));
        // The function name is AgentDojo's, without the suite.
        assert_eq!(run.out[1]["name"], "read");
        assert_eq!(run.out[1]["arguments"], json!({}));
        assert_eq!(run.out[2]["is_error"], false);
        let text = run.out[2]["text"].as_str().unwrap();
        assert!(text.contains("## note [ugc_review, trust "), "{text}");
        assert!(text.contains("all quiet"));
        // An address in an untrusted output is only ever shown as a ref.
        assert!(!text.contains("a@b.example"), "{text}");
        assert_eq!(refs_in(text).len(), 1, "{text}");
        // An output with refs says what they are, without naming one.
        assert!(text.ends_with(crate::front::REFS_NOTE), "{text}");
        assert!(
            !text.contains(crate::front::FLAG_NOTE),
            "no Reader flag, no note"
        );

        let ended = &run.out[3];
        assert_eq!(ended["takeover"], Value::Null);
        assert_eq!(ended["ledger_verified"], true);
        assert!(ended["ledger_entries"].as_u64().unwrap() >= 4);
        assert!(ended["context_trust"].as_u64().unwrap() < 100);
        // The ledger really is where it was asked for, and its parent directory was created.
        assert_eq!(
            munix_ledger::verify_file(&run.ledger).unwrap() as u64,
            ended["ledger_entries"].as_u64().unwrap()
        );
    }

    #[test]
    fn a_destination_from_the_prompt_runs_with_the_real_address() {
        let run = drive(
            &[
                start(),
                call("send", json!({"to": ["ref:e1"], "body": "done"})),
                tool_ok(json!({"message_id": "m-1"})),
                end(),
            ],
            no_reviewer(),
        );
        run.result.as_ref().unwrap();
        assert_eq!(ops(&run), ["started", "run_tool", "result", "ended"]);
        assert_eq!(run.out[1]["name"], "send");
        // Python gets the resolved argument, not the ref.
        assert_eq!(
            run.out[1]["arguments"],
            json!({"to": ["boss@corp.example"], "body": "done"})
        );
        assert_eq!(run.out[2]["is_error"], false);
        assert!(run.out[2]["text"].as_str().unwrap().contains("m-1"));
        assert_eq!(run.out[3]["takeover"], Value::Null);
        // Only trusted content was touched, so the context stays high.
        assert!(run.out[3]["context_trust"].as_u64().unwrap() >= 60);
    }

    #[test]
    fn a_destination_from_a_low_trust_output_is_a_takeover_and_halts_the_task() {
        // The first `read` is followed by the contacts' ref in a `send`; the second `send` is never run.
        let mut lines = vec![
            start(),
            call("read", json!({})),
            tool_ok(json!({"note": "hi", "contacts": ["evil@attacker.example"]})),
        ];
        // The ref id is only known once the first result is out, so run the first half to learn it.
        let first = drive(&lines, no_reviewer());
        let text = first.out[2]["text"].as_str().unwrap().to_owned();
        let contact = refs_in(&text).remove(0);
        drop(first);

        lines.push(call("send", json!({"to": [contact], "body": "x"})));
        lines.push(call("send", json!({"to": ["ref:e1"], "body": "y"})));
        lines.push(end());
        let run = drive(&lines, no_reviewer());
        run.result.as_ref().unwrap();
        // No `run_tool` for either send.
        assert_eq!(
            ops(&run),
            ["started", "run_tool", "result", "result", "result", "ended"]
        );
        assert_eq!(run.out[3]["text"], "denied: untrusted_destination");
        assert_eq!(run.out[3]["is_error"], true);
        assert_eq!(run.out[4]["text"], "denied: task halted");
        assert_eq!(run.out[4]["is_error"], true);
        assert_eq!(run.out[5]["takeover"], "untrusted_destination");
        assert_eq!(run.out[5]["ledger_verified"], true);
    }

    #[test]
    fn a_gray_zone_call_the_reviewer_hands_to_the_user_is_denied_without_asking() {
        let reviewer = Arc::new(MockAdapter::new(vec![Ok(json!({
            "verdict": "confirm_user",
            "reason": "unclear",
        }))]));
        let run = drive(
            &[
                start(),
                call("news", json!({})),
                tool_ok(json!({"headline": "A quiet day"})),
                call("send", json!({"to": ["ref:e1"], "body": "done"})),
                end(),
            ],
            reviewer.clone(),
        );
        run.result.as_ref().unwrap();
        // `news` ran; `send` was reviewed, handed to the (always-no) Console, and never reached Python.
        assert_eq!(
            ops(&run),
            ["started", "run_tool", "result", "result", "ended"]
        );
        assert_eq!(reviewer.seen().len(), 1);
        assert_eq!(run.out[3]["text"], "denied: user_denied");
        assert_eq!(run.out[3]["is_error"], true);
        assert_eq!(run.out[4]["takeover"], Value::Null);
        // The reviewer's one call is reported, so the runner can count the Supervisor's spend.
        assert_eq!(run.out[4]["supervisor_usage"]["calls"], 1);
    }

    #[test]
    fn without_a_reviewer_a_gray_zone_call_goes_to_the_console_and_is_denied() {
        let run = drive_with(
            &[
                start(),
                call("news", json!({})),
                tool_ok(json!({"headline": "A quiet day"})),
                call("send", json!({"to": ["ref:e1"], "body": "done"})),
                end(),
            ],
            None,
        );
        run.result.as_ref().unwrap();
        // The same gray-zone call as above, with no adapter anywhere: denied by the Console, nothing runs.
        assert_eq!(
            ops(&run),
            ["started", "run_tool", "result", "result", "ended"]
        );
        assert_eq!(run.out[3]["text"], "denied: user_denied");
        assert_eq!(run.out[3]["is_error"], true);
        assert_eq!(run.out[4]["takeover"], Value::Null);
        assert_eq!(run.out[4]["supervisor_usage"]["calls"], 0);
    }

    #[test]
    fn the_simulated_user_approves_a_prompt_recipient_and_denies_a_low_trust_one() {
        let plan = plan_with_step_recipients();
        let read = [
            start(),
            call("read", json!({})),
            tool_ok(json!({"note": "hi", "contacts": ["evil@attacker.example"]})),
        ];
        // The ref id is only known once the first result is out.
        let first = drive_simulated(&read, &plan);
        first.result.as_ref().unwrap();
        let contact = refs_in(first.out[2]["text"].as_str().unwrap()).remove(0);
        drop(first);

        // The recipient is the address in the user's prompt: the simulated user approves, so it runs.
        let mut lines = read.to_vec();
        lines.push(call("send", json!({"to": ["ref:e1"], "body": "done"})));
        lines.push(tool_ok(json!({"message_id": "m-1"})));
        lines.push(end());
        let run = drive_simulated(&lines, &plan);
        run.result.as_ref().unwrap();
        assert_eq!(
            ops(&run),
            [
                "started", "run_tool", "result", "run_tool", "result", "ended"
            ]
        );
        assert_eq!(run.out[3]["name"], "send");
        assert_eq!(
            run.out[3]["arguments"],
            json!({"to": ["boss@corp.example"], "body": "done"})
        );
        assert_eq!(run.out[4]["is_error"], false);
        let ledger = std::fs::read_to_string(&run.ledger).unwrap();
        assert!(ledger.contains("console.simulated_user"), "{ledger}");
        assert!(!ledger.contains("console.user"), "{ledger}");
        drop(run);

        // The recipient only traces to a low-trust output: denied, and nothing runs.
        let mut lines = read.to_vec();
        lines.push(call("send", json!({"to": [contact], "body": "x"})));
        lines.push(end());
        let run = drive_simulated(&lines, &plan);
        run.result.as_ref().unwrap();
        assert_eq!(
            ops(&run),
            ["started", "run_tool", "result", "result", "ended"]
        );
        assert_eq!(run.out[3]["text"], "denied: user_denied");
        assert_eq!(run.out[3]["is_error"], true);
        assert_eq!(run.out[4]["takeover"], Value::Null);
        let ledger = std::fs::read_to_string(&run.ledger).unwrap();
        assert!(ledger.contains("console.simulated_user"), "{ledger}");

        // Without the flag the same prompt recipient is denied: the Console is a flat no.
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("munix-bridge-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut lines = read.to_vec();
        lines.push(call("send", json!({"to": ["ref:e1"], "body": "done"})));
        lines.push(end());
        let input: String = lines.iter().map(|l| format!("{l}\n")).collect();
        let run = drive_raw(&input, setup_with(&dir, None, &plan, false), dir);
        assert_eq!(run.out[3]["text"], "denied: user_denied");
    }

    #[test]
    fn a_failed_tool_is_a_coarse_failure_and_the_session_goes_on() {
        let run = drive(
            &[
                start(),
                call("read", json!({})),
                json!({"op": "tool_result", "ok": false, "error": "no such thing"}),
                end(),
            ],
            no_reviewer(),
        );
        run.result.as_ref().unwrap();
        assert_eq!(ops(&run), ["started", "run_tool", "result", "ended"]);
        assert_eq!(run.out[2]["text"], "tool failed: bad_input");
        assert_eq!(run.out[2]["is_error"], true);
    }

    #[test]
    fn a_call_outside_the_plan_is_a_takeover() {
        let run = drive(
            &[start(), call("wire_money", json!({})), end()],
            no_reviewer(),
        );
        run.result.as_ref().unwrap();
        assert_eq!(ops(&run), ["started", "result", "ended"]);
        assert_eq!(run.out[1]["text"], "denied: off_plan");
        assert_eq!(run.out[2]["takeover"], "off_plan");
    }

    #[test]
    fn stdin_closing_early_ends_quietly() {
        let before_start = drive(&[], no_reviewer());
        before_start.result.as_ref().unwrap();
        assert!(before_start.out.is_empty());

        let after_start = drive(&[start()], no_reviewer());
        after_start.result.as_ref().unwrap();
        assert_eq!(ops(&after_start), ["started"]);

        // Closing while a tool waits for its result writes no `result` or `ended`.
        let mid_tool = drive(&[start(), call("read", json!({}))], no_reviewer());
        mid_tool.result.as_ref().unwrap();
        assert_eq!(ops(&mid_tool), ["started", "run_tool"]);
    }

    #[test]
    fn malformed_input_is_an_error_and_exit_code_2() {
        let cases: Vec<(&str, Vec<Value>)> = vec![
            ("not json", vec![]),
            ("call before start", vec![call("read", json!({}))]),
            ("start twice", vec![start(), start()]),
            ("unknown op", vec![json!({"op": "dance"})]),
            (
                "unexpected field",
                vec![json!({"op": "start", "prompt": "x", "extra": 1})],
            ),
            ("stray tool_result", vec![start(), tool_ok(json!({}))]),
            (
                "wrong reply to run_tool",
                vec![start(), call("read", json!({})), end()],
            ),
        ];
        for (what, lines) in cases {
            let mut input: String = lines.iter().map(|l| format!("{l}\n")).collect();
            if what == "not json" {
                input.push_str("this is not json\n");
            }
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let dir =
                std::env::temp_dir().join(format!("munix-bridge-test-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let run = drive_raw(&input, setup(&dir, Some(no_reviewer())), dir);
            let failure = run.result.as_ref().unwrap_err();
            assert_eq!(failure.code, 2, "{what}");
            let last = run.out.last().unwrap();
            assert_eq!(last["op"], "error", "{what}");
            assert_eq!(last["message"], "malformed input", "{what}");
        }
    }

    #[test]
    fn manifests_must_share_one_suite() {
        let read = ToolManifest::from_yaml(READ).unwrap();
        let other = ToolManifest::from_yaml(&NEWS.replace("test.news", "other.news")).unwrap();
        let mixed = Catalog::from_manifests(vec![read.clone(), other]).unwrap();
        assert!(suite_of(&mixed).is_err());
        let bare = Catalog::from_manifests(vec![
            ToolManifest::from_yaml(&NEWS.replace("test.news", "news")).unwrap(),
        ])
        .unwrap();
        assert!(suite_of(&bare).is_err());
        let one = Catalog::from_manifests(vec![read]).unwrap();
        assert_eq!(suite_of(&one).unwrap(), "test");
    }

    #[test]
    fn arguments_are_parsed() {
        let args =
            |parts: &[&str]| -> Vec<String> { parts.iter().map(|p| (*p).to_owned()).collect() };
        let ok = parse_args(&args(&[
            "bridge",
            "--manifests",
            "m",
            "--ledger",
            "l.jsonl",
            "--plan",
            "p.yaml",
        ]))
        .unwrap();
        assert_eq!(
            ok,
            Options {
                manifests: "m".into(),
                ledger: "l.jsonl".into(),
                plan: Some("p.yaml".into()),
                no_reviewer: false,
                simulated_user: false,
                plan_memory: None,
                detector: None,
            }
        );
        let memory = parse_args(&args(&[
            "bridge",
            "--manifests",
            "m",
            "--ledger",
            "l.jsonl",
            "--plan-memory",
            "mem",
        ]))
        .unwrap();
        assert_eq!(memory.plan_memory, Some(PathBuf::from("mem")));
        // Plan memory stands in for the planner: not with a given plan.
        assert!(
            parse_args(&args(&[
                "bridge",
                "--manifests",
                "m",
                "--ledger",
                "l.jsonl",
                "--plan",
                "p.yaml",
                "--plan-memory",
                "mem",
            ]))
            .is_err()
        );
        let simulated = parse_args(&args(&[
            "bridge",
            "--manifests",
            "m",
            "--ledger",
            "l.jsonl",
            "--simulated-user",
        ]))
        .unwrap();
        assert!(simulated.simulated_user && simulated.plan.is_none() && !simulated.no_reviewer);
        let both = parse_args(&args(&[
            "bridge",
            "--simulated-user",
            "--manifests",
            "m",
            "--ledger",
            "l.jsonl",
            "--plan",
            "p.yaml",
            "--no-reviewer",
        ]))
        .unwrap();
        assert!(both.simulated_user && both.no_reviewer);
        let quiet = parse_args(&args(&[
            "bridge",
            "--manifests",
            "m",
            "--no-reviewer",
            "--ledger",
            "l.jsonl",
            "--plan",
            "p.yaml",
        ]))
        .unwrap();
        assert!(quiet.no_reviewer);
        assert_eq!(quiet.plan, Some(PathBuf::from("p.yaml")));
        for bad in [
            // `--no-reviewer` without `--plan` would leave the planner without a model.
            args(&[
                "bridge",
                "--manifests",
                "m",
                "--ledger",
                "l",
                "--no-reviewer",
            ]),
            args(&[
                "bridge",
                "--manifests",
                "m",
                "--ledger",
                "l",
                "--plan",
                "p",
                "--no-reviewer",
                "--no-reviewer",
            ]),
            args(&[
                "bridge",
                "--manifests",
                "m",
                "--ledger",
                "l",
                "--simulated-user",
                "--simulated-user",
            ]),
            args(&["bridge"]),
            args(&["bridge", "--help"]),
            args(&["bridge", "--manifests", "m"]),
            args(&["bridge", "--manifests", "m", "--ledger"]),
            args(&[
                "bridge",
                "--manifests",
                "m",
                "--manifests",
                "n",
                "--ledger",
                "l",
            ]),
            args(&["run", "--manifests", "m", "--ledger", "l"]),
        ] {
            assert_eq!(parse_args(&bad).unwrap_err().code, 2, "{bad:?}");
        }
    }

    #[test]
    fn detector_flags_are_parsed_and_checked() {
        let base = [
            "bridge",
            "--manifests",
            "m",
            "--ledger",
            "l",
            "--plan",
            "p.yaml",
        ];
        let with = |extra: &[&str]| -> Result<Options, Failure> {
            let all: Vec<String> = base.iter().chain(extra).map(|p| (*p).to_owned()).collect();
            parse_args(&all)
        };
        let url = "http://127.0.0.1:8787/score";
        let only_url = with(&["--detector-url", url]).unwrap();
        assert_eq!(
            only_url.detector,
            Some(DetectorOpts {
                url: url.to_owned(),
                name: DEFAULT_DETECTOR_NAME.to_owned(),
                threshold: DEFAULT_THRESHOLD,
            })
        );
        let full = with(&[
            "--detector-threshold",
            "0.8",
            "--detector-url",
            "http://localhost:9/score",
            "--detector-name",
            "guard-x",
        ])
        .unwrap();
        assert_eq!(
            full.detector,
            Some(DetectorOpts {
                url: "http://localhost:9/score".to_owned(),
                name: "guard-x".to_owned(),
                threshold: 0.8,
            })
        );
        assert_eq!(with(&[]).unwrap().detector, None);
        for bad in [
            // a name or threshold without a URL
            &["--detector-name", "x"][..],
            &["--detector-threshold", "0.5"],
            // a URL that could send text off the machine, or is malformed
            &["--detector-url", "http://example.com:80/score"],
            &["--detector-url", "https://127.0.0.1:8787/score"],
            &["--detector-url", "http://127.0.0.1/score"],
            // bad thresholds
            &["--detector-url", url, "--detector-threshold", "1.5"],
            &["--detector-url", url, "--detector-threshold", "-0.1"],
            &["--detector-url", url, "--detector-threshold", "nan"],
            &["--detector-url", url, "--detector-threshold", "high"],
            // bad name, repeated or incomplete flags
            &["--detector-url", url, "--detector-name", ""],
            &["--detector-url", url, "--detector-url", url],
            &["--detector-url"],
        ] {
            assert_eq!(with(bad).unwrap_err().code, 2, "{bad:?}");
        }
    }

    // ---- plan memory ----

    /// The planner's draft for PROMPT: read the headline, then send to the address in the prompt.
    fn draft() -> Value {
        json!({
            "reads": ["editorial", "operator_content", "ugc_review"],
            "steps": [
                {"id": 1, "tool": "test.read", "args": {}, "budget": 2},
                {"id": 2, "tool": "test.news", "args": {}, "budget": 2},
                {"id": 3, "tool": "test.send", "args": {"to": {"from": ["prompt"]}, "body": {"dlp": "no_secret"}},
                 "budget": 1}
            ],
            "amendments": {"auto_max_tier": 1}
        })
    }

    /// A session whose plan comes from `planner` (or plan memory), with memory in `memory_dir`.
    fn drive_planned(lines: &[Value], planner: Vec<Value>, memory_dir: &Path) -> Run {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("munix-bridge-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut setup = setup_with(&dir, None, PLAN, false);
        let adapter: Arc<dyn ModelAdapter> =
            Arc::new(MockAdapter::new(planner.into_iter().map(Ok).collect()));
        setup.plan = PlanSource::Planner(adapter);
        setup.memory = Some(PlanMemory::open(memory_dir, &setup.catalog, "test-planner"));
        let input: String = lines.iter().map(|l| format!("{l}\n")).collect();
        drive_raw(&input, setup, dir)
    }

    fn start_with(prompt: &str) -> Value {
        json!({"op": "start", "prompt": prompt})
    }

    fn ledger_events(run: &Run) -> Vec<String> {
        std::fs::read_to_string(&run.ledger)
            .unwrap()
            .lines()
            .map(|l| {
                serde_json::from_str::<Value>(l).unwrap()["event"]["event"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn a_clean_planner_plan_is_remembered_and_reused_by_shape_then_exactly() {
        let memory =
            std::env::temp_dir().join(format!("munix-bridge-memory-{}-a", std::process::id()));
        let _ = std::fs::remove_dir_all(&memory);
        let task = |prompt: &str| {
            vec![
                start_with(prompt),
                call("news", json!({})),
                tool_ok(json!({"headline": "A quiet day"})),
                end(),
            ]
        };
        // 1. The planner writes the plan; the run is clean, so it is kept.
        let first = drive_planned(&task(PROMPT), vec![draft()], &memory);
        first.result.as_ref().unwrap();
        assert_eq!(first.out.last().unwrap()["plan"], "planner");
        assert!(ledger_events(&first).contains(&"plan_remembered".to_owned()));
        assert_eq!(PlanMemory::list(&memory).len(), 1);

        // 2. The same prompt with another address: the stored plan, no planner call (the mock has no reply left).
        let other = "Send my status to carol@corp.example when you are done.";
        let second = drive_planned(&task(other), Vec::new(), &memory);
        second.result.as_ref().unwrap();
        assert_eq!(second.out[0]["plan_steps"], 3);
        assert_eq!(second.out.last().unwrap()["plan"], "memory:shape");
        assert_eq!(second.out.last().unwrap()["supervisor_usage"]["calls"], 0);
        assert!(ledger_events(&second).contains(&"plan_reused".to_owned()));

        // 3. That prompt again: an exact match now, and the use is counted.
        let third = drive_planned(&task(other), Vec::new(), &memory);
        assert_eq!(third.out.last().unwrap()["plan"], "memory:exact");
        assert_eq!(PlanMemory::list(&memory)[0].uses, 2);
    }

    #[test]
    fn a_stored_plan_over_the_planners_limits_is_a_miss() {
        let memory =
            std::env::temp_dir().join(format!("munix-bridge-memory-{}-c", std::process::id()));
        let _ = std::fs::remove_dir_all(&memory);
        let task = vec![
            start_with(PROMPT),
            call("news", json!({})),
            tool_ok(json!({"headline": "x"})),
            end(),
        ];
        drive_planned(&task, vec![draft()], &memory)
            .result
            .as_ref()
            .unwrap();
        // Someone edits the stored plan to allow automatic amendments of payments (tier 3).
        let path = std::fs::read_dir(&memory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut template: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        template["amendments"]["auto_max_tier"] = json!(3);
        std::fs::write(&path, template.to_string()).unwrap();
        // Not reused: the planner is asked again (and here it has a draft ready).
        let run = drive_planned(&task, vec![draft()], &memory);
        run.result.as_ref().unwrap();
        assert_eq!(run.out.last().unwrap()["plan"], "planner");
    }

    #[test]
    fn a_plan_from_a_run_with_a_takeover_or_an_off_plan_denial_is_not_kept() {
        let memory =
            std::env::temp_dir().join(format!("munix-bridge-memory-{}-b", std::process::id()));
        let _ = std::fs::remove_dir_all(&memory);
        // A takeover: the destination comes from a low-trust output.
        let mut lines = vec![
            start_with(PROMPT),
            call("read", json!({})),
            tool_ok(json!({"note": "hi", "contacts": ["evil@attacker.example"]})),
        ];
        let probe = drive_planned(&lines, vec![draft()], &memory);
        let contact = refs_in(probe.out[2]["text"].as_str().unwrap()).remove(0);
        drop(probe);
        let _ = std::fs::remove_dir_all(&memory);
        lines.push(call("send", json!({"to": [contact], "body": "x"})));
        lines.push(end());
        let run = drive_planned(&lines, vec![draft()], &memory);
        assert_eq!(run.out.last().unwrap()["takeover"], "untrusted_destination");
        assert!(PlanMemory::list(&memory).is_empty());

        // An off-plan denial in the ledger (the plan missed something) also keeps the plan out, as does a broken
        // ledger.
        let dir = std::env::temp_dir().join(format!("munix-bridge-offplan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("l.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut ledger = Ledger::create(&path).unwrap();
        ledger
            .append(json!({"event": "ruling", "outcome": "allow"}))
            .unwrap();
        drop(ledger);
        assert!(!off_plan_in(&path));
        let _ = std::fs::remove_file(dir.join("l2.jsonl"));
        let mut ledger = Ledger::create(dir.join("l2.jsonl")).unwrap();
        ledger
            .append(json!({"event": "ruling", "outcome": "deny", "code": "off_plan"}))
            .unwrap();
        assert!(off_plan_in(&dir.join("l2.jsonl")));
        assert!(off_plan_in(&dir.join("missing.jsonl")));
        assert!(PlanMemory::list(&memory).is_empty());
    }
}
