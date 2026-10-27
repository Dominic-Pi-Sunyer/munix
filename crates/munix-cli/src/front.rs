//! The Gate's MCP front: what the agent sees as its tools, and how each call becomes a Gate request.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use munix_core::crypto::{Digest, Purpose, Signed, SigningKey};
use munix_core::decision::{Decision, Stage, Verdict};
use munix_core::ids::ToolName;
use munix_core::manifest::{ArgSpec, Catalog};
use munix_core::plan::Step;
use munix_core::prompt::PromptEnvelope;
use munix_core::request::{DEFAULT_LIST_MAX, Request};
use munix_core::validate::Scalar;
use munix_gate::gate::{Gate, Reply, TaskBrief};
use munix_gate::ingest::Delivered;
use munix_gate::policy::DenyCode;
use munix_gate::tool::ToolFailure;
use munix_runtime::mcp::{CallResult, McpHandler, ToolInfo};
use munix_supervisor::reviewer::Reviewer;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::confirm::Confirmer;

/// Progress on one agent instance's MCP channel, read by the watchdog.
pub struct FrontProgress {
    last_call: Mutex<Instant>,
    delivered: AtomicU64,
}

impl Default for FrontProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl FrontProgress {
    pub fn new() -> Self {
        FrontProgress {
            last_call: Mutex::new(Instant::now()),
            delivered: AtomicU64::new(0),
        }
    }

    pub fn last_call(&self) -> Instant {
        *self
            .last_call
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn delivered(&self) -> u64 {
        self.delivered.load(Ordering::Relaxed)
    }

    fn note_call(&self) {
        *self
            .last_call
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
    }

    fn note_delivered(&self) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
    }
}

/// Serves one task's tools to one agent instance.
pub struct GateFront<'a, C: Confirmer> {
    gate: &'a mut Gate,
    key: &'a SigningKey,
    brief: TaskBrief,
    confirmer: C,
    reviewer: Option<(Reviewer, PromptEnvelope)>,
    progress: Option<Arc<FrontProgress>>,
    takeover: Option<DenyCode>,
    operator_log: bool,
}

impl<'a, C: Confirmer> GateFront<'a, C> {
    /// `key` signs the Console's decisions (`Purpose::UserConfirmation`); it is the Gate's key.
    pub fn new(gate: &'a mut Gate, key: &'a SigningKey, brief: TaskBrief, confirmer: C) -> Self {
        GateFront {
            gate,
            key,
            brief,
            confirmer,
            reviewer: None,
            progress: None,
            takeover: None,
            operator_log: false,
        }
    }

    /// Prints one block on stderr (the operator's terminal, never the agent) each time the Gate denies a call:
    /// what was blocked, why, and where each destination came from. `munix run` turns it on.
    pub fn with_operator_log(mut self) -> Self {
        self.operator_log = true;
        self
    }

    /// Attaches the Supervisor's gray-zone reviewer for `Stage::LlmReview` requests.
    pub fn with_reviewer(
        mut self,
        reviewer: munix_supervisor::reviewer::Reviewer,
        prompt: munix_core::prompt::PromptEnvelope,
    ) -> Self {
        self.reviewer = Some((reviewer, prompt));
        self
    }

    /// Records tool call timing and delivered step counts for the watchdog.
    pub fn with_progress(mut self, p: Arc<FrontProgress>) -> Self {
        self.progress = Some(p);
        self
    }

    /// The takeover signal that ended the session, if any.
    pub fn takeover(&self) -> Option<DenyCode> {
        self.takeover
    }

    /// The tool a call names (see [`resolve_tool`]). Only the brief's planned steps are preferred, so amended
    /// tools are never advertised.
    fn tool_named(&self, name: &str) -> Option<ToolName> {
        resolve_tool(
            name,
            self.brief.plan.steps.iter().map(|step| &step.tool),
            self.gate.catalog(),
        )
    }

    /// The first step with this tool that still has budget, else the last one with it, else step 0. Steps come from
    /// the Gate's current plan for the task, so a step the Gate amended in earlier is found like a planned one.
    fn step_for(&self, tool: &ToolName) -> u32 {
        let Some(plan) = self.gate.plan(&self.brief.task) else {
            return 0;
        };
        let steps: Vec<&Step> = plan
            .steps
            .iter()
            .filter(|step| &step.tool == tool)
            .collect();
        let open = steps.iter().find(|step| {
            self.gate.calls_made(&self.brief.task, step.id).unwrap_or(0) < step.budget
        });
        open.or(steps.last()).map_or(0, |step| step.id)
    }

    /// Shows a parked request to the user and applies their signed answer.
    fn ask_user(&mut self, request_hash: &Digest) -> Reply {
        let Some(view) = self.gate.describe_pending(&self.brief.task, request_hash) else {
            return Reply::Failed(ToolFailure::Internal);
        };
        let approved = self.confirmer.confirm(&view);
        let decision = Decision {
            verdict: if approved {
                Verdict::Approve
            } else {
                Verdict::Deny
            },
            request_hash: request_hash.clone(),
            task: self.brief.task.clone(),
            plan: self.brief.plan.plan.clone(),
            band: view.band,
            stage: Stage::User,
            reasons: vec!["console.user".to_owned()],
        };
        match Signed::sign(self.key, Purpose::UserConfirmation, decision) {
            Ok(signed) => self.gate.decide(&signed),
            Err(_) => Reply::Failed(ToolFailure::Internal),
        }
    }

    /// Asks the Supervisor's reviewer about a request parked for `Stage::LlmReview` and applies its signed decision.
    fn ask_reviewer(&mut self, request_hash: &Digest) -> Option<Reply> {
        let (reviewer, prompt) = self.reviewer.as_ref()?;
        let view = self.gate.review_view(&self.brief.task, request_hash)?;
        let plan = self.gate.plan(&self.brief.task)?;
        let signed = reviewer.review(prompt, plan, &view, request_hash).ok()?;
        Some(self.gate.decide(&signed))
    }

    fn answer(&mut self, reply: Reply) -> CallResult {
        let reply = match reply {
            Reply::Pending {
                request_hash,
                needs: Stage::LlmReview,
            } => self
                .ask_reviewer(&request_hash)
                .unwrap_or_else(|| self.ask_user(&request_hash)),
            other => other,
        };
        match reply {
            Reply::Pending {
                request_hash,
                needs: Stage::User,
            } => {
                let reply = self.ask_user(&request_hash);
                self.settled(reply)
            }
            other => self.settled(other),
        }
    }

    /// The text for a reply that is not waiting for anyone.
    fn settled(&mut self, reply: Reply) -> CallResult {
        match reply {
            Reply::Delivered(delivered) => {
                if let Some(p) = &self.progress {
                    p.note_delivered();
                }
                ok(delivered_text(&delivered))
            }
            Reply::Malformed(violations) => {
                let codes: Vec<String> = violations.iter().map(|v| code_text(&v.code)).collect();
                refused(format!("denied: {}", codes.join(", ")))
            }
            Reply::Denied(code) => refused(format!("denied: {}", code_text(&code))),
            Reply::Takeover(code) => {
                self.takeover = Some(code);
                refused(format!("denied: {}", code_text(&code)))
            }
            Reply::Halted => refused("denied: task halted".to_owned()),
            Reply::Failed(failure) => refused(format!("tool failed: {}", code_text(&failure))),
            // A user decision never leaves a request waiting; if it ever did, nothing ran.
            Reply::Pending { .. } => refused(format!(
                "tool failed: {}",
                code_text(&ToolFailure::Internal)
            )),
        }
    }

    fn refs_paragraph(&self) -> String {
        let destinations =
            "Pass destinations (links and addresses) as these refs, never as raw text.";
        if self.brief.refs.is_empty() {
            return destinations.to_owned();
        }
        let refs: Vec<String> = self
            .brief
            .refs
            .iter()
            .map(|r| format!("{}: {}", r.id, r.what))
            .collect();
        format!("Refs you can use: {}. {destinations}", refs.join("; "))
    }
}

impl<C: Confirmer> McpHandler for GateFront<'_, C> {
    /// One tool per distinct tool in the plan's steps, in plan order. The MCP name is the tool name with `.`
    /// replaced by `_` (`web.open` → `web_open`). The description is the manifest's, then a short paragraph listing
    /// the brief's refs (`ref:e2: store contacts.boss`) and saying that destinations should be passed as refs. The
    /// input schema comes from the manifest's arguments: `text`/`email`/`url`/`phone`/`id`/`date`/`ref` are
    /// strings, `bool` boolean, `int` integer, `number` number, `enum` a string with `enum`; lists are arrays with
    /// `maxItems` (`max`, else 100); non-optional arguments are `required`; arguments the step's plan rule forbids
    /// are left out; `additionalProperties` is false.
    fn tools(&self) -> Vec<ToolInfo> {
        let catalog = self.gate.catalog();
        let mut seen = BTreeSet::new();
        let mut tools = Vec::new();
        for step in &self.brief.plan.steps {
            if !seen.insert(step.tool.clone()) {
                continue;
            }
            let Some(manifest) = catalog.get(&step.tool) else {
                continue;
            };
            // An argument is left out only when every step that uses this tool forbids it.
            let users: Vec<&Step> = self
                .brief
                .plan
                .steps
                .iter()
                .filter(|s| s.tool == step.tool)
                .collect();
            let mut properties = Map::new();
            let mut required = Vec::new();
            for (name, spec) in &manifest.args {
                let forbidden = users
                    .iter()
                    .all(|s| s.args.get(name).is_some_and(|rule| rule.is_forbidden()));
                if forbidden {
                    continue;
                }
                properties.insert(name.clone(), arg_schema(spec));
                if !spec.optional {
                    required.push(json!(name));
                }
            }
            tools.push(ToolInfo {
                name: mcp_name(&step.tool),
                description: format!("{}\n\n{}", manifest.description, self.refs_paragraph()),
                input_schema: json!({
                    "type": "object",
                    "properties": properties,
                    "required": required,
                    "additionalProperties": false,
                }),
            });
        }
        tools
    }

    /// Turns the call into a `Request` for this task and submits it.
    ///
    /// - The name maps back by replacing `_` with `.`. A name that isn't a valid tool name, or any tool, is still
    ///   submitted (with step 0 when no plan step uses it), so the Gate rules on it and logs it. A name that can't
    ///   become a `ToolName` at all is answered `denied: off_plan` and treated as a takeover.
    /// - The step is the first step of the Gate's current plan (planned or amended) with that tool whose budget isn't
    ///   used up (`Gate::calls_made`), else the last step with that tool. A tool no step uses is sent as step 0 and
    ///   the Gate may amend a step in for it (low tiers only).
    /// - `arguments` must be an object (`null` counts as `{}`); anything else is answered `denied: wrong_type`.
    ///
    /// Replies, as text (`is_error` for everything but `Delivered`):
    /// - `Delivered`: one block per field in name order, headed `## <field> [<region>, trust <n>]`, with strings as
    ///   they are and list items as `- item` lines; then one line naming the withheld fields, if any.
    /// - `Malformed`: `denied: ` and the violation codes, comma-separated.
    /// - `Denied(code)`: `denied: <code>`.
    /// - `Pending`: when `needs` is `Stage::LlmReview` and a reviewer is attached, asks `Reviewer::review` on the
    ///   Gate's redacted `review_view` and passes the signed decision to `Gate::decide`; if `decide` answers
    ///   `Pending { needs: User }` (or if there is no reviewer, the view or plan is missing, or `review` errors),
    ///   falls back to the Console. When `needs` is `Stage::User`, goes straight to the Console (`Gate::describe_pending`
    ///   and the confirmer), signs a `Stage::User` decision (approve or deny, the band from the view, reason
    ///   `console.user`) with `Purpose::UserConfirmation`, passes it to `Gate::decide`, and answers with that reply
    ///   mapped the same way.
    /// - `Takeover(code)`: `denied: <code>`; records the code so `should_stop` ends the session.
    /// - `Halted`: `denied: task halted`. `Failed(f)`: `tool failed: <f>`.
    fn call(&mut self, name: &str, arguments: &Value) -> CallResult {
        if let Some(p) = &self.progress {
            p.note_call();
        }
        let Some(tool) = self.tool_named(name) else {
            self.takeover = Some(DenyCode::OffPlan);
            return refused(format!("denied: {}", code_text(&DenyCode::OffPlan)));
        };
        let args = match arguments {
            Value::Object(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            Value::Null => Default::default(),
            _ => return refused("denied: wrong_type".to_owned()),
        };
        let request = Request {
            task: self.brief.task.clone(),
            plan: self.brief.plan.plan.clone(),
            step: self.step_for(&tool),
            tool,
            args,
        };
        let reply = self.gate.submit(&request);
        if self.operator_log {
            let blocked = match &reply {
                Reply::Takeover(code) => Some((code, true)),
                Reply::Denied(code) => Some((code, false)),
                _ => None,
            };
            if let Some((code, takeover)) = blocked {
                let args = self
                    .gate
                    .describe_destinations(&request.task, &request)
                    .unwrap_or_default();
                for line in blocked_lines(&request.tool, code, takeover, &args) {
                    eprintln!("{line}");
                }
            }
        }
        self.answer(reply)
    }

    fn should_stop(&self) -> bool {
        self.takeover.is_some()
    }
}

/// The operator's lines for a denied call, e.g.
/// `munix: BLOCKED email.send (untrusted_destination): takeover, the task is halted` then
/// `munix:   to = hacker@evil.com  <- step 1 reviews (ugc_review, trust 15)`.
pub fn blocked_lines(
    tool: &ToolName,
    code: &DenyCode,
    takeover: bool,
    args: &[munix_gate::gate::PendingArg],
) -> Vec<String> {
    let what = if takeover {
        "takeover, the task is halted"
    } else {
        "denied"
    };
    let mut lines = vec![format!(
        "munix: BLOCKED {} ({}): {what}",
        tool.as_str(),
        code_text(code)
    )];
    for arg in args {
        let sources = if arg.sources.is_empty() {
            "untraced".to_owned()
        } else {
            arg.sources.join(", ")
        };
        lines.push(format!(
            "munix:   {} = {}  <- {sources}",
            arg.name, arg.value
        ));
    }
    lines
}

/// The tool an MCP name stands for: a planned tool whose MCP name matches; else the one catalog tool whose MCP name
/// matches (so `banking_get_balance` is `banking.get_balance`, a tool the Gate may amend in); else the name with
/// every `_` read as `.` (not in the catalog, so the Gate takes it over as off plan). Two catalog tools with the same
/// MCP name resolve to neither.
pub fn resolve_tool<'t>(
    name: &str,
    planned: impl Iterator<Item = &'t ToolName>,
    catalog: &Catalog,
) -> Option<ToolName> {
    let mut planned = planned;
    if let Some(tool) = planned.find(|tool| mcp_name(tool) == name) {
        return Some(tool.clone());
    }
    let mut in_catalog = catalog
        .iter()
        .map(|(tool, _)| tool)
        .filter(|tool| mcp_name(tool) == name);
    match (in_catalog.next(), in_catalog.next()) {
        (Some(tool), None) => Some(tool.clone()),
        (Some(_), Some(_)) => None,
        (None, _) => name.replace('_', ".").parse().ok(),
    }
}

/// The MCP name of a tool: `web.open` is `web_open`.
fn mcp_name(tool: &ToolName) -> String {
    tool.as_str().replace('.', "_")
}

fn arg_schema(spec: &ArgSpec) -> Value {
    let item = match spec.ty.scalar {
        Scalar::Bool => json!({"type": "boolean"}),
        Scalar::Int => json!({"type": "integer"}),
        Scalar::Number => json!({"type": "number"}),
        Scalar::Enum => json!({"type": "string", "enum": spec.values}),
        Scalar::Text
        | Scalar::Email
        | Scalar::Url
        | Scalar::Phone
        | Scalar::Iban
        | Scalar::Id
        | Scalar::Date
        | Scalar::Ref => json!({"type": "string"}),
    };
    if spec.ty.list {
        json!({
            "type": "array",
            "items": item,
            "maxItems": spec.max.unwrap_or(DEFAULT_LIST_MAX),
        })
    } else {
        item
    }
}

/// The snake_case name a coarse code goes by on the wire (`off_plan`, `unavailable`).
pub fn code_text<T: Serialize>(code: &T) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn ok(text: String) -> CallResult {
    CallResult {
        text,
        is_error: false,
    }
}

fn refused(text: String) -> CallResult {
    CallResult {
        text,
        is_error: true,
    }
}

fn delivered_text(delivered: &Delivered) -> String {
    let mut blocks = Vec::new();
    for (name, value) in &delivered.fields {
        let head = match delivered.labels.get(name) {
            Some(label) => format!(
                "## {name} [{}, trust {}]",
                code_text(&label.region),
                label.trust.value()
            ),
            None => format!("## {name}"),
        };
        let body = match value {
            Value::String(text) => text.clone(),
            Value::Array(items) => items
                .iter()
                .map(|item| match item {
                    Value::String(text) => format!("- {text}"),
                    other => format!("- {other}"),
                })
                .collect::<Vec<_>>()
                .join("\n"),
            other => other.to_string(),
        };
        blocks.push(format!("{head}\n{body}"));
    }
    if !delivered.withheld.is_empty() {
        blocks.push(format!(
            "Withheld fields: {}",
            delivered.withheld.join(", ")
        ));
    }
    if blocks.is_empty() {
        return "(no output)".to_owned();
    }
    blocks.join("\n\n")
}
