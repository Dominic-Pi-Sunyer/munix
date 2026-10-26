//! The Gate's MCP front: what the agent sees as its tools, and how each call becomes a Gate request.

use std::collections::BTreeSet;

use munix_core::crypto::{Digest, Purpose, Signed, SigningKey};
use munix_core::decision::{Decision, Stage, Verdict};
use munix_core::ids::ToolName;
use munix_core::manifest::ArgSpec;
use munix_core::plan::Step;
use munix_core::request::{DEFAULT_LIST_MAX, Request};
use munix_core::validate::Scalar;
use munix_gate::gate::{Gate, Reply, TaskBrief};
use munix_gate::ingest::Delivered;
use munix_gate::policy::DenyCode;
use munix_gate::tool::ToolFailure;
use munix_runtime::mcp::{CallResult, McpHandler, ToolInfo};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::confirm::Confirmer;

/// Serves one task's tools to one agent instance.
pub struct GateFront<'a, C: Confirmer> {
    gate: &'a mut Gate,
    key: &'a SigningKey,
    brief: TaskBrief,
    confirmer: C,
    takeover: Option<DenyCode>,
}

impl<'a, C: Confirmer> GateFront<'a, C> {
    /// `key` signs the Console's decisions (`Purpose::UserConfirmation`); it is the Gate's key.
    pub fn new(gate: &'a mut Gate, key: &'a SigningKey, brief: TaskBrief, confirmer: C) -> Self {
        GateFront {
            gate,
            key,
            brief,
            confirmer,
            takeover: None,
        }
    }

    /// The takeover signal that ended the session, if any.
    pub fn takeover(&self) -> Option<DenyCode> {
        self.takeover
    }

    /// The tool a call names: the plan's tool whose MCP name matches, else the name with `_` read as `.`.
    fn tool_named(&self, name: &str) -> Option<ToolName> {
        let in_plan = self
            .brief
            .plan
            .steps
            .iter()
            .map(|step| &step.tool)
            .find(|tool| mcp_name(tool) == name);
        match in_plan {
            Some(tool) => Some(tool.clone()),
            None => name.replace('_', ".").parse().ok(),
        }
    }

    /// The first plan step with this tool that still has budget, else the last one with it, else step 0.
    fn step_for(&self, tool: &ToolName) -> u32 {
        let steps: Vec<&Step> = self
            .brief
            .plan
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

    fn answer(&mut self, reply: Reply) -> CallResult {
        match reply {
            Reply::Pending { request_hash, .. } => {
                // A request that needs the Supervisor's review goes to the user too, until the Supervisor exists.
                let reply = self.ask_user(&request_hash);
                self.settled(reply)
            }
            other => self.settled(other),
        }
    }

    /// The text for a reply that is not waiting for anyone.
    fn settled(&mut self, reply: Reply) -> CallResult {
        match reply {
            Reply::Delivered(delivered) => ok(delivered_text(&delivered)),
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
    /// - The step is the first plan step with that tool whose budget isn't used up (`Gate::calls_made`), else the
    ///   last step with that tool.
    /// - `arguments` must be an object (`null` counts as `{}`); anything else is answered `denied: wrong_type`.
    ///
    /// Replies, as text (`is_error` for everything but `Delivered`):
    /// - `Delivered`: one block per field in name order, headed `## <field> [<region>, trust <n>]`, with strings as
    ///   they are and list items as `- item` lines; then one line naming the withheld fields, if any.
    /// - `Malformed`: `denied: ` and the violation codes, comma-separated.
    /// - `Denied(code)`: `denied: <code>`.
    /// - `Pending`: shows the request on the Console (`Gate::describe_pending` and the confirmer), signs a
    ///   `Stage::User` decision (approve or deny, the band from the view, reason `console.user`) with
    ///   `Purpose::UserConfirmation`, passes it to `Gate::decide`, and answers with that reply mapped the same way.
    ///   A review the Supervisor would give (`needs: LlmReview`) also goes to the user until the Supervisor exists.
    /// - `Takeover(code)`: `denied: <code>`; records the code so `should_stop` ends the session.
    /// - `Halted`: `denied: task halted`. `Failed(f)`: `tool failed: <f>`.
    fn call(&mut self, name: &str, arguments: &Value) -> CallResult {
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
        self.answer(reply)
    }

    fn should_stop(&self) -> bool {
        self.takeover.is_some()
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
