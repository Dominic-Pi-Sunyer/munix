//! The planner (design spec 6, Phase 1): writes the Plan of Record before anything is read.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::Arc;

use munix_adapters::{ModelAdapter, ModelRequest, complete_typed, sanitize_schema};
use munix_core::crypto::{Purpose, Signed, SigningKey};
use munix_core::ids::{PlanId, ToolName};
use munix_core::label::RegionType;
use munix_core::manifest::{ArgRole, Catalog};
use munix_core::plan::{Amendments, ArgRule, Plan, SourcePath, Step};
use munix_core::prompt::PromptEnvelope;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::reviewer::region_name;

const MAX_OUTPUT_TOKENS: u32 = 4000;

const SYSTEM_PROMPT: &str = "\
You are the Munix Supervisor planner. Before the agent reads any untrusted content, you write the \
Plan of Record for the user's task. Everything not allowed by the plan will be denied by the Gate.

Return a JSON object with:
- \"reads\": array of region types the agent may read (choose from: \"operator_legal\", \
\"operator_content\", \"operator_ui\", \"product_listing\", \"editorial\", \"search_snippet\", \
\"ugc_post\", \"ugc_review\", \"profile\", \"ugc_comment\", \"ad\", \"embedded_third_party\", \
\"user_content\", \"message\", \"unclassified\"; never \"hidden\"). List every region the task needs to do \
its job well, not only the ones the prompt names: summarizing a product's reviews also needs the product listing \
(name, price, specs) and any editorial take. Leave out regions the task has no use for. Include third-party regions (\"ugc_review\", \"ugc_comment\", \"ugc_post\", \"profile\", \"message\", \"unclassified\", \"ad\", \"embedded_third_party\", \"search_snippet\") \
only when the task needs that text; records the user or operator produced (\"operator_content\", \"user_content\", \"product_listing\" where relevant) carry what most tasks need.
- \"steps\": ordered array of 1 to 8 tool steps. Each step has:
  - \"id\": unique positive integer (1, 2, ...);
  - \"tool\": tool name from the catalog;
  - \"args\": object mapping argument names to their rule object (set any argument not used by \
this step's tool to null). Each rule object has:
    - \"from\": array of source paths (\"prompt\", \"user_data\", \"store.<name>.<key>\", \
\"step.<id>\", or \"step.<id>.<field>\") or null;
    - \"min_trust\": integer 0-100 (required whenever \"from\" includes a \"step.<id>\" source) or null;
    - \"dlp\": \"no_secret\", \"no_private\", or \"public_only\" (only on content arguments) or null;
    - \"may_embed\": {\"from\": [...], \"min_trust\": <int or null>} (on content arguments that may \
embed refs or values from earlier steps or prompt; \"min_trust\" is required when \"from\" includes \
a \"step.<id>\" source) or null;
    - \"forbid\": true to forbid an optional argument (when true, all other fields on that rule \
must be null), or null. On read-only tools (tier 0) never forbid control arguments (counts, \
flags): they carry no destination or data. On any other tool, forbid a control argument (amount, \
date, recurring) whenever the task does not call for changing it;
  - \"budget\": maximum calls for this step (integer 1 to 10).
- \"amendments\": {\"auto_max_tier\": 0 or 1}.

Rules that every valid plan must obey:
1. Only use tools from the catalog and argument names that belong to that step's tool.
2. Every destination argument of a tier 1+ tool must have either a non-empty \"from\" list or \
\"forbid\": true. Forbid optional destination arguments (such as \"cc\") when the prompt does not \
need them.
3. Every \"store.<name>.<key>\" source path must exist in the provided stores.
4. Every \"step.<id>\" or \"step.<id>.<field>\" source path must refer to an earlier step and an \
output field that tool actually produces, and must include \"min_trust\" (e.g. 60).
5. Content arguments on egress tools should set \"dlp\": \"no_secret\" (and \"forbid\": true on \
optional attachment arguments when unneeded).

Example plan for an unrelated task (\"Fetch the release notes URL from the prompt and post a \
summary to the team channel\"):
{
  \"reads\": [\"operator_content\", \"editorial\"],
  \"steps\": [
    {
      \"id\": 1,
      \"tool\": \"web.open\",
      \"args\": {
        \"url\": {\"from\": [\"prompt\"], \"min_trust\": null, \"dlp\": null, \"may_embed\": null, \"forbid\": null}
      },
      \"budget\": 2
    },
    {
      \"id\": 2,
      \"tool\": \"chat.post\",
      \"args\": {
        \"channel\": {\"from\": [\"store.channels.team\"], \"min_trust\": null, \"dlp\": null, \"may_embed\": null, \"forbid\": null},
        \"message\": {\"from\": null, \"min_trust\": null, \"dlp\": \"no_secret\", \"may_embed\": {\"from\": [\"prompt\", \"step.1\"], \"min_trust\": 60}, \"forbid\": null}
      },
      \"budget\": 1
    }
  ],
  \"amendments\": {\"auto_max_tier\": 1}
}";

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    /// The model failed, or gave no valid plan in two tries. The message is a fixed string or the validator's text,
    /// never the model's output.
    #[error("no valid plan: {0}")]
    NoPlan(String),
    #[error("could not sign the plan")]
    Sign,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftStep {
    id: u32,
    tool: ToolName,
    #[serde(default)]
    args: BTreeMap<String, Option<ArgRule>>,
    budget: u32,
}

impl From<DraftStep> for Step {
    fn from(draft: DraftStep) -> Self {
        let mut args = BTreeMap::new();
        for (name, rule) in draft.args {
            if let Some(mut rule) = rule {
                if rule.forbid == Some(false)
                    && (rule.from.is_some()
                        || rule.min_trust.is_some()
                        || rule.dlp.is_some()
                        || rule.may_embed.is_some())
                {
                    rule.forbid = None;
                }
                args.insert(name, rule);
            }
        }
        Step {
            id: draft.id,
            tool: draft.tool,
            args,
            budget: draft.budget,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanDraft {
    reads: BTreeSet<RegionType>,
    steps: Vec<DraftStep>,
    amendments: Amendments,
}

pub struct Planner {
    adapter: Arc<dyn ModelAdapter>,
    key: SigningKey,
}

/// Limits the planner can only tighten: a plan above them is rejected even if the model writes it.
pub const MAX_BUDGET_PER_STEP: u32 = 10;
pub const MAX_STEPS: usize = 8;
/// The lowest `min_trust` a rule may set on values taken from an earlier step's output, in `from` or `may_embed`.
/// The model can ask for more, never less: a lower value (the live planner once wrote 0, which would let a link
/// from a user review into an email) is raised to this.
pub const MIN_STEP_TRUST: u8 = 60;

/// Drops a `forbid` the model wrote on a control argument of a read-only tool (tier 0, no egress: a local read with
/// a count or a flag). Such arguments are checked for shape only and carry no destination or data, so forbidding
/// one adds no protection and only makes honest calls fail. On every other tool a forbid stays: on a write or a
/// payment tool a control argument (`amount`, `date`, `recurring`) changes what the call does, and the planner's
/// forbid is how a task like "change only the subject" pins it. Forbids on destination, selector and content
/// arguments always stay.
fn allow_control_args(plan: &mut Plan, catalog: &Catalog) {
    for step in &mut plan.steps {
        let Some(manifest) = catalog.get(&step.tool) else {
            continue;
        };
        if manifest.tier != 0 || manifest.egress {
            continue;
        }
        step.args.retain(|name, rule| {
            let control = manifest
                .args
                .get(name)
                .is_some_and(|spec| spec.role == ArgRole::Control);
            !(control && rule.is_forbidden())
        });
    }
}

/// Raises every `min_trust` the model set on a step source to at least [`MIN_STEP_TRUST`]. Tighten-only; a missing
/// `min_trust` is left for the validator to reject.
fn raise_step_trust_floors(plan: &mut Plan) {
    let floor = munix_core::label::Trust::new(MIN_STEP_TRUST);
    let names_a_step = |paths: &[munix_core::plan::SourcePath]| {
        paths
            .iter()
            .any(|p| matches!(p, munix_core::plan::SourcePath::Step { .. }))
    };
    for step in &mut plan.steps {
        for rule in step.args.values_mut() {
            // Only raise a floor the model wrote: a missing one stays missing, so `Plan::validate` still rejects it.
            if rule.from.as_deref().is_some_and(names_a_step)
                && let Some(t) = rule.min_trust
            {
                rule.min_trust = Some(t.max(floor));
            }
            if let Some(embed) = rule.may_embed.as_mut()
                && names_a_step(&embed.from)
                && let Some(t) = embed.min_trust
            {
                embed.min_trust = Some(t.max(floor));
            }
        }
    }
}

impl Planner {
    /// `adapter` should be built for `munix_adapters::Role::Planner`.
    pub fn new(adapter: Arc<dyn ModelAdapter>, key: SigningKey) -> Self {
        Planner { adapter, key }
    }

    /// Writes and signs the plan for a prompt.
    ///
    /// - **What the model sees:** a fixed system message that explains the plan format and the rules, with an
    ///   example plan for an unrelated task. Then:
    ///   - the prompt's text;
    ///   - the catalog: each tool's name, description, tier, arguments (name, type, role, optional) and outputs
    ///     (name, type, region);
    ///   - the store names and keys from `stores` (`contacts: boss`), never their values.
    /// - **What the model answers:** a draft with `reads`, `steps` (id, tool, args rules, budget) and
    ///   `amendments`, as JSON matching a hand-written schema. Source paths are strings such as `prompt`,
    ///   `store.contacts.boss` or `step.1`.
    /// - **Building the plan:** the planner sets `plan`, `task` (from the prompt) and `prompt_hash`
    ///   (`prompt.digest()`) itself, then checks it:
    ///   - `Plan::validate(catalog)`;
    ///   - at most `MAX_STEPS` steps;
    ///   - every budget at most `MAX_BUDGET_PER_STEP`;
    ///   - `auto_max_tier` at most 1;
    ///   - no store path that isn't in `stores`.
    /// - **Retry:** on a failed check it asks once more, adding the failure text (the validator's message, never
    ///   echoed model output) to the conversation. A second failure is `NoPlan`.
    /// - **Signing:** with `Purpose::Plan`.
    pub fn plan(
        &self,
        prompt: &PromptEnvelope,
        catalog: &Catalog,
        stores: &BTreeMap<String, Vec<String>>,
        plan_id: PlanId,
    ) -> Result<Signed<Plan>, PlanError> {
        let prompt_hash = prompt
            .digest()
            .map_err(|e| PlanError::NoPlan(format!("invalid prompt envelope: {e}")))?;
        let base_user = format_user_prompt(&prompt.text, catalog, stores);
        let schema = plan_schema(catalog);

        let mut last_failure: Option<String> = None;
        for _attempt in 0..2 {
            let user = match &last_failure {
                None => base_user.clone(),
                Some(failure) => format!(
                    "{base_user}\n\nPREVIOUS ATTEMPT FAILED\n{failure}\n\
                     Produce a corrected plan that satisfies every check."
                ),
            };
            let req = ModelRequest {
                system: SYSTEM_PROMPT.to_owned(),
                user,
                schema_name: "plan_draft".to_owned(),
                schema: schema.clone(),
                max_output_tokens: MAX_OUTPUT_TOKENS,
            };
            let draft = match complete_typed::<PlanDraft>(self.adapter.as_ref(), &req) {
                Ok(draft) => draft,
                Err(_) => {
                    last_failure = Some(
                        "draft parse check failed: the answer did not match the plan format"
                            .to_owned(),
                    );
                    continue;
                }
            };
            let mut plan = Plan {
                plan: plan_id.clone(),
                task: prompt.task.clone(),
                prompt_hash: prompt_hash.clone(),
                reads: draft.reads,
                steps: draft.steps.into_iter().map(Step::from).collect(),
                amendments: draft.amendments,
            };
            raise_step_trust_floors(&mut plan);
            allow_control_args(&mut plan, catalog);
            match check_plan(&plan, catalog, stores) {
                Ok(()) => {
                    return Signed::sign(&self.key, Purpose::Plan, plan)
                        .map_err(|_| PlanError::Sign);
                }
                Err(failure) => {
                    last_failure = Some(failure);
                }
            }
        }
        Err(PlanError::NoPlan(last_failure.unwrap_or_else(|| {
            "planner did not produce a valid plan".to_owned()
        })))
    }
}

fn check_plan(
    plan: &Plan,
    catalog: &Catalog,
    stores: &BTreeMap<String, Vec<String>>,
) -> Result<(), String> {
    if let Err(err) = plan.validate(catalog) {
        return Err(format!("plan validation check failed: {err}"));
    }
    if plan.steps.len() > MAX_STEPS {
        return Err(format!(
            "step count limit check failed: plan has more than {MAX_STEPS} steps"
        ));
    }
    if plan
        .steps
        .iter()
        .any(|step| step.budget > MAX_BUDGET_PER_STEP)
    {
        return Err(format!(
            "step budget limit check failed: step budget exceeds {MAX_BUDGET_PER_STEP}"
        ));
    }
    if plan.amendments.auto_max_tier > 1 {
        return Err("amendments limit check failed: auto_max_tier must be at most 1".to_owned());
    }
    for step in &plan.steps {
        for rule in step.args.values() {
            let paths = rule
                .from
                .iter()
                .flatten()
                .chain(rule.may_embed.iter().flat_map(|embed| embed.from.iter()));
            for path in paths {
                if let SourcePath::Store { name, key } = path
                    && !store_path_exists(stores, name, key.as_deref())
                {
                    return Err(
                        "store path check failed: plan names a store path that is not in stores"
                            .to_owned(),
                    );
                }
            }
        }
    }
    Ok(())
}

fn store_path_exists(
    stores: &BTreeMap<String, Vec<String>>,
    name: &str,
    key: Option<&str>,
) -> bool {
    let Some(keys) = stores.get(name) else {
        return false;
    };
    match key {
        Some(k) => keys.iter().any(|entry| entry == k),
        None => !keys.is_empty(),
    }
}

fn format_user_prompt(
    prompt_text: &str,
    catalog: &Catalog,
    stores: &BTreeMap<String, Vec<String>>,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "PROMPT\n{prompt_text}\n\nCATALOG");
    for (name, manifest) in catalog.iter() {
        let _ = writeln!(
            out,
            "- {name} (tier {}): {}",
            manifest.tier, manifest.description
        );
        for (arg_name, spec) in &manifest.args {
            let opt = if spec.optional {
                "optional"
            } else {
                "required"
            };
            let _ = writeln!(
                out,
                "  arg {arg_name}: type={}, role={}, {opt}",
                spec.ty,
                role_name(spec.role)
            );
        }
        for (out_name, spec) in &manifest.output {
            let _ = writeln!(
                out,
                "  output {out_name}: type={}, region={}",
                spec.ty,
                region_name(spec.region)
            );
        }
    }
    let _ = writeln!(out, "\nSTORES");
    if stores.is_empty() {
        let _ = write!(out, "(none)");
    } else {
        for (i, (store_name, keys)) in stores.iter().enumerate() {
            if i > 0 {
                let _ = writeln!(out);
            }
            let _ = write!(out, "{store_name}: {}", keys.join(", "));
        }
    }
    out
}

fn role_name(role: ArgRole) -> &'static str {
    match role {
        ArgRole::Destination => "destination",
        ArgRole::Content => "content",
        ArgRole::Selector => "selector",
        ArgRole::Control => "control",
    }
}

fn plan_schema(catalog: &Catalog) -> Value {
    let mut arg_names = BTreeSet::new();
    let mut tool_names = Vec::new();
    for (tool, manifest) in catalog.iter() {
        tool_names.push(Value::String(tool.as_str().to_owned()));
        for arg_name in manifest.args.keys() {
            arg_names.insert(arg_name.clone());
        }
    }
    let mut arg_props = Map::new();
    for arg_name in arg_names {
        arg_props.insert(
            arg_name,
            json!({
                "anyOf": [
                    {"$ref": "#/$defs/arg_rule"},
                    {"type": "null"}
                ]
            }),
        );
    }
    let tool_schema = if tool_names.is_empty() {
        json!({"type": "string"})
    } else {
        json!({"type": "string", "enum": tool_names})
    };
    sanitize_schema(&json!({
        "type": "object",
        "properties": {
            "reads": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "operator_legal",
                        "operator_content",
                        "operator_ui",
                        "product_listing",
                        "editorial",
                        "search_snippet",
                        "ugc_post",
                        "ugc_review",
                        "profile",
                        "ugc_comment",
                        "ad",
                        "embedded_third_party",
                        "user_content",
                        "message",
                        "unclassified"
                    ]
                }
            },
            "steps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "tool": tool_schema,
                        "args": {
                            "type": "object",
                            "properties": arg_props
                        },
                        "budget": {"type": "integer"}
                    }
                }
            },
            "amendments": {
                "type": "object",
                "properties": {
                    "auto_max_tier": {"type": "integer"}
                }
            }
        },
        "$defs": {
            "embed": {
                "type": "object",
                "properties": {
                    "from": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "min_trust": {
                        "anyOf": [
                            {"type": "integer"},
                            {"type": "null"}
                        ]
                    }
                }
            },
            "arg_rule": {
                "type": "object",
                "properties": {
                    "from": {
                        "anyOf": [
                            {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            {"type": "null"}
                        ]
                    },
                    "min_trust": {
                        "anyOf": [
                            {"type": "integer"},
                            {"type": "null"}
                        ]
                    },
                    "dlp": {
                        "anyOf": [
                            {
                                "type": "string",
                                "enum": ["no_secret", "no_private", "public_only"]
                            },
                            {"type": "null"}
                        ]
                    },
                    "may_embed": {
                        "anyOf": [
                            {"$ref": "#/$defs/embed"},
                            {"type": "null"}
                        ]
                    },
                    "forbid": {
                        "anyOf": [
                            {"type": "boolean"},
                            {"type": "null"}
                        ]
                    }
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use munix_adapters::{MockAdapter, Role, from_spec_for};
    use munix_core::crypto::Digest;
    use munix_core::manifest::ToolManifest;
    use munix_core::prompt::Attachment;

    const WEB_OPEN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../manifests/web.open.yaml"
    ));
    const EMAIL_SEND: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../manifests/email.send.yaml"
    ));
    const DEMO_PLAN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/demo-plan.yaml"
    ));

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[11; 32]).unwrap()
    }

    fn catalog() -> Catalog {
        Catalog::from_manifests([
            ToolManifest::from_yaml(WEB_OPEN).unwrap(),
            ToolManifest::from_yaml(EMAIL_SEND).unwrap(),
        ])
        .unwrap()
    }

    fn stores() -> BTreeMap<String, Vec<String>> {
        BTreeMap::from([("contacts".to_owned(), vec!["boss".to_owned()])])
    }

    fn prompt() -> PromptEnvelope {
        PromptEnvelope {
            task: "T-demo".parse().unwrap(),
            session: "S-secret-session".parse().unwrap(),
            nonce: "secret-nonce-9876543210".to_owned(),
            text: "Read the reviews at the PixelMart URL and email a short summary to my boss"
                .to_owned(),
            data: vec![Attachment {
                name: "private-notes.txt".to_owned(),
                content_digest: Digest::of_bytes(b"private-notes"),
                len: 13,
            }],
        }
    }

    fn valid_demo_draft() -> Value {
        json!({
            "reads": ["operator_content", "product_listing", "editorial", "ugc_review"],
            "steps": [
                {
                    "id": 1,
                    "tool": "web.open",
                    "args": {
                        "url": {"from": ["prompt"]}
                    },
                    "budget": 3
                },
                {
                    "id": 2,
                    "tool": "email.send",
                    "args": {
                        "to": {"from": ["store.contacts.boss"]},
                        "cc": {"forbid": true},
                        "attachments": {"forbid": true},
                        "subject": {"dlp": "no_secret"},
                        "body": {
                            "dlp": "no_secret",
                            "may_embed": {"from": ["prompt", "step.1"], "min_trust": 60}
                        }
                    },
                    "budget": 1
                }
            ],
            "amendments": {"auto_max_tier": 1}
        })
    }

    #[test]
    fn forbids_on_control_args_are_dropped_only_on_read_only_tools() {
        let payment = munix_core::manifest::ToolManifest::from_yaml(
            "
tool: bank.update
description: Update a scheduled payment.
tier: 3
egress: true
args:
  id:        {type: int,  role: selector}
  recipient: {type: iban, role: destination, optional: true}
  amount:    {type: int,  role: control, optional: true}
  date:      {type: date, role: control, optional: true}
  recurring: {type: bool, role: control, optional: true}
  note:      {type: text, role: content, optional: true}
output:
  message: {type: text, region: operator_content, confidential: public}
",
        )
        .unwrap();
        let read = munix_core::manifest::ToolManifest::from_yaml(
            "
tool: notes.list
description: List local notes.
tier: 0
args:
  n:    {type: int, role: control, optional: true}
  tag:  {type: text, role: selector, optional: true}
output:
  message: {type: text, region: operator_content, confidential: public}
",
        )
        .unwrap();
        let catalog = Catalog::from_manifests([payment, read]).unwrap();
        let mut plan = Plan::from_yaml(&format!(
            "
plan: P-1
task: T-1
prompt_hash: \"{}\"
reads: [operator_content]
steps:
  - id: 1
    tool: bank.update
    args:
      id:        {{from: [prompt]}}
      recipient: {{forbid: true}}
      amount:    {{forbid: true}}
      date:      {{forbid: true}}
      recurring: {{forbid: true}}
      note:      {{forbid: true}}
    budget: 1
  - id: 2
    tool: notes.list
    args:
      n:   {{forbid: true}}
      tag: {{forbid: true}}
    budget: 1
amendments:
  auto_max_tier: 0
",
            prompt().digest().unwrap().as_str()
        ))
        .unwrap();
        allow_control_args(&mut plan, &catalog);
        let pay = &plan.steps[0].args;
        for name in ["amount", "date", "recurring", "recipient", "note"] {
            assert!(
                pay[name].is_forbidden(),
                "{name} stays forbidden on a tier 3 tool"
            );
        }
        assert!(pay["id"].from.is_some(), "other rules are untouched");
        let read = &plan.steps[1].args;
        assert!(
            !read.contains_key("n"),
            "a read-only tool's control forbid is dropped"
        );
        assert!(read["tag"].is_forbidden(), "a selector stays forbidden");
    }

    #[test]
    fn low_step_trust_is_raised_to_the_floor_and_higher_is_kept() {
        // The body's floor comes back as 0, as the live planner once wrote; the subject asks for more than the floor.
        let mut draft = valid_demo_draft();
        draft["steps"][1]["args"]["body"]["may_embed"]["min_trust"] = json!(0);
        draft["steps"][1]["args"]["subject"] =
            json!({"dlp": "no_secret", "may_embed": {"from": ["step.1"], "min_trust": 90}});
        let mock = Arc::new(MockAdapter::new(vec![Ok(draft)]));
        let signing_key = key();
        let planner = Planner::new(mock, signing_key.clone());
        let signed = planner
            .plan(&prompt(), &catalog(), &stores(), "P-floor".parse().unwrap())
            .unwrap();
        let plan = signed.verify(&signing_key, Purpose::Plan).unwrap();
        let args = &plan.steps[1].args;
        let body = args["body"].may_embed.as_ref().unwrap();
        assert_eq!(
            body.min_trust,
            Some(munix_core::label::Trust::new(MIN_STEP_TRUST))
        );
        let subject = args["subject"].may_embed.as_ref().unwrap();
        assert_eq!(subject.min_trust, Some(munix_core::label::Trust::new(90)));
    }

    #[test]
    fn from_step_rule_low_trust_is_raised_and_missing_min_trust_is_rejected() {
        let mut draft = valid_demo_draft();
        draft["steps"][1]["args"]["to"] = json!({"from": ["step.1"], "min_trust": 0});
        let mock = Arc::new(MockAdapter::new(vec![Ok(draft)]));
        let signing_key = key();
        let planner = Planner::new(mock, signing_key.clone());
        let signed = planner
            .plan(
                &prompt(),
                &catalog(),
                &stores(),
                "P-to-floor".parse().unwrap(),
            )
            .unwrap();
        let plan = signed.verify(&signing_key, Purpose::Plan).unwrap();
        assert_eq!(
            plan.steps[1].args["to"].min_trust,
            Some(munix_core::label::Trust::new(MIN_STEP_TRUST))
        );

        let mut missing_min_trust = valid_demo_draft();
        missing_min_trust["steps"][1]["args"]["to"] = json!({"from": ["step.1"]});
        let mock = Arc::new(MockAdapter::new(vec![
            Ok(missing_min_trust.clone()),
            Ok(missing_min_trust),
        ]));
        let planner = Planner::new(mock, key());
        let err = planner
            .plan(
                &prompt(),
                &catalog(),
                &stores(),
                "P-no-floor".parse().unwrap(),
            )
            .unwrap_err();
        let PlanError::NoPlan(msg) = err else {
            panic!("expected NoPlan, got {err:?}");
        };
        assert!(msg.contains("a step source needs min_trust"), "{msg}");
    }

    #[test]
    fn good_draft_produces_signed_demo_plan() {
        let mock = Arc::new(MockAdapter::new(vec![Ok(valid_demo_draft())]));
        let signing_key = key();
        let planner = Planner::new(mock, signing_key.clone());
        let prompt = prompt();
        let plan_id: PlanId = "P-demo".parse().unwrap();

        let signed = planner
            .plan(&prompt, &catalog(), &stores(), plan_id.clone())
            .unwrap();
        let verified = signed.verify(&signing_key, Purpose::Plan).unwrap();

        let expected = Plan::from_yaml(DEMO_PLAN).unwrap();
        assert_eq!(verified.plan, plan_id);
        assert_eq!(verified.task, prompt.task);
        assert_eq!(verified.prompt_hash, prompt.digest().unwrap());
        assert_eq!(verified.reads, expected.reads);
        assert_eq!(verified.steps, expected.steps);
        assert_eq!(verified.amendments, expected.amendments);
        verified.validate(&catalog()).unwrap();
    }

    #[test]
    fn invalid_first_draft_then_valid_second_draft_succeeds_without_quoting_draft() {
        let mut bad_draft = valid_demo_draft();
        // Remove the required destination constraint on `url` and include a distinctive string in another field
        // to verify the retry prompt never quotes the first draft's contents.
        bad_draft["steps"][0]["args"] = json!({});
        let mock = Arc::new(MockAdapter::new(vec![
            Ok(bad_draft),
            Ok(valid_demo_draft()),
        ]));
        let signing_key = key();
        let planner = Planner::new(mock.clone(), signing_key.clone());
        let prompt = prompt();
        let plan_id: PlanId = "P-retry".parse().unwrap();

        let signed = planner
            .plan(&prompt, &catalog(), &stores(), plan_id.clone())
            .unwrap();
        let verified = signed.verify(&signing_key, Purpose::Plan).unwrap();
        assert_eq!(verified.plan, plan_id);

        let seen = mock.seen();
        assert_eq!(seen.len(), 2);
        assert!(!seen[0].user.contains("PREVIOUS ATTEMPT FAILED"));
        assert!(seen[1].user.contains("PREVIOUS ATTEMPT FAILED"));
        assert!(
            seen[1]
                .user
                .contains("every destination argument of a tier 1+ tool needs from or forbid")
        );
        assert!(!seen[1].user.contains("\"auto_max_tier\""));
        assert!(!seen[1].user.contains("may_embed"));
    }

    #[test]
    fn two_invalid_drafts_return_no_plan() {
        let mut first_bad = valid_demo_draft();
        first_bad["reads"] = json!(["hidden"]);
        let mut second_bad = valid_demo_draft();
        second_bad["steps"][1]["args"]["to"] = json!({"from": ["step.1"]});

        let mock = Arc::new(MockAdapter::new(vec![Ok(first_bad), Ok(second_bad)]));
        let planner = Planner::new(mock.clone(), key());
        let err = planner
            .plan(&prompt(), &catalog(), &stores(), "P-fail".parse().unwrap())
            .unwrap_err();
        let PlanError::NoPlan(msg) = err else {
            panic!("expected NoPlan, got {err:?}");
        };
        assert!(msg.contains("a step source needs min_trust"), "{msg}");
        assert_eq!(mock.seen().len(), 2);
    }

    #[test]
    fn unknown_fields_in_draft_are_rejected() {
        let mut extra = valid_demo_draft();
        extra["secret_override"] = json!("poison-value-not-echoed");
        let mock = Arc::new(MockAdapter::new(vec![Ok(extra.clone()), Ok(extra)]));
        let planner = Planner::new(mock.clone(), key());
        let err = planner
            .plan(&prompt(), &catalog(), &stores(), "P-extra".parse().unwrap())
            .unwrap_err();
        let PlanError::NoPlan(msg) = err else {
            panic!("expected NoPlan, got {err:?}");
        };
        assert!(!msg.contains("poison-value-not-echoed"));
        assert!(!mock.seen()[1].user.contains("poison-value-not-echoed"));
    }

    #[test]
    fn extra_limits_each_reject() {
        // 1. More than MAX_STEPS (8) steps.
        let mut too_many_steps = valid_demo_draft();
        let steps: Vec<Value> = (1..=9)
            .map(|id| {
                json!({
                    "id": id,
                    "tool": "web.open",
                    "args": {"url": {"from": ["prompt"]}},
                    "budget": 1
                })
            })
            .collect();
        too_many_steps["steps"] = Value::Array(steps);

        // 2. Budget above MAX_BUDGET_PER_STEP (10).
        let mut budget_too_high = valid_demo_draft();
        budget_too_high["steps"][0]["budget"] = json!(11);

        // 3. auto_max_tier above 1 (2 is valid in Plan::validate, rejected by Planner).
        let mut tier_too_high = valid_demo_draft();
        tier_too_high["amendments"]["auto_max_tier"] = json!(2);

        // 4. Unknown store path in `from`.
        let mut unknown_store_key = valid_demo_draft();
        unknown_store_key["steps"][1]["args"]["to"] = json!({"from": ["store.contacts.attacker"]});

        // 5. Unknown store name in `may_embed`.
        let mut unknown_store_embed = valid_demo_draft();
        unknown_store_embed["steps"][1]["args"]["body"]["may_embed"] =
            json!({"from": ["store.other.boss"]});

        for (label, bad) in [
            ("steps", too_many_steps),
            ("budget", budget_too_high),
            ("auto_max_tier", tier_too_high),
            ("unknown_store_key", unknown_store_key),
            ("unknown_store_embed", unknown_store_embed),
        ] {
            let mock = Arc::new(MockAdapter::new(vec![Ok(bad.clone()), Ok(bad)]));
            let planner = Planner::new(mock, key());
            let res = planner.plan(&prompt(), &catalog(), &stores(), "P-limit".parse().unwrap());
            assert!(
                matches!(res, Err(PlanError::NoPlan(_))),
                "limit {label} should have rejected: {res:?}"
            );
        }
    }

    #[test]
    fn model_never_receives_store_values_or_prompt_metadata() {
        let mock = Arc::new(MockAdapter::new(vec![Ok(valid_demo_draft())]));
        let planner = Planner::new(mock.clone(), key());
        let prompt = prompt();
        let _ = planner
            .plan(&prompt, &catalog(), &stores(), "P-demo".parse().unwrap())
            .unwrap();
        let seen = mock.seen();
        assert_eq!(seen.len(), 1);
        let user = &seen[0].user;
        assert!(user.contains(&prompt.text));
        assert!(user.contains("web.open (tier 1)"));
        assert!(user.contains("email.send (tier 3)"));
        assert!(user.contains("contacts: boss"));
        assert!(!user.contains("boss@corp.example"));
        assert!(!user.contains("vault://mail/demo"));
        assert!(!user.contains(&prompt.nonce));
        assert!(!user.contains(prompt.session.as_str()));
        assert!(!user.contains("private-notes.txt"));
    }

    #[test]
    #[ignore]
    fn live_meta_planner() {
        if std::env::var("MUNIX_LIVE_META").as_deref() != Ok("1") {
            return;
        }
        let adapter = from_spec_for("meta:muse-spark-1.3", Role::Planner).unwrap();
        let signing_key = key();
        let planner = Planner::new(adapter, signing_key.clone());
        let catalog = catalog();
        let signed = planner
            .plan(&prompt(), &catalog, &stores(), "P-live".parse().unwrap())
            .unwrap();
        let verified = signed.verify(&signing_key, Purpose::Plan).unwrap();
        verified.validate(&catalog).unwrap();
        eprintln!(
            "live plan: {}",
            serde_json::to_string_pretty(verified).unwrap()
        );
    }
}
