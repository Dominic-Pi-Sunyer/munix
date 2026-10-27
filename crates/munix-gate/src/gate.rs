//! The Gate itself: tasks, the request pipeline and signed decisions (design spec 6, "Execution loop").
//!
//! One `Gate` serves every task on this host. It is plain synchronous code; the runtime wraps it in a mutex.

use std::collections::{BTreeMap, BTreeSet};

use munix_core::context::{Band, ContextState};
use munix_core::crypto::{self, Digest, Purpose, Signed, SigningKey};
use munix_core::decision::{Decision, Stage, Verdict};
use munix_core::ids::{RefId, TaskId, ToolName, find_embedded};
use munix_core::label::{Author, Capacity, Confidential, Label, RegionType, Source, Trust};
use munix_core::manifest::{ArgRole, Catalog, ToolManifest};
use munix_core::plan::{Plan, SourcePath};
use munix_core::prompt::PromptEnvelope;
use munix_core::request::{Request, Violation};
use munix_core::validate::{Scalar, is_email, is_url, is_valid};
use munix_ledger::Ledger;
use serde::Serialize;
use serde_json::{Value, json};

use crate::facts::Origin;
use crate::ingest::{Delivered, ingest};
use crate::policy::{DenyCode, Facts, Outcome, Ruling, evaluate};
use crate::refs::RefTable;
use crate::tool::{Tool, ToolFailure};
use crate::trace::trace_arg;
use crate::vault::{Credential, Vault};

/// Why the Gate refused to set something up. Returned to the runtime and the Supervisor, never to the agent.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("tool is not in the catalog")]
    UnknownTool,
    #[error("manifest digest does not match the pinned digest")]
    ManifestMismatch,
    #[error("tool is already registered")]
    AlreadyRegistered,
    #[error("bad signature")]
    BadSignature,
    #[error("plan does not belong to this prompt")]
    PlanMismatch,
    #[error("plan is invalid: {0}")]
    InvalidPlan(String),
    #[error("a plan step uses a tool with no registered implementation")]
    ToolNotRegistered,
    #[error("the plan's tool needs a credential the vault does not hold")]
    MissingCredential,
    #[error("task already exists")]
    TaskExists,
    #[error("store value is not valid for its type")]
    BadStoreValue,
    #[error("ledger: {0}")]
    Ledger(#[from] munix_ledger::LedgerError),
}

/// One operator-held value the plan may name as `store.<name>.<key>`, such as the user's contacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreValue {
    pub value: String,
    pub scalar: Scalar,
    pub confidential: Confidential,
}

/// Operator stores: `name -> key -> value`.
pub type Store = BTreeMap<String, BTreeMap<String, StoreValue>>;

/// A ref the agent may use from the start, with a description safe to show it (operator-chosen names only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BriefRef {
    pub id: RefId,
    /// Such as `store contacts.boss` or `url 1 in the prompt`.
    pub what: String,
}

/// What the agent is told when its task starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskBrief {
    pub task: TaskId,
    pub plan: Plan,
    pub refs: Vec<BriefRef>,
}

/// The Gate's answer to a request or a decision.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// The tool ran; this is what the agent gets.
    Delivered(Delivered),
    /// The request does not fit the manifest. Coarse codes only.
    Malformed(Vec<Violation>),
    /// Stage 1 (or a reviewer) denied it. Not a takeover signal.
    Denied(DenyCode),
    /// Waiting for a signed decision: from the Supervisor's review (`Stage::LlmReview`) or the user
    /// (`Stage::User`).
    Pending { request_hash: Digest, needs: Stage },
    /// A takeover signal. The task is halted until recovery; every later request gets `Halted`.
    Takeover(DenyCode),
    /// The task is halted or paused, or does not exist.
    Halted,
    /// The tool failed.
    Failed(ToolFailure),
}

/// A parked request as the Console shows it to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingView {
    pub tool: ToolName,
    pub step: u32,
    pub needs: Stage,
    pub band: Band,
    pub args: Vec<PendingArg>,
}

/// One argument of a parked request: the value as it will be sent, and where each part of it came from, such as
/// `store contacts.boss (trust 100)` or `step 1 reviews (ugc_review, trust 15)`. Raw values the Gate can't trace
/// say `untraced`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingArg {
    pub name: String,
    pub value: String,
    pub sources: Vec<String>,
}

pub struct Gate {
    key: SigningKey,
    catalog: Catalog,
    tools: BTreeMap<ToolName, Box<dyn Tool>>,
    vault: Vault,
    ledger: Ledger,
    tasks: BTreeMap<TaskId, Task>,
    /// Opaque numbers for web hosts, stable for the life of the Gate. The Supervisor only ever sees numbers.
    domains: BTreeMap<String, u32>,
}

enum Status {
    Running,
    /// Three denials on one step: the user is asked.
    Paused,
    /// A takeover signal: recovery starts a fresh agent.
    Halted,
}

struct Pending {
    request: Request,
    needs: Stage,
    band: Band,
    /// Stage 1's reasons, for the Supervisor's view. Fixed strings built from manifest names only.
    reasons: Vec<String>,
}

/// State bound to one Worker instance. A fresh Worker instance (recovery, rotation) replaces the whole
/// `Instance`, and only [`ContextState::fresh`] starts one (invariant 4).
struct Instance {
    context: ContextState,
    /// The lowest-trust field delivered to this agent instance, as (step, field, label), for the Supervisor's view.
    lowest: Option<(u32, String, Label)>,
}

struct Task {
    plan: Plan,
    brief_refs: Vec<BriefRef>,
    instance: Instance,
    refs: RefTable,
    status: Status,
    /// Executed calls per step.
    calls: BTreeMap<u32, u32>,
    /// Denials per step (any code, including malformed requests).
    denials: BTreeMap<u32, u32>,
    pending: BTreeMap<Digest, Pending>,
    /// Delivered items across the task, for quarantine attribution.
    items: Vec<crate::quarantine::Item>,
    /// Digests of quarantined items. Only grows.
    quarantine: BTreeSet<Digest>,
    /// Everything withheld so far in this task, oldest first.
    quarantined_notes: Vec<QuarantineNote>,
    /// Values blocked by the latest takeover (cleared on a watchdog trip or recovery).
    blocked: Vec<String>,
    /// Recoveries already performed on this task.
    recoveries: u32,
}

/// Denials on one step before the task pauses (design spec 7.4).
pub const MAX_DENIALS_PER_STEP: u32 = 3;

/// Recoveries per task before it pauses and the user is asked (design spec 6, "Recovery").
pub const MAX_RECOVERIES: u32 = 2;

/// Items below this trust are withheld when a takeover or a stall traces to nothing.
pub const FALLBACK_QUARANTINE_BELOW: u8 = 50;

/// Why the watchdog ended an agent instance (design spec 3, "Watchdog"). A trip is treated like a takeover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TripReason {
    /// No tool or model call for too long.
    Liveness,
    /// The task ran past its deadline.
    Deadline,
    /// Too many model calls or tokens since the last completed step.
    SpinBudget,
}

/// One withheld item, as recorded in the ledger and reported to the user: where it was and why, never its text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuarantineNote {
    pub step: u32,
    pub field: String,
    pub index: Option<usize>,
    pub region: RegionType,
    pub trust: Trust,
    pub cause: crate::quarantine::Cause,
    pub hash: Digest,
}

/// What a recovery did. The runtime starts a fresh agent with `brief`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    /// 1 for the first recovery of the task.
    pub attempt: u32,
    /// The items newly withheld by this recovery.
    pub quarantined: Vec<QuarantineNote>,
    pub brief: TaskBrief,
}

/// Why a task can't be recovered.
#[derive(Debug, thiserror::Error)]
pub enum RecoverError {
    #[error("no such task")]
    UnknownTask,
    #[error("the task is not halted")]
    NotHalted,
    #[error("the task has used its recoveries; the user must decide")]
    LimitReached,
    #[error("ledger: {0}")]
    Ledger(#[from] munix_ledger::LedgerError),
}

/// What the ruling and denial paths need to know about the request in hand.
struct Case<'a> {
    request: &'a Request,
    hash: &'a Digest,
    band: Band,
}

impl Gate {
    pub fn new(key: SigningKey, catalog: Catalog, vault: Vault, ledger: Ledger) -> Gate {
        Gate {
            key,
            catalog,
            tools: BTreeMap::new(),
            vault,
            ledger,
            tasks: BTreeMap::new(),
            domains: BTreeMap::new(),
        }
    }

    /// Registers the implementation of a catalog tool. The operator pins each manifest by digest; a manifest
    /// that changed since it was pinned is refused. Writes `tool_registered`.
    pub fn register(
        &mut self,
        tool: ToolName,
        pinned: Digest,
        imp: Box<dyn Tool>,
    ) -> Result<(), GateError> {
        let manifest = self.catalog.get(&tool).ok_or(GateError::UnknownTool)?;
        if self.tools.contains_key(&tool) {
            return Err(GateError::AlreadyRegistered);
        }
        let actual = manifest.digest().map_err(|_| GateError::ManifestMismatch)?;
        if actual != pinned {
            return Err(GateError::ManifestMismatch);
        }
        self.ledger.append(json!({
            "event": "tool_registered",
            "tool": tool.as_str(),
            "manifest_digest": actual.as_str(),
        }))?;
        self.tools.insert(tool, imp);
        Ok(())
    }

    /// Starts a task from a signed prompt and a signed plan.
    ///
    /// Checks: the prompt verifies for `Purpose::Prompt` and passes `PromptEnvelope::validate`; the plan verifies
    /// for `Purpose::Plan`, names the prompt's task, has `prompt_hash` equal to the prompt's digest and passes
    /// `Plan::validate`; every step's tool is registered and its credential (if any) is in the vault; the task id
    /// is new. Any failure writes nothing and starts nothing.
    ///
    /// Then it issues refs, in this order: every url and email in the prompt text (whitespace-separated tokens
    /// with surrounding `()[]<>"',.;:!?` trimmed that pass core's `is_url` / `is_email`), with origin
    /// `Origin::Prompt`; then every store value the plan names in a `from` or `may_embed` path, with origin
    /// `Origin::Store`. Labels: source `prompt` or `store`, region `user_content`, author `user`, trust 100,
    /// confidential `internal` for the prompt and the value's own for the store, capacity `free_text`.
    /// The context starts with `ContextState::fresh()`. Writes `task_started` with the task, plan id, plan digest
    /// and prompt digest.
    pub fn start_task(
        &mut self,
        prompt: &Signed<PromptEnvelope>,
        plan: &Signed<Plan>,
        store: &Store,
    ) -> Result<TaskBrief, GateError> {
        let envelope = prompt
            .verify(&self.key, Purpose::Prompt)
            .map_err(|_| GateError::BadSignature)?;
        // A signed prompt that breaks its own rules is a bug upstream; there is no better variant for it.
        envelope
            .validate()
            .map_err(|e| GateError::InvalidPlan(format!("prompt: {e}")))?;
        let body = plan
            .verify(&self.key, Purpose::Plan)
            .map_err(|_| GateError::BadSignature)?;
        let prompt_digest = envelope
            .digest()
            .map_err(|e| GateError::InvalidPlan(format!("prompt: {e}")))?;
        if body.task != envelope.task || body.prompt_hash != prompt_digest {
            return Err(GateError::PlanMismatch);
        }
        body.validate(&self.catalog)
            .map_err(|e| GateError::InvalidPlan(e.to_string()))?;
        let plan_digest = body
            .digest()
            .map_err(|e| GateError::InvalidPlan(e.to_string()))?;
        for step in &body.steps {
            if !self.tools.contains_key(&step.tool) {
                return Err(GateError::ToolNotRegistered);
            }
            let manifest = self
                .catalog
                .get(&step.tool)
                .ok_or(GateError::ToolNotRegistered)?;
            if let Some(at) = &manifest.credentials
                && !self.vault.contains(at)
            {
                return Err(GateError::MissingCredential);
            }
        }
        if self.tasks.contains_key(&envelope.task) {
            return Err(GateError::TaskExists);
        }

        let mut refs = RefTable::new();
        let mut brief_refs: Vec<BriefRef> = Vec::new();
        let mut seen: BTreeSet<RefId> = BTreeSet::new();
        let (mut urls, mut emails) = (0u32, 0u32);
        for (value, scalar) in prompt_values(&envelope.text) {
            let label = user_label(Source::Prompt, Confidential::Internal);
            let id = refs.issue(&value, scalar, Origin::Prompt, label);
            if seen.insert(id.clone()) {
                let what = if scalar == Scalar::Url {
                    urls += 1;
                    format!("url {urls} in the prompt")
                } else {
                    emails += 1;
                    format!("email {emails} in the prompt")
                };
                brief_refs.push(BriefRef { id, what });
            }
        }
        for (name, key) in named_store_values(body, store) {
            let Some(entry) = store.get(&name).and_then(|keys| keys.get(&key)) else {
                continue;
            };
            if !is_valid(entry.scalar, &entry.value) {
                return Err(GateError::BadStoreValue);
            }
            let label = user_label(Source::Store, entry.confidential);
            let origin = Origin::Store {
                name: name.clone(),
                key: key.clone(),
            };
            let id = refs.issue(&entry.value, entry.scalar, origin, label);
            if seen.insert(id.clone()) {
                brief_refs.push(BriefRef {
                    id,
                    what: format!("store {name}.{key}"),
                });
            }
        }

        self.ledger.append(json!({
            "event": "task_started",
            "task": envelope.task.as_str(),
            "plan": body.plan.as_str(),
            "plan_digest": plan_digest.as_str(),
            "prompt_digest": prompt_digest.as_str(),
        }))?;
        let brief = TaskBrief {
            task: envelope.task.clone(),
            plan: body.clone(),
            refs: brief_refs.clone(),
        };
        self.tasks.insert(
            envelope.task.clone(),
            Task {
                plan: body.clone(),
                brief_refs,
                instance: Instance {
                    context: ContextState::fresh(),
                    lowest: None,
                },
                refs,
                status: Status::Running,
                calls: BTreeMap::new(),
                denials: BTreeMap::new(),
                pending: BTreeMap::new(),
                items: Vec::new(),
                quarantine: BTreeSet::new(),
                quarantined_notes: Vec::new(),
                blocked: Vec::new(),
                recoveries: 0,
            },
        );
        Ok(brief)
    }

    /// Runs one request through the pipeline (design spec 6, steps 1-8):
    ///
    /// 1. Unknown task, or a task not `Running`: `Halted`. The request's plan id must be the task's (else
    ///    `Takeover(OffPlan)`).
    /// 2. `check_shape` against the tool's manifest (a tool not in the catalog is `Takeover(OffPlan)`):
    ///    violations give `Malformed`, counted as a denial on the step.
    /// 3. Trace every argument (`trace::trace_arg`, with the vault's credentials for the DLP check), then
    ///    `policy::evaluate` with the task's band and the step's executed-call count.
    /// 4. `Allow`: execute. `Gray`: park the request and reply `Pending { needs: LlmReview }`. `ConfirmUser`:
    ///    park it and reply `Pending { needs: User }`. A takeover code: halt the task and reply `Takeover`.
    ///    Any other deny: `Denied`, counted.
    /// 5. After `MAX_DENIALS_PER_STEP` denials on one step the task is `Paused` and the reply is still the
    ///    denial.
    ///
    /// Execution: resolve refs (whole values and refs embedded in text) to their values, fetch the manifest's
    /// credential from the vault, call the tool, count the call, then `ingest::ingest` the output with source
    /// `web` (the host of the tool's url destination argument, numbered through `domains`) for a tool with a url
    /// destination and `tool` otherwise, and lower the context to `min_trust`. An ingest error is
    /// `Failed(Internal)`.
    ///
    /// Ledger: `request` (task, step, tool, request hash) before anything else; `ruling` (outcome, reasons,
    /// band); `executed` (ok or the failure code, withheld fields, min trust) or `takeover` / `paused`;
    /// `context_lowered` (from, to) when it drops. Argument values are never written, only hashes and ref ids.
    /// If a ledger write fails, nothing executes and the reply is `Failed(Internal)` (fail closed).
    pub fn submit(&mut self, request: &Request) -> Reply {
        let Ok(hash) = crypto::digest(request) else {
            return Reply::Failed(ToolFailure::Internal);
        };
        if !self.log(request_event("request", request, &hash, json!({}))) {
            return Reply::Failed(ToolFailure::Internal);
        }
        let state = self.tasks.get(&request.task).map(|t| {
            (
                matches!(t.status, Status::Running),
                t.plan.plan == request.plan,
                t.instance.context.band(),
            )
        });
        let Some((true, plan_ok, band)) = state else {
            let _ = self.log(request_event(
                "ruling",
                request,
                &hash,
                json!({"outcome": "halted", "reasons": ["task.not_running"]}),
            ));
            return Reply::Halted;
        };
        let case = Case {
            request,
            hash: &hash,
            band,
        };
        if !plan_ok {
            return self.finish_deny(
                &case,
                DenyCode::OffPlan,
                &["plan.id_mismatch".to_owned()],
                true,
            );
        }
        let Some(manifest) = self.catalog.get(&request.tool).cloned() else {
            return self.finish_deny(
                &case,
                DenyCode::OffPlan,
                &["plan.unknown_tool".to_owned()],
                true,
            );
        };
        if let Err(violations) = request.check_shape(&manifest) {
            return self.finish_malformed(&case, violations);
        }
        let Some(ruling) = self
            .tasks
            .get(&request.task)
            .map(|task| self.rule(task, &manifest, request))
        else {
            return Reply::Halted;
        };
        match ruling.outcome {
            Outcome::Allow => {
                if !self.log_ruling(&case, "allow", None, &ruling.reasons) {
                    return Reply::Failed(ToolFailure::Internal);
                }
                self.execute(&case)
            }
            Outcome::Gray => self.park(&case, &ruling, Stage::LlmReview, "gray"),
            Outcome::ConfirmUser => self.park(&case, &ruling, Stage::User, "confirm_user"),
            Outcome::Deny(code) => self.finish_deny(&case, code, &ruling.reasons, true),
        }
    }

    /// Applies a signed decision to a parked request.
    ///
    /// The decision must verify for `Purpose::Decision` when its stage is `llm_review` and for
    /// `Purpose::UserConfirmation` when it is `user` (a `deterministic` decision is refused: only the Gate makes
    /// those). Its task, plan, `request_hash` and `band` must match a parked request of a `Running` task whose
    /// band has not changed since (a stale decision is refused), and its stage must be the one the request
    /// needs, except that a user decision may answer a request parked for review. Refused decisions return
    /// `Halted` and change nothing.
    ///
    /// `approve` executes the parked request as in `submit`. `deny` and `require_amendment` reply
    /// `Denied(Reviewer)`, counted. `confirm_user` from a review re-parks it as `Pending { needs: User }`.
    /// Writes `decision` (stage, verdict, reasons) first.
    pub fn decide(&mut self, decision: &Signed<Decision>) -> Reply {
        let body = &decision.body;
        let purpose = match body.stage {
            Stage::LlmReview => Purpose::Decision,
            Stage::User => Purpose::UserConfirmation,
            Stage::Deterministic => return self.refuse_decision(body, "stage"),
        };
        if decision.verify(&self.key, purpose).is_err() {
            return self.refuse_decision(body, "signature");
        }
        let (request, needs) = match self.check_decision(body) {
            Ok(found) => found,
            Err(why) => return self.refuse_decision(body, why),
        };
        let logged = self.log(json!({
            "event": "decision",
            "task": body.task.as_str(),
            "plan": body.plan.as_str(),
            "request_hash": body.request_hash.as_str(),
            "band": body.band,
            "stage": body.stage,
            "verdict": body.verdict,
            "reasons": body.reasons,
        }));
        if !logged {
            return Reply::Failed(ToolFailure::Internal);
        }
        let hash = body.request_hash.clone();
        let case = Case {
            request: &request,
            hash: &hash,
            band: body.band,
        };
        match body.verdict {
            Verdict::Approve => {
                self.remove_pending(&request.task, &hash);
                // The code rules again: an approval never overrides a deterministic deny, and the budget may have
                // been used up by another request since this one was parked.
                let Some(manifest) = self.catalog.get(&request.tool).cloned() else {
                    return Reply::Failed(ToolFailure::Internal);
                };
                let Some(ruling) = self
                    .tasks
                    .get(&request.task)
                    .map(|task| self.rule(task, &manifest, &request))
                else {
                    return Reply::Halted;
                };
                if let Outcome::Deny(code) = ruling.outcome {
                    return self.finish_deny(&case, code, &ruling.reasons, true);
                }
                self.execute(&case)
            }
            Verdict::Deny | Verdict::RequireAmendment => {
                self.remove_pending(&request.task, &hash);
                let code = match body.stage {
                    Stage::User => DenyCode::UserDenied,
                    _ => DenyCode::Reviewer,
                };
                self.finish_deny(&case, code, &["decision.not_approved".to_owned()], false)
            }
            Verdict::ConfirmUser => {
                if needs != Stage::LlmReview {
                    return Reply::Halted;
                }
                if let Some(parked) = self
                    .tasks
                    .get_mut(&request.task)
                    .and_then(|task| task.pending.get_mut(&hash))
                {
                    parked.needs = Stage::User;
                }
                Reply::Pending {
                    request_hash: hash,
                    needs: Stage::User,
                }
            }
        }
    }

    /// Halts a running task because the watchdog tripped: refuses further requests, clears parked ones and writes
    /// `watchdog_trip` (reason). Nothing traces from a trip, so the next recovery uses the low-trust fallback.
    /// Returns `Reply::Halted`; an unknown or already halted task is also `Halted` and changes nothing.
    pub fn trip(&mut self, task: &TaskId, reason: TripReason) -> Reply {
        let Some(t) = self.tasks.get_mut(task) else {
            return Reply::Halted;
        };
        if !matches!(t.status, Status::Running) {
            return Reply::Halted;
        }
        t.status = Status::Halted;
        t.pending.clear();
        t.blocked.clear();
        let _ = self.log(json!({
            "event": "watchdog_trip",
            "task": task.as_str(),
            "reason": reason,
        }));
        Reply::Halted
    }

    /// Halts a running task for a takeover the MCP front saw before any request could be built (a tool name that
    /// isn't a valid tool name). Writes `takeover` with the code and no request. A task that is not running is left
    /// as it is. Nothing traces, so the next recovery uses the low-trust fallback.
    pub fn halt_for_takeover(&mut self, task: &TaskId, code: DenyCode) {
        let running = self
            .tasks
            .get(task)
            .is_some_and(|t| matches!(t.status, Status::Running));
        if !running {
            return;
        }
        let _ = self.log(json!({
            "event": "takeover",
            "task": task.as_str(),
            "code": code,
            "request": null,
        }));
        if let Some(t) = self.tasks.get_mut(task) {
            t.status = Status::Halted;
            t.pending.clear();
            t.blocked.clear();
        }
    }

    /// Starts a fresh agent instance on the same signed plan after a takeover or a watchdog trip.
    ///
    /// - **When:** only for a `Halted` task (else `NotHalted`), at most `MAX_RECOVERIES` times. The next attempt
    ///   pauses the task (`Status::Paused`, writes `paused`) and returns `LimitReached`.
    /// - **Quarantine:** `quarantine::choose` over every item delivered so far in the task, with the values the
    ///   takeover blocked and `FALLBACK_QUARANTINE_BELOW`. The chosen items' digests join the task's quarantine set,
    ///   and every later tool output is passed through `quarantine::filter` before it is labeled. The set only
    ///   grows, and outlives the instance.
    /// - **The values the takeover blocked:** recorded when the takeover happened. They are the real values (refs
    ///   resolved) of the destination arguments that failed their trace, plus the raw link and address tokens of
    ///   content arguments. A watchdog trip records none.
    /// - **Fresh instance:** a new `Instance` (context `ContextState::fresh()`, no lowest read), no parked requests,
    ///   denial counts reset, status `Running`. Call counts and the ref table carry over.
    /// - **Ledger:** writes `recovered` (attempt, the quarantine notes) before returning; if that write fails,
    ///   nothing changes and the error is returned.
    pub fn recover(&mut self, task: &TaskId) -> Result<Recovery, RecoverError> {
        let t = self.tasks.get(task).ok_or(RecoverError::UnknownTask)?;
        if !matches!(t.status, Status::Halted) {
            return Err(RecoverError::NotHalted);
        }
        if t.recoveries >= MAX_RECOVERIES {
            let recoveries = t.recoveries;
            self.ledger.append(json!({
                "event": "paused",
                "task": task.as_str(),
                "recoveries": recoveries,
            }))?;
            if let Some(t) = self.tasks.get_mut(task) {
                t.status = Status::Paused;
            }
            return Err(RecoverError::LimitReached);
        }

        let unquarantined: Vec<crate::quarantine::Item> = t
            .items
            .iter()
            .filter(|item| !t.quarantine.contains(&item.hash))
            .cloned()
            .collect();
        let chosen = crate::quarantine::choose(
            &unquarantined,
            &t.blocked,
            Trust::new(FALLBACK_QUARANTINE_BELOW),
        );
        let mut seen = t.quarantine.clone();
        let mut quarantined = Vec::new();
        for (idx, cause) in chosen {
            if let Some(item) = unquarantined.get(idx)
                && seen.insert(item.hash.clone())
            {
                quarantined.push(QuarantineNote {
                    step: item.step,
                    field: item.field.clone(),
                    index: item.index,
                    region: item.region,
                    trust: item.trust,
                    cause,
                    hash: item.hash.clone(),
                });
            }
        }
        let attempt = t.recoveries.saturating_add(1);
        self.ledger.append(json!({
            "event": "recovered",
            "task": task.as_str(),
            "attempt": attempt,
            "quarantined": quarantined,
        }))?;

        let t = self.tasks.get_mut(task).ok_or(RecoverError::UnknownTask)?;
        t.recoveries = attempt;
        t.quarantine = seen;
        t.quarantined_notes.extend(quarantined.clone());
        t.blocked.clear();
        t.instance = Instance {
            context: ContextState::fresh(),
            lowest: None,
        };
        t.pending.clear();
        t.denials.clear();
        t.status = Status::Running;
        let brief = TaskBrief {
            task: task.clone(),
            plan: t.plan.clone(),
            refs: t.brief_refs.clone(),
        };
        Ok(Recovery {
            attempt,
            quarantined,
            brief,
        })
    }

    /// Everything withheld so far in a task, oldest first (for the final report).
    pub fn quarantined(&self, task: &TaskId) -> Vec<QuarantineNote> {
        self.tasks
            .get(task)
            .map(|t| t.quarantined_notes.clone())
            .unwrap_or_default()
    }

    /// The context trust of a task's current agent instance.
    pub fn context_trust(&self, task: &TaskId) -> Option<Trust> {
        self.tasks.get(task).map(|t| t.instance.context.trust())
    }

    /// The opaque numbers of the hosts seen so far.
    pub fn known_domains(&self) -> BTreeSet<u32> {
        self.domains.values().copied().collect()
    }

    /// Calls already executed on one step of a task.
    pub fn calls_made(&self, task: &TaskId, step: u32) -> Option<u32> {
        self.tasks
            .get(task)
            .map(|t| t.calls.get(&step).copied().unwrap_or(0))
    }

    /// The catalog this Gate enforces.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// The plan a task runs under.
    pub fn plan(&self, task: &TaskId) -> Option<&Plan> {
        self.tasks.get(task).map(|t| &t.plan)
    }

    /// What the Supervisor's model sees about a parked request: see [`crate::view::ReviewView`]. `None` when the task
    /// or the request isn't parked.
    pub fn review_view(
        &self,
        task: &TaskId,
        request_hash: &Digest,
    ) -> Option<crate::view::ReviewView> {
        let t = self.tasks.get(task)?;
        let parked = t.pending.get(request_hash)?;
        let manifest = self.catalog.get(&parked.request.tool)?;
        let step = t.plan.steps.iter().find(|s| s.id == parked.request.step)?;
        let credentials: Vec<&Credential> = t
            .plan
            .steps
            .iter()
            .filter_map(|s| self.catalog.get(&s.tool))
            .filter_map(|m| m.credentials.as_ref())
            .filter_map(|at| self.vault.get(at))
            .collect();
        let args = parked
            .request
            .args
            .iter()
            .filter_map(|(name, value)| {
                let spec = manifest.args.get(name)?;
                Some(review_arg(name, spec, value, &t.refs, &credentials))
            })
            .collect();
        // The lowest-trust field delivered to this agent instance (text fields never become refs, so the ref table
        // alone can't say).
        let lowest_read =
            t.instance
                .lowest
                .as_ref()
                .map(|(step, field, label)| crate::view::SourceView::Step {
                    step: *step,
                    field: field.clone(),
                    region: label.region,
                    domain: match label.source {
                        Source::Web { domain } => Some(domain),
                        _ => None,
                    },
                    trust: label.trust,
                });
        Some(crate::view::ReviewView {
            tool: parked.request.tool.clone(),
            tier: manifest.tier,
            step: parked.request.step,
            steps_in_plan: t.plan.steps.len(),
            calls_made: t.calls.get(&parked.request.step).copied().unwrap_or(0),
            budget: step.budget,
            context_trust: t.instance.context.trust(),
            band: parked.band,
            lowest_read,
            args,
            checks: parked.reasons.clone(),
        })
    }

    /// What the user sees to confirm a parked request at the Console: the tool, and each argument as it will be
    /// sent, with where its values came from. Real values: this goes to the user's own screen, never to a model.
    pub fn describe_pending(&self, task: &TaskId, request_hash: &Digest) -> Option<PendingView> {
        let t = self.tasks.get(task)?;
        let parked = t.pending.get(request_hash)?;
        let manifest = self.catalog.get(&parked.request.tool)?;
        let resolved = resolve_args(manifest, &parked.request.args, &t.refs)?;
        let args = resolved
            .iter()
            .map(|(name, value)| {
                let raw = &parked.request.args[name];
                PendingArg {
                    name: name.clone(),
                    value: match value {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    },
                    sources: describe_sources(raw, &t.refs),
                }
            })
            .collect();
        Some(PendingView {
            tool: parked.request.tool.clone(),
            step: parked.request.step,
            needs: parked.needs,
            band: parked.band,
            args,
        })
    }

    // ---- private helpers ----

    /// Appends one event. False means the write failed and the caller must fail closed.
    fn log(&mut self, event: Value) -> bool {
        self.ledger.append(event).is_ok()
    }

    fn log_ruling(
        &mut self,
        case: &Case<'_>,
        outcome: &str,
        code: Option<DenyCode>,
        reasons: &[String],
    ) -> bool {
        self.log(request_event(
            "ruling",
            case.request,
            case.hash,
            json!({"outcome": outcome, "code": code, "reasons": reasons, "band": case.band}),
        ))
    }

    /// Stage 1 on one request that already passed the shape check: trace every argument, then evaluate.
    fn rule(&self, task: &Task, manifest: &ToolManifest, request: &Request) -> Ruling {
        // Every credential the vault holds for the tools in this task's plan, for the DLP check.
        let credentials: Vec<&Credential> = task
            .plan
            .steps
            .iter()
            .filter_map(|step| self.catalog.get(&step.tool))
            .filter_map(|m| m.credentials.as_ref())
            .filter_map(|at| self.vault.get(at))
            .collect();
        let mut args = BTreeMap::new();
        for (name, value) in &request.args {
            if let Some(spec) = manifest.args.get(name) {
                args.insert(
                    name.clone(),
                    trace_arg(spec, value, &task.refs, &credentials),
                );
            }
        }
        evaluate(&Facts {
            plan: &task.plan,
            step: request.step,
            tool: &request.tool,
            manifest,
            calls_so_far: task.calls.get(&request.step).copied().unwrap_or(0),
            band: task.instance.context.band(),
            args: &args,
        })
    }

    /// Parks a request until a signed decision arrives.
    fn park(&mut self, case: &Case<'_>, ruling: &Ruling, needs: Stage, outcome: &str) -> Reply {
        if !self.log_ruling(case, outcome, None, &ruling.reasons) {
            return Reply::Failed(ToolFailure::Internal);
        }
        let Some(task) = self.tasks.get_mut(&case.request.task) else {
            return Reply::Halted;
        };
        task.pending.insert(
            case.hash.clone(),
            Pending {
                request: case.request.clone(),
                needs,
                band: case.band,
                reasons: ruling.reasons.clone(),
            },
        );
        Reply::Pending {
            request_hash: case.hash.clone(),
            needs,
        }
    }

    fn remove_pending(&mut self, task: &TaskId, hash: &Digest) {
        if let Some(task) = self.tasks.get_mut(task) {
            task.pending.remove(hash);
        }
    }

    /// A deny. With `takeover_allowed`, a takeover code halts the task instead of counting as a denial.
    fn finish_deny(
        &mut self,
        case: &Case<'_>,
        code: DenyCode,
        reasons: &[String],
        takeover_allowed: bool,
    ) -> Reply {
        // A deny stands whether or not the ledger write works.
        let _ = self.log_ruling(case, "deny", Some(code), reasons);
        if takeover_allowed && code.is_takeover() {
            let blocked = self.blocked_values(case.request);
            if let Some(task) = self.tasks.get_mut(&case.request.task) {
                task.status = Status::Halted;
                task.pending.clear();
                task.blocked = blocked;
            }
            let _ = self.log(request_event(
                "takeover",
                case.request,
                case.hash,
                json!({"code": code}),
            ));
            return Reply::Takeover(code);
        }
        self.count_denial(&case.request.task, case.request.step);
        Reply::Denied(code)
    }

    /// Extracts the values blocked by a takeover request: the real values (refs resolved) of destination
    /// arguments whose trace failed the step's rule, plus untraced raw destination tokens and embedded values in
    /// content arguments that failed `may_embed`.
    fn blocked_values(&self, request: &Request) -> Vec<String> {
        let Some(manifest) = self.catalog.get(&request.tool) else {
            return Vec::new();
        };
        let Some(task) = self.tasks.get(&request.task) else {
            return Vec::new();
        };
        let Some(step) = task
            .plan
            .steps
            .iter()
            .find(|s| s.id == request.step && s.tool == request.tool)
        else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (name, value) in &request.args {
            let Some(spec) = manifest.args.get(name) else {
                continue;
            };
            if !spec.ty.scalar.is_string_shaped() {
                continue;
            }
            match spec.role {
                ArgRole::Destination => {
                    let rule = step.args.get(name);
                    let from = rule.and_then(|r| r.from.as_deref());
                    let min_trust = rule.and_then(|r| r.min_trust);
                    let facts = trace_arg(spec, value, &task.refs, &[]);
                    for (raw, traced) in value_strings(value).into_iter().zip(facts.values.iter()) {
                        let ok = match from {
                            Some(from) => traced.satisfies(from, min_trust),
                            None => manifest.tier == 0,
                        };
                        if !ok && let Some(real) = resolve_text(raw, false, &task.refs) {
                            out.push(real);
                        }
                    }
                }
                ArgRole::Content if spec.ty.scalar != Scalar::Ref => {
                    let embed = step.args.get(name).and_then(|r| r.may_embed.as_ref());
                    for text in value_strings(value) {
                        for token in crate::trace::raw_destination_tokens(text) {
                            if task.refs.find_value(&token).is_empty() {
                                out.push(token);
                            }
                        }
                        let facts =
                            trace_arg(spec, &Value::String(text.to_owned()), &task.refs, &[]);
                        for traced in &facts.embedded {
                            let allowed = traced.matches.iter().any(|m| m.origin.is_clean_side())
                                || embed.is_some_and(|e| traced.satisfies(&e.from, e.min_trust));
                            if !allowed {
                                for m in &traced.matches {
                                    if let Some(id) = &m.id
                                        && let Some(entry) = task.refs.get(id)
                                    {
                                        out.push(entry.value.clone());
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    fn finish_malformed(&mut self, case: &Case<'_>, violations: Vec<Violation>) -> Reply {
        // Codes only: an argument name in a violation can be chosen by the agent.
        let codes: Vec<Value> = violations.iter().map(|v| json!(v.code)).collect();
        let _ = self.log(request_event(
            "ruling",
            case.request,
            case.hash,
            json!({"outcome": "malformed", "violations": codes, "band": case.band}),
        ));
        self.count_denial(&case.request.task, case.request.step);
        Reply::Malformed(violations)
    }

    /// Counts a denial on a step and pauses the task at the limit.
    fn count_denial(&mut self, task_id: &TaskId, step: u32) {
        let Some(task) = self.tasks.get_mut(task_id) else {
            return;
        };
        let count = task.denials.entry(step).or_insert(0);
        *count = count.saturating_add(1);
        let count = *count;
        let pause = count >= MAX_DENIALS_PER_STEP && matches!(task.status, Status::Running);
        if pause {
            task.status = Status::Paused;
        }
        if pause {
            let _ = self.log(json!({
                "event": "paused",
                "task": task_id.as_str(),
                "step": step,
                "denials": count,
            }));
        }
    }

    /// Checks a verified decision against the parked request. Returns the request and what it was parked for.
    fn check_decision(&self, body: &Decision) -> Result<(Request, Stage), &'static str> {
        let task = self.tasks.get(&body.task).ok_or("no_task")?;
        if !matches!(task.status, Status::Running) {
            return Err("not_running");
        }
        if task.plan.plan != body.plan {
            return Err("plan");
        }
        let parked = task.pending.get(&body.request_hash).ok_or("no_pending")?;
        if body.band != parked.band || task.instance.context.band() != parked.band {
            return Err("stale_band");
        }
        let stage_ok = body.stage == parked.needs
            || (body.stage == Stage::User && parked.needs == Stage::LlmReview);
        if !stage_ok {
            return Err("stage");
        }
        if body.stage == Stage::User && body.verdict == Verdict::ConfirmUser {
            return Err("verdict");
        }
        Ok((parked.request.clone(), parked.needs))
    }

    fn refuse_decision(&mut self, body: &Decision, why: &str) -> Reply {
        // Only identifiers and the coarse reason: the body is not trusted when its signature failed.
        let _ = self.log(json!({
            "event": "decision_refused",
            "task": body.task.as_str(),
            "request_hash": body.request_hash.as_str(),
            "reason": why,
        }));
        Reply::Halted
    }

    /// Executes a request the code or a signed decision has cleared.
    fn execute(&mut self, case: &Case<'_>) -> Reply {
        let request = case.request;
        let Some(manifest) = self.catalog.get(&request.tool).cloned() else {
            return self.fail_before_call(case);
        };
        let resolved = match self.tasks.get(&request.task) {
            Some(task) => resolve_args(&manifest, &request.args, &task.refs),
            None => return Reply::Halted,
        };
        let Some(resolved) = resolved else {
            return self.fail_before_call(case);
        };

        let result = {
            let credential = match &manifest.credentials {
                Some(at) => match self.vault.get(at) {
                    Some(found) => Some(found),
                    None => return self.fail_before_call(case),
                },
                None => None,
            };
            match self.tools.get(&request.tool) {
                Some(tool) => tool.call(&resolved, credential),
                None => return self.fail_before_call(case),
            }
        };
        if let Some(task) = self.tasks.get_mut(&request.task) {
            let calls = task.calls.entry(request.step).or_insert(0);
            *calls = calls.saturating_add(1);
        }

        let output = match result {
            Ok(output) => output,
            Err(failure) => {
                let _ = self.log(request_event(
                    "executed",
                    request,
                    case.hash,
                    json!({"ok": false, "ran": true, "failure": failure}),
                ));
                return Reply::Failed(failure);
            }
        };

        let (raw_output, removed) = match self.tasks.get(&request.task) {
            Some(task) => crate::quarantine::filter(output, &task.quarantine),
            None => return Reply::Halted,
        };
        let quarantined = removed.len();

        let source = if has_url_destination(&manifest) {
            let host = url_destination_host(&manifest, &resolved);
            Source::Web {
                domain: domain_number(&mut self.domains, host),
            }
        } else {
            Source::Tool {
                tool: request.tool.clone(),
            }
        };
        let ingested = match self.tasks.get_mut(&request.task) {
            Some(task) => ingest(
                &manifest,
                request.step,
                &source,
                &task.plan.reads,
                raw_output.clone(),
                &mut task.refs,
            ),
            None => return Reply::Halted,
        };
        let delivered = match ingested {
            Ok(delivered) => delivered,
            Err(_) => {
                let _ = self.log(request_event(
                    "executed",
                    request,
                    case.hash,
                    json!({"ok": false, "ran": true, "failure": ToolFailure::Internal}),
                ));
                return Reply::Failed(ToolFailure::Internal);
            }
        };

        // Trust drops whether or not the ledger write below works.
        if let Some(task) = self.tasks.get_mut(&request.task) {
            task.items.extend(crate::quarantine::items_of(
                request.step,
                &raw_output,
                &delivered.labels,
            ));
            for (field, label) in &delivered.labels {
                if task
                    .instance
                    .lowest
                    .as_ref()
                    .is_none_or(|(_, _, low)| label.trust < low.trust)
                {
                    task.instance.lowest = Some((request.step, field.clone(), label.clone()));
                }
            }
        }
        let lowered = match (self.tasks.get_mut(&request.task), delivered.min_trust) {
            (Some(task), Some(min)) => {
                let from = task.instance.context.trust();
                task.instance
                    .context
                    .lower_to(min)
                    .then(|| (from, task.instance.context.trust()))
            }
            _ => None,
        };
        let mut logged = self.log(request_event(
            "executed",
            request,
            case.hash,
            json!({
                "ok": true,
                "ran": true,
                "withheld": delivered.withheld,
                "quarantined": quarantined,
                "min_trust": delivered.min_trust.map(Trust::value),
            }),
        ));
        if let Some((from, to)) = lowered {
            logged &= self.log(request_event(
                "context_lowered",
                request,
                case.hash,
                json!({"from": from.value(), "to": to.value()}),
            ));
        }
        if !logged {
            // Nothing the ledger did not record reaches the agent.
            return Reply::Failed(ToolFailure::Internal);
        }
        Reply::Delivered(delivered)
    }

    /// The call never happened: record it and fail.
    fn fail_before_call(&mut self, case: &Case<'_>) -> Reply {
        let _ = self.log(request_event(
            "executed",
            case.request,
            case.hash,
            json!({"ok": false, "ran": false, "failure": ToolFailure::Internal}),
        ));
        Reply::Failed(ToolFailure::Internal)
    }
}

/// A ledger event about one request: the name, the request's ids and hash, plus `extra` fields.
fn request_event(name: &str, request: &Request, hash: &Digest, extra: Value) -> Value {
    let mut event = json!({
        "event": name,
        "task": request.task.as_str(),
        "step": request.step,
        "tool": request.tool.as_str(),
        "request_hash": hash.as_str(),
    });
    if let (Some(fields), Value::Object(more)) = (event.as_object_mut(), extra) {
        fields.extend(more);
    }
    event
}

fn user_label(source: Source, confidential: Confidential) -> Label {
    Label {
        source,
        region: RegionType::UserContent,
        author: Author::User,
        trust: Trust::FULL,
        confidential,
        capacity: Capacity::FreeText,
    }
}

/// Urls and emails in the prompt text, in order of appearance.
fn prompt_values(text: &str) -> Vec<(String, Scalar)> {
    text.split_whitespace()
        .filter_map(|token| {
            let token = token.trim_matches(|c| "()[]<>\"',.;:!?".contains(c));
            if is_url(token) {
                Some((token.to_owned(), Scalar::Url))
            } else if is_email(token) {
                Some((token.to_owned(), Scalar::Email))
            } else {
                None
            }
        })
        .collect()
}

/// The `(store name, key)` pairs the plan names in a `from` or `may_embed` path, in a stable order. A path
/// without a key names every key the store has under that name.
fn named_store_values(plan: &Plan, store: &Store) -> BTreeSet<(String, String)> {
    let mut named = BTreeSet::new();
    let paths = plan
        .steps
        .iter()
        .flat_map(|step| step.args.values())
        .flat_map(|rule| {
            rule.from
                .iter()
                .flatten()
                .chain(rule.may_embed.iter().flat_map(|e| e.from.iter()))
        });
    for path in paths {
        let SourcePath::Store { name, key } = path else {
            continue;
        };
        let Some(keys) = store.get(name) else {
            continue;
        };
        match key {
            Some(key) => {
                if keys.contains_key(key) {
                    named.insert((name.clone(), key.clone()));
                }
            }
            None => named.extend(keys.keys().map(|key| (name.clone(), key.clone()))),
        }
    }
    named
}

/// Swaps refs for their values in the arguments the tracer examined. Destinations and selectors take whole-value
/// refs only (that is all the tracer checks); content text also takes refs embedded in it. Control arguments are
/// never examined, so they are passed through untouched. `None` means a ref could not be resolved.
/// Where the values of one argument came from, for the Console.
fn describe_sources(value: &Value, refs: &RefTable) -> Vec<String> {
    let mut out = Vec::new();
    let mut strings = Vec::new();
    match value {
        Value::String(s) => strings.push(s.as_str()),
        Value::Array(items) => strings.extend(items.iter().filter_map(Value::as_str)),
        _ => {}
    }
    for s in strings {
        let mut found = false;
        let ids: Vec<RefId> = match s.parse::<RefId>() {
            Ok(id) => vec![id],
            Err(_) => find_embedded(s).into_iter().map(|(_, _, id)| id).collect(),
        };
        for id in ids {
            if let Some(entry) = refs.get(&id) {
                out.push(describe_entry(entry));
                found = true;
            }
        }
        if !found && s.parse::<RefId>().is_err() {
            let matches = refs.find_value(s);
            if matches.is_empty() {
                if find_embedded(s).is_empty() && !s.is_empty() && !s.contains(char::is_whitespace)
                {
                    out.push("untraced".to_owned());
                }
            } else {
                out.extend(matches.into_iter().map(|(_, entry)| describe_entry(entry)));
            }
        }
    }
    out.dedup();
    out
}

fn describe_entry(entry: &crate::refs::RefEntry) -> String {
    let trust = entry.label.trust.value();
    match &entry.origin {
        Origin::Prompt => format!("the prompt (trust {trust})"),
        Origin::UserData => format!("the user's data (trust {trust})"),
        Origin::Store { name, key } => format!("store {name}.{key} (trust {trust})"),
        Origin::Step { step, field } => {
            let region = serde_json::to_value(entry.label.region)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default();
            format!("step {step} {field} ({region}, trust {trust})")
        }
    }
}

fn resolve_args(
    manifest: &ToolManifest,
    args: &BTreeMap<String, Value>,
    refs: &RefTable,
) -> Option<BTreeMap<String, Value>> {
    let mut resolved = BTreeMap::new();
    for (name, value) in args {
        let spec = manifest.args.get(name)?;
        let value = if spec.role == ArgRole::Control || !spec.ty.scalar.is_string_shaped() {
            value.clone()
        } else {
            resolve_value(value, spec.role == ArgRole::Content, refs)?
        };
        resolved.insert(name.clone(), value);
    }
    Some(resolved)
}

fn resolve_value(value: &Value, embedded: bool, refs: &RefTable) -> Option<Value> {
    match value {
        Value::String(text) => resolve_text(text, embedded, refs).map(Value::String),
        Value::Array(items) => items
            .iter()
            .map(|item| resolve_value(item, embedded, refs))
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        other => Some(other.clone()),
    }
}

fn resolve_text(text: &str, embedded: bool, refs: &RefTable) -> Option<String> {
    if !embedded {
        return match text.parse::<RefId>() {
            Ok(id) => Some(refs.get(&id)?.value.clone()),
            Err(_) => Some(text.to_owned()),
        };
    }
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (start, end, id) in find_embedded(text) {
        out.push_str(text.get(last..start)?);
        out.push_str(&refs.get(&id)?.value);
        last = end;
    }
    out.push_str(text.get(last..)?);
    Some(out)
}

fn url_destinations(manifest: &ToolManifest) -> impl Iterator<Item = &String> {
    manifest
        .args
        .iter()
        .filter(|(_, spec)| spec.role == ArgRole::Destination && spec.ty.scalar == Scalar::Url)
        .map(|(name, _)| name)
}

fn has_url_destination(manifest: &ToolManifest) -> bool {
    url_destinations(manifest).next().is_some()
}

/// The lowercased host of the first url destination value in the resolved arguments (empty when there is none).
fn url_destination_host(manifest: &ToolManifest, resolved: &BTreeMap<String, Value>) -> String {
    let url = url_destinations(manifest)
        .filter_map(|name| resolved.get(name))
        .find_map(|value| match value {
            Value::String(s) => Some(s.as_str()),
            Value::Array(items) => items.iter().find_map(Value::as_str),
            _ => None,
        })
        .unwrap_or("");
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let end = rest.find(['/', '?', '#', ':']).unwrap_or(rest.len());
    rest.get(..end).unwrap_or("").to_lowercase()
}

/// The opaque number of a host: numbers start at 1 and never change.
fn domain_number(domains: &mut BTreeMap<String, u32>, host: String) -> u32 {
    if let Some(n) = domains.get(&host) {
        return *n;
    }
    let n = u32::try_from(domains.len())
        .unwrap_or(u32::MAX)
        .saturating_add(1);
    domains.insert(host, n);
    n
}

fn entry_source_view(entry: &crate::refs::RefEntry) -> crate::view::SourceView {
    let trust = entry.label.trust;
    match &entry.origin {
        Origin::Prompt => crate::view::SourceView::Prompt { trust },
        Origin::UserData => crate::view::SourceView::UserData { trust },
        Origin::Store { name, key } => crate::view::SourceView::Store {
            name: name.clone(),
            key: key.clone(),
            trust,
        },
        Origin::Step { step, field } => crate::view::SourceView::Step {
            step: *step,
            field: field.clone(),
            region: entry.label.region,
            domain: match entry.label.source {
                Source::Web { domain } => Some(domain),
                _ => None,
            },
            trust,
        },
    }
}

fn untraced_value_view() -> crate::view::ValueView {
    crate::view::ValueView {
        ref_id: None,
        ty: None,
        sources: vec![crate::view::SourceView::Untraced],
    }
}

fn traced_value_view(traced: &crate::facts::Traced, refs: &RefTable) -> crate::view::ValueView {
    let mut sources = Vec::with_capacity(traced.matches.len());
    let mut first: Option<(RefId, String)> = None;
    for m in &traced.matches {
        let Some(id) = &m.id else {
            continue;
        };
        let Some(entry) = refs.get(id) else {
            continue;
        };
        if first.is_none() {
            first = Some((id.clone(), entry.scalar.name().to_owned()));
        }
        sources.push(entry_source_view(entry));
    }
    match first {
        Some((ref_id, ty)) => crate::view::ValueView {
            ref_id: Some(ref_id),
            ty: Some(ty),
            sources,
        },
        None => untraced_value_view(),
    }
}

fn value_strings(value: &Value) -> Vec<&str> {
    match value {
        Value::String(s) => vec![s.as_str()],
        Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn review_arg(
    name: &str,
    spec: &munix_core::manifest::ArgSpec,
    value: &Value,
    refs: &RefTable,
    credentials: &[&Credential],
) -> crate::view::ArgView {
    let ty = spec.ty.to_string();
    let role = spec.role;
    let control = role == ArgRole::Control || !spec.ty.scalar.is_string_shaped();
    if control {
        return crate::view::ArgView {
            name: name.to_owned(),
            ty,
            role,
            values: Vec::new(),
            chars: None,
            embeds: Vec::new(),
            raw_destinations: 0,
            confidential: Confidential::Public,
            control: true,
        };
    }
    let facts = trace_arg(spec, value, refs, credentials);
    match role {
        ArgRole::Destination | ArgRole::Selector => {
            let confidential = facts
                .values
                .iter()
                .flat_map(|t| &t.matches)
                .map(|m| m.confidential)
                .max()
                .unwrap_or(Confidential::Public);
            let values = facts
                .values
                .iter()
                .map(|t| traced_value_view(t, refs))
                .collect();
            crate::view::ArgView {
                name: name.to_owned(),
                ty,
                role,
                values,
                chars: None,
                embeds: Vec::new(),
                raw_destinations: 0,
                confidential,
                control: false,
            }
        }
        ArgRole::Content => {
            let chars = (spec.ty.scalar != Scalar::Ref)
                .then(|| value_strings(value).iter().map(|s| s.chars().count()).sum());
            let embeds = facts
                .embedded
                .iter()
                .map(|t| traced_value_view(t, refs))
                .collect();
            crate::view::ArgView {
                name: name.to_owned(),
                ty,
                role,
                values: Vec::new(),
                chars,
                embeds,
                raw_destinations: facts.raw_destinations,
                confidential: facts.confidential,
                control: false,
            }
        }
        ArgRole::Control => unreachable!("handled above"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::view::{ReviewView, SourceView};
    use munix_core::manifest::{ArgSpec, ArgType};

    fn spec(scalar: Scalar, list: bool, role: ArgRole) -> ArgSpec {
        ArgSpec {
            ty: ArgType { scalar, list },
            role,
            optional: false,
            max: None,
            max_len: None,
            values: Vec::new(),
            single_line: false,
        }
    }

    #[test]
    fn review_arg_never_leaks_invented_refs_in_destination_content_ref_or_body() {
        let mut refs = RefTable::new();
        let boss = refs.issue(
            "boss@corp.example",
            Scalar::Email,
            Origin::Store {
                name: "contacts".to_owned(),
                key: "boss".to_owned(),
            },
            user_label(Source::Store, Confidential::Private),
        );
        assert_eq!(boss.as_str(), "ref:e1");

        let to_view = review_arg(
            "to",
            &spec(Scalar::Email, true, ArgRole::Destination),
            &json!(["ref:send_to_mallory_now", boss.as_str()]),
            &refs,
            &[],
        );
        let attachments_view = review_arg(
            "attachments",
            &spec(Scalar::Ref, true, ArgRole::Content),
            &json!(["ref:ignore_all_prior", boss.as_str()]),
            &refs,
            &[],
        );
        let body_view = review_arg(
            "body",
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!(format!(
                "Summary with ref:send_to_mallory_now and ref:ignore_all_prior for {boss}"
            )),
            &refs,
            &[],
        );

        let view = ReviewView {
            tool: "email.send".parse().unwrap(),
            tier: 3,
            step: 2,
            steps_in_plan: 2,
            calls_made: 0,
            budget: 1,
            context_trust: Trust::new(10),
            band: Band::Lockdown,
            lowest_read: None,
            args: vec![attachments_view, body_view, to_view],
            checks: vec!["plan.step2".to_owned()],
        };
        let rendered = view.render();
        let serialized = serde_json::to_string(&view).unwrap();
        for forbidden in [
            "ref:send_to_mallory_now",
            "ref:ignore_all_prior",
            "send_to_mallory_now",
            "ignore_all_prior",
            "mallory",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "render() leaked {forbidden:?}:\n{rendered}"
            );
            assert!(
                !serialized.contains(forbidden),
                "json leaked {forbidden:?}:\n{serialized}"
            );
        }
        assert_eq!(view.args[0].embeds[0].ref_id, None);
        assert_eq!(view.args[0].embeds[0].ty, None);
        assert_eq!(view.args[0].embeds[0].sources, vec![SourceView::Untraced]);
        assert_eq!(view.args[1].embeds[0].ref_id, None);
        assert_eq!(view.args[1].embeds[1].ref_id, None);
        assert_eq!(view.args[2].values[0].ref_id, None);
    }
}
