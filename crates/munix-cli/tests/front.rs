#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The Gate's MCP front, driven directly through `McpHandler`: a real Gate with the real manifests and demo plan,
//! a real ledger file, fake tools and a scripted Console. No Docker, no network, no model.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use munix_adapters::{AdapterError, MockAdapter};
use munix_cli::confirm::Confirmer;
use munix_cli::front::{FrontProgress, GateFront};
use munix_core::context::Band;
use munix_core::crypto::{Purpose, Signed, SigningKey};
use munix_core::decision::Stage;
use munix_core::ids::TaskId;
use munix_core::label::Confidential;
use munix_core::manifest::{Catalog, ToolManifest};
use munix_core::plan::Plan;
use munix_core::prompt::PromptEnvelope;
use munix_core::validate::Scalar;
use munix_gate::gate::{Gate, PendingView, Store, StoreValue, TaskBrief};
use munix_gate::policy::DenyCode;
use munix_gate::tool::{Tool, ToolFailure};
use munix_gate::vault::{Credential, Vault};
use munix_ledger::Ledger;
use munix_runtime::mcp::{CallResult, McpHandler};
use munix_supervisor::reviewer::Reviewer;
use serde_json::{Value, json};

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
/// A tier 0 tool whose output is `editorial` (ceiling 75): reading it puts the context in the Elevated band.
const NEWS_READ: &str = "
tool: news.read
description: Read the headline of the day.
tier: 0
output:
  headline: {type: text, region: editorial, confidential: public}
";

const BOSS: &str = "boss@corp.example";
const PAGE_TEXT: &str = "PAGE-TEXT-MARKER the reviews are great";
const PROMPT_URL: &str = "https://pixelmart.test:8080/reviews";

type Args = BTreeMap<String, Value>;

fn tool<F>(f: F) -> Box<dyn Tool>
where
    F: Fn(&Args, Option<&Credential>) -> Result<Args, ToolFailure> + Send + Sync + 'static,
{
    Box::new(f)
}

fn args(pairs: &[(&str, Value)]) -> Args {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("munix-cli-test-{}-{n}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// What the Console was shown, and what the user will answer (`false` once the answers run out).
#[derive(Clone, Default)]
struct Script {
    shown: Arc<Mutex<Vec<PendingView>>>,
    answers: Arc<Mutex<VecDeque<bool>>>,
}

impl Script {
    fn answering(answers: &[bool]) -> Script {
        let script = Script::default();
        script
            .answers
            .lock()
            .unwrap()
            .extend(answers.iter().copied());
        script
    }

    fn shown(&self) -> Vec<PendingView> {
        self.shown.lock().unwrap().clone()
    }
}

impl Confirmer for Script {
    fn confirm(&mut self, view: &PendingView) -> bool {
        self.shown.lock().unwrap().push(view.clone());
        self.answers.lock().unwrap().pop_front().unwrap_or(false)
    }
}

struct Harness {
    gate: Gate,
    key: SigningKey,
    brief: TaskBrief,
    envelope: PromptEnvelope,
    dir: PathBuf,
    task: TaskId,
    /// Every argument map the fake email tool received.
    sent: Arc<Mutex<Vec<Args>>>,
    /// Every url the fake web tool was asked to open.
    opened: Arc<Mutex<Vec<String>>>,
    /// Makes the fake web tool fail with `Unavailable`.
    web_fails: Arc<AtomicBool>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[derive(Default)]
struct Options {
    /// Puts the `news.read` tool in the catalog and registers it.
    news: bool,
    /// Adds `news.read` as step 3 of the plan.
    news_step: bool,
    /// Lets the email carry a `cc` (the demo plan forbids it).
    allow_cc: bool,
    /// Adds a second `web.open` step (id 4, budget 2) after the first one.
    second_open: bool,
    /// Gives `news.read` this tier instead of 0 (the demo plan amends in tools up to tier 1 by itself).
    news_tier: Option<u8>,
}

fn harness() -> Harness {
    build(&Options::default())
}

fn build(options: &Options) -> Harness {
    let key = SigningKey::from_bytes(&[7u8; 32]).unwrap();
    let mut manifests = vec![
        ToolManifest::from_yaml(WEB_OPEN).unwrap(),
        ToolManifest::from_yaml(EMAIL_SEND).unwrap(),
    ];
    if options.news {
        let tier = options.news_tier.unwrap_or(0);
        let yaml = NEWS_READ.replace("tier: 0", &format!("tier: {tier}"));
        manifests.push(ToolManifest::from_yaml(&yaml).unwrap());
    }
    let digests: Vec<_> = manifests.iter().map(|m| m.digest().unwrap()).collect();
    let catalog = Catalog::from_manifests(manifests).unwrap();
    let dir = fresh_dir();
    let ledger = Ledger::create(dir.join("ledger.jsonl")).unwrap();
    let vault = Vault::new().with(
        "vault://mail/demo".parse().unwrap(),
        Credential::new("mail-credential-xyz-0042"),
    );
    let mut gate = Gate::new(key.clone(), catalog, vault, ledger);

    let sent = Arc::new(Mutex::new(Vec::new()));
    let opened = Arc::new(Mutex::new(Vec::new()));
    let log = opened.clone();
    let web_fails = Arc::new(AtomicBool::new(false));
    let fails = web_fails.clone();
    gate.register(
        "web.open".parse().unwrap(),
        digests[0].clone(),
        tool(move |a, _| {
            log.lock()
                .unwrap()
                .push(a["url"].as_str().unwrap().to_owned());
            if fails.load(Ordering::SeqCst) {
                return Err(ToolFailure::Unavailable);
            }
            Ok(args(&[
                ("page", json!(format!("{PAGE_TEXT} see ref:u1 for more"))),
                (
                    "links",
                    json!([
                        "https://pixelmart.test:8080/shop",
                        "https://evil.test/collect"
                    ]),
                ),
            ]))
        }),
    )
    .unwrap();
    let log = sent.clone();
    gate.register(
        "email.send".parse().unwrap(),
        digests[1].clone(),
        tool(move |a, _| {
            log.lock().unwrap().push(a.clone());
            Ok(args(&[("message_id", json!("msg-1"))]))
        }),
    )
    .unwrap();
    if options.news {
        gate.register(
            "news.read".parse().unwrap(),
            digests[2].clone(),
            tool(|_, _| Ok(args(&[("headline", json!("A quiet day"))]))),
        )
        .unwrap();
    }

    let task: TaskId = "T-demo".parse().unwrap();
    let envelope = PromptEnvelope {
        task: task.clone(),
        session: "S-1".parse().unwrap(),
        nonce: "0123456789abcdef".to_owned(),
        text: format!("Read the reviews at {PROMPT_URL} and email a short summary to my boss."),
        data: Vec::new(),
    };
    let mut text = DEMO_PLAN.replace(
        "reads: [operator_content, product_listing, editorial, ugc_review]",
        "reads: [operator_content, product_listing, editorial, ugc_review, unclassified]",
    );
    let mut extra = String::new();
    if options.news_step {
        extra.push_str("  - id: 3\n    tool: news.read\n    args: {}\n    budget: 5\n");
    }
    if options.second_open {
        extra.push_str("  - id: 4\n    tool: web.open\n    args:\n      url: {from: [prompt]}\n    budget: 2\n");
    }
    text = text.replace("amendments:", &format!("{extra}amendments:"));
    if options.allow_cc {
        let forbidding = "cc:          {forbid: true}";
        assert!(text.contains(forbidding), "demo plan changed");
        text = text.replace(forbidding, "cc:          {from: [store.contacts.boss]}");
    }
    let mut plan = Plan::from_yaml(&text).unwrap();
    plan.prompt_hash = envelope.digest().unwrap();
    let prompt = Signed::sign(&key, Purpose::Prompt, envelope.clone()).unwrap();
    let plan = Signed::sign(&key, Purpose::Plan, plan).unwrap();
    let store: Store = BTreeMap::from([(
        "contacts".to_owned(),
        BTreeMap::from([(
            "boss".to_owned(),
            StoreValue {
                value: BOSS.to_owned(),
                scalar: Scalar::Email,
                confidential: Confidential::Private,
            },
        )]),
    )]);
    let brief = gate.start_task(&prompt, &plan, &store).unwrap();
    Harness {
        gate,
        key,
        brief,
        envelope,
        dir,
        task,
        sent,
        opened,
        web_fails,
    }
}

impl Harness {
    fn front(&mut self, script: &Script) -> GateFront<'_, Script> {
        GateFront::new(
            &mut self.gate,
            &self.key,
            self.brief.clone(),
            script.clone(),
        )
    }

    fn front_with_reviewer(
        &mut self,
        script: &Script,
        mock: Arc<MockAdapter>,
    ) -> GateFront<'_, Script> {
        let reviewer = Reviewer::new(mock, self.key.clone());
        let envelope = self.envelope.clone();
        self.front(script).with_reviewer(reviewer, envelope)
    }

    fn ledger_path(&self) -> PathBuf {
        self.dir.join("ledger.jsonl")
    }

    fn ledger_len(&self) -> usize {
        munix_ledger::verify_file(self.ledger_path()).unwrap()
    }

    fn emails(&self) -> Vec<Args> {
        self.sent.lock().unwrap().clone()
    }
}

fn email(subject: &str) -> Value {
    json!({"to": ["ref:e2"], "subject": subject, "body": "The reviews are positive."})
}

/// The ref ids in a `links` block: its `- ref:uN` lines.
fn link_refs(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.strip_prefix("- "))
        .filter(|item| item.starts_with("ref:"))
        .map(str::to_owned)
        .collect()
}

fn refused(result: &CallResult, text: &str) {
    assert!(result.is_error, "{result:?}");
    assert_eq!(result.text, text);
}

// ---- tools() ----

#[test]
fn tools_follow_the_plan_and_the_manifests() {
    let mut h = harness();
    let script = Script::default();
    let front = h.front(&script);
    let tools = front.tools();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["web_open", "email_send"]);

    // cc and attachments are left out: the demo plan forbids them. The rest follows the manifest.
    assert_eq!(
        tools[1].input_schema,
        json!({
            "type": "object",
            "properties": {
                "body": {"type": "string"},
                "subject": {"type": "string"},
                "to": {"type": "array", "items": {"type": "string"}, "maxItems": 5},
            },
            "required": ["body", "subject", "to"],
            "additionalProperties": false,
        })
    );
    assert_eq!(
        tools[0].input_schema,
        json!({
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
            "additionalProperties": false,
        })
    );
}

#[test]
fn descriptions_come_from_the_manifests_and_list_the_briefs_refs() {
    let mut h = harness();
    let refs = h.brief.refs.clone();
    assert_eq!(refs.len(), 2, "the prompt's url and the boss");
    let script = Script::default();
    let tools = h.front(&script).tools();
    let email = ToolManifest::from_yaml(EMAIL_SEND).unwrap();
    let web = ToolManifest::from_yaml(WEB_OPEN).unwrap();
    assert!(tools[0].description.starts_with(&web.description));
    assert!(tools[1].description.starts_with(&email.description));
    for tool in &tools {
        for r in &refs {
            assert!(
                tool.description.contains(&format!("{}: {}", r.id, r.what)),
                "{}",
                tool.description
            );
        }
        assert!(
            tool.description
                .contains("as these refs, never as raw text")
        );
        // The description names refs, never the values behind them.
        assert!(!tool.description.contains(BOSS));
        assert!(!tool.description.contains("pixelmart"));
    }
    assert!(tools[0].description.contains("ref:e2: store contacts.boss"));
}

#[test]
fn an_argument_the_plan_does_not_forbid_is_offered_and_optional() {
    let mut h = build(&Options {
        allow_cc: true,
        ..Options::default()
    });
    let script = Script::default();
    let tools = h.front(&script).tools();
    let schema = &tools[1].input_schema;
    assert_eq!(
        schema["properties"]["cc"],
        json!({"type": "array", "items": {"type": "string"}, "maxItems": 5})
    );
    assert!(schema["properties"].get("attachments").is_none());
    assert_eq!(schema["required"], json!(["body", "subject", "to"]));
}

#[test]
fn a_tool_with_several_steps_is_listed_once() {
    let mut h = build(&Options {
        news: true,
        news_step: true,
        second_open: true,
        ..Options::default()
    });
    let script = Script::default();
    let names: Vec<String> = h
        .front(&script)
        .tools()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert_eq!(names, ["web_open", "email_send", "news_read"]);
}

// ---- call() ----

#[test]
fn web_open_with_the_prompts_url_delivers_labeled_blocks() {
    let mut h = harness();
    let url_ref = h.brief.refs[0].id.to_string();
    let script = Script::default();
    let mut front = h.front(&script);
    let result = front.call("web_open", &json!({"url": url_ref}));
    assert!(!result.is_error, "{result:?}");
    assert!(!front.should_stop());
    drop(front);

    // Fields in name order, each headed by its region and trust; the page is untrusted, so the trust is low.
    let links_at = result
        .text
        .find("## links [unclassified, trust 10]\n")
        .unwrap();
    let page_at = result
        .text
        .find("## page [unclassified, trust 10]\n")
        .unwrap();
    assert!(links_at < page_at, "{}", result.text);
    assert_eq!(link_refs(&result.text).len(), 2, "{}", result.text);
    assert!(result.text.contains(PAGE_TEXT));
    assert!(!result.text.contains("evil.test") && !result.text.contains("pixelmart.test"));
    assert!(!result.text.contains("Withheld"));
    assert_eq!(*h.opened.lock().unwrap(), [PROMPT_URL]);
    assert_eq!(h.gate.context_trust(&h.task).map(|t| t.value()), Some(10));
}

#[test]
fn an_email_to_the_boss_ref_at_clean_is_delivered() {
    let mut h = harness();
    let script = Script::default();
    let mut front = h.front(&script);
    let result = front.call("email_send", &email("Reviews"));
    assert!(!result.is_error, "{result:?}");
    assert!(
        result
            .text
            .contains("## message_id [operator_content, trust 85]\nmsg-1"),
        "{}",
        result.text
    );
    assert!(!front.should_stop());
    drop(front);
    assert!(script.shown().is_empty(), "no one was asked");
    let sent = h.emails();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["to"], json!([BOSS]));
}

#[test]
fn after_a_low_trust_read_the_user_sees_the_real_address_and_can_approve() {
    let mut h = harness();
    let url_ref = h.brief.refs[0].id.to_string();
    let script = Script::answering(&[true]);
    let mut front = h.front(&script);
    assert!(!front.call("web_open", &json!({"url": url_ref})).is_error);
    let result = front.call("email_send", &email("Reviews"));
    assert!(!result.is_error, "{result:?}");
    assert!(result.text.contains("msg-1"));
    assert!(!front.should_stop());
    drop(front);

    // The Console was asked once, with the real address, where it came from, and nothing else about the agent.
    let shown = script.shown();
    assert_eq!(shown.len(), 1);
    let view = &shown[0];
    assert_eq!(view.tool.as_str(), "email.send");
    assert_eq!(
        (view.step, view.needs, view.band),
        (2, Stage::User, Band::Lockdown)
    );
    let to = view.args.iter().find(|a| a.name == "to").unwrap();
    assert!(to.value.contains(BOSS));
    assert_eq!(to.sources, ["store contacts.boss (trust 100)"]);

    // The fake tool got the real address, and the approval is in the ledger as a user decision.
    let sent = h.emails();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["to"], json!([BOSS]));
    let ledger = std::fs::read_to_string(h.ledger_path()).unwrap();
    assert!(ledger.contains("\"decision\"") && ledger.contains("console.user"));
    assert!(!ledger.contains(BOSS), "the ledger never holds values");
}

#[test]
fn a_simulated_user_decision_is_marked_in_the_ledger() {
    use munix_cli::confirm::SimulatedUser;
    let mut h = harness();
    let url_ref = h.brief.refs[0].id.to_string();
    let mut front = GateFront::new(&mut h.gate, &h.key, h.brief.clone(), SimulatedUser);
    assert!(!front.call("web_open", &json!({"url": url_ref})).is_error);
    // The recipient traces to the store, so the simulated user approves.
    let result = front.call("email_send", &email("Reviews"));
    assert!(!result.is_error, "{result:?}");
    drop(front);
    assert_eq!(h.emails().len(), 1);
    let ledger = std::fs::read_to_string(h.ledger_path()).unwrap();
    assert!(ledger.contains("console.simulated_user"), "{ledger}");
    assert!(!ledger.contains("console.user"), "{ledger}");
}

#[test]
fn a_user_who_says_no_gets_user_denied_and_nothing_is_sent() {
    let mut h = harness();
    let url_ref = h.brief.refs[0].id.to_string();
    let script = Script::answering(&[false]);
    let mut front = h.front(&script);
    assert!(!front.call("web_open", &json!({"url": url_ref})).is_error);
    let result = front.call("email_send", &email("Reviews"));
    refused(&result, "denied: user_denied");
    // A denial is not a takeover: the session goes on.
    assert!(!front.should_stop());
    assert_eq!(front.takeover(), None);
    drop(front);
    assert_eq!(script.shown().len(), 1);
    assert!(h.emails().is_empty());
}

#[test]
fn an_unanswered_console_is_a_no() {
    let mut h = harness();
    let url_ref = h.brief.refs[0].id.to_string();
    let script = Script::default();
    let mut front = h.front(&script);
    assert!(!front.call("web_open", &json!({"url": url_ref})).is_error);
    refused(
        &front.call("email_send", &email("Reviews")),
        "denied: user_denied",
    );
    drop(front);
    assert!(h.emails().is_empty());
}

#[test]
fn a_review_request_with_no_reviewer_goes_to_the_user() {
    let mut h = build(&Options {
        news: true,
        news_step: true,
        ..Options::default()
    });
    let script = Script::answering(&[true]);
    let mut front = h.front(&script);
    assert!(!front.call("news_read", &json!({})).is_error);
    let result = front.call("email_send", &email("Reviews"));
    assert!(!result.is_error, "{result:?}");
    drop(front);
    let shown = script.shown();
    assert_eq!(shown.len(), 1);
    assert_eq!(
        (shown[0].needs, shown[0].band),
        (Stage::LlmReview, Band::Elevated)
    );
    assert_eq!(h.emails().len(), 1);
}

#[test]
fn reviewer_approve_at_elevated_delivers_without_asking_the_confirmer() {
    let mut h = build(&Options {
        news: true,
        news_step: true,
        ..Options::default()
    });
    let mock = Arc::new(MockAdapter::new(vec![Ok(json!({
        "verdict": "approve",
        "reason": "serves_prompt",
    }))]));
    let script = Script::default();
    let mut front = h.front_with_reviewer(&script, mock.clone());
    assert!(!front.call("news_read", &json!({})).is_error);
    let result = front.call("email_send", &email("Reviews"));
    assert!(!result.is_error, "{result:?}");
    assert!(result.text.contains("msg-1"), "{}", result.text);
    assert!(!front.should_stop());
    drop(front);

    assert!(script.shown().is_empty(), "the confirmer is never asked");
    let seen = mock.seen();
    assert_eq!(seen.len(), 1);
    // Invariant 3: the reviewer sees metadata and the user's prompt, never tool output or store values.
    assert!(!seen[0].user.contains(BOSS));
    assert!(!seen[0].user.contains("A quiet day"));
    assert!(!seen[0].user.contains("The reviews are positive."));
    let sent = h.emails();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["to"], json!([BOSS]));
}

#[test]
fn reviewer_deny_returns_denied_reviewer_without_asking_the_confirmer() {
    let mut h = build(&Options {
        news: true,
        news_step: true,
        ..Options::default()
    });
    let mock = Arc::new(MockAdapter::new(vec![Ok(json!({
        "verdict": "deny",
        "reason": "off_task",
    }))]));
    let script = Script::answering(&[true]);
    let mut front = h.front_with_reviewer(&script, mock.clone());
    assert!(!front.call("news_read", &json!({})).is_error);
    let result = front.call("email_send", &email("Reviews"));
    refused(&result, "denied: reviewer");
    assert!(!front.should_stop());
    drop(front);

    assert_eq!(mock.seen().len(), 1);
    assert!(script.shown().is_empty(), "the confirmer is never asked");
    assert!(h.emails().is_empty());
}

#[test]
fn reviewer_confirm_user_goes_to_the_confirmer() {
    let mut h = build(&Options {
        news: true,
        news_step: true,
        ..Options::default()
    });
    let mock = Arc::new(MockAdapter::new(vec![Ok(json!({
        "verdict": "confirm_user",
        "reason": "unclear",
    }))]));
    let script = Script::answering(&[true]);
    let mut front = h.front_with_reviewer(&script, mock.clone());
    assert!(!front.call("news_read", &json!({})).is_error);
    let result = front.call("email_send", &email("Reviews"));
    assert!(!result.is_error, "{result:?}");
    assert!(result.text.contains("msg-1"), "{}", result.text);
    drop(front);

    assert_eq!(mock.seen().len(), 1);
    let shown = script.shown();
    assert_eq!(shown.len(), 1);
    assert_eq!(
        (shown[0].needs, shown[0].band),
        (Stage::User, Band::Elevated)
    );
    assert_eq!(h.emails().len(), 1);
}

#[test]
fn a_mock_adapter_error_in_the_reviewer_goes_to_the_confirmer() {
    let mut h = build(&Options {
        news: true,
        news_step: true,
        ..Options::default()
    });
    let mock = Arc::new(MockAdapter::new(vec![Err(AdapterError::Timeout)]));
    let script = Script::answering(&[true]);
    let mut front = h.front_with_reviewer(&script, mock.clone());
    assert!(!front.call("news_read", &json!({})).is_error);
    let result = front.call("email_send", &email("Reviews"));
    assert!(!result.is_error, "{result:?}");
    assert!(result.text.contains("msg-1"), "{}", result.text);
    drop(front);

    assert_eq!(mock.seen().len(), 1);
    let shown = script.shown();
    assert_eq!(shown.len(), 1);
    assert_eq!(
        (shown[0].needs, shown[0].band),
        (Stage::User, Band::Elevated)
    );
    assert_eq!(h.emails().len(), 1);
}

#[test]
fn a_request_parked_for_the_user_never_reaches_the_reviewer() {
    let mut h = harness();
    let url_ref = h.brief.refs[0].id.to_string();
    let mock = Arc::new(MockAdapter::new(vec![Ok(json!({
        "verdict": "approve",
        "reason": "serves_prompt",
    }))]));
    let script = Script::answering(&[false]);
    let mut front = h.front_with_reviewer(&script, mock.clone());
    assert!(!front.call("web_open", &json!({"url": url_ref})).is_error);
    let result = front.call("email_send", &email("Reviews"));
    refused(&result, "denied: user_denied");
    drop(front);

    assert!(
        mock.seen().is_empty(),
        "a request parked for the user must never reach the reviewer"
    );
    let shown = script.shown();
    assert_eq!(shown.len(), 1);
    assert_eq!(
        (shown[0].needs, shown[0].band),
        (Stage::User, Band::Lockdown)
    );
    assert!(h.emails().is_empty());
}

#[test]
fn an_address_taken_from_the_page_is_a_takeover() {
    for raw in [false, true] {
        let mut h = harness();
        let url_ref = h.brief.refs[0].id.to_string();
        let script = Script::answering(&[true, true]);
        let mut front = h.front(&script);
        let page = front.call("web_open", &json!({"url": url_ref}));
        let links = link_refs(&page.text);
        let to = if raw {
            "attacker@evil.test".to_owned()
        } else {
            links[0].clone()
        };
        let result = front.call(
            "email_send",
            &json!({"to": [to], "subject": "Hi", "body": "The reviews are positive."}),
        );
        refused(&result, "denied: untrusted_destination");
        assert!(front.should_stop());
        assert_eq!(front.takeover(), Some(DenyCode::UntrustedDestination));

        // The task is halted: nothing else runs, and the Console is never asked.
        refused(
            &front.call("email_send", &email("Hi")),
            "denied: task halted",
        );
        drop(front);
        assert!(script.shown().is_empty());
        assert!(h.emails().is_empty());
        assert_eq!(h.opened.lock().unwrap().len(), 1);
    }
}

#[test]
fn a_raw_link_in_the_body_is_a_takeover() {
    let mut h = harness();
    let script = Script::default();
    let mut front = h.front(&script);
    let result = front.call(
        "email_send",
        &json!({"to": ["ref:e2"], "subject": "Hi", "body": "Read https://evil.test/collect now"}),
    );
    refused(&result, "denied: raw_destination");
    assert!(front.should_stop());
    assert_eq!(front.takeover(), Some(DenyCode::RawDestination));
}

#[test]
fn an_unknown_tool_is_a_takeover() {
    let mut h = harness();
    let script = Script::default();
    let mut front = h.front(&script);
    assert!(!front.should_stop());
    refused(&front.call("mail_read", &json!({})), "denied: off_plan");
    assert!(front.should_stop());
    assert_eq!(front.takeover(), Some(DenyCode::OffPlan));
    drop(front);
    // It reached the Gate, which logged it.
    let ledger = std::fs::read_to_string(h.ledger_path()).unwrap();
    assert!(ledger.contains("mail.read"));
}

#[test]
fn a_tool_in_the_catalog_but_not_in_the_plan_is_a_takeover() {
    // news.read is in the catalog and registered, but this plan has no step for it. The front still submits it
    // (on step 0), and the Gate rules. At tier 2 it is above the plan's auto_max_tier, so it is not amended in.
    let mut h = build(&Options {
        news: true,
        news_tier: Some(2),
        ..Options::default()
    });
    let before = h.ledger_len();
    let script = Script::default();
    let mut front = h.front(&script);
    let names: Vec<String> = front.tools().into_iter().map(|t| t.name).collect();
    assert_eq!(
        names,
        ["web_open", "email_send"],
        "the agent is not offered it"
    );
    refused(&front.call("news_read", &json!({})), "denied: off_plan");
    assert!(front.should_stop());
    assert_eq!(front.takeover(), Some(DenyCode::OffPlan));
    drop(front);
    assert!(h.ledger_len() > before);
}

#[test]
fn a_low_tier_tool_the_plan_lacks_is_amended_in_and_later_calls_use_its_step() {
    let mut h = build(&Options {
        news: true,
        ..Options::default()
    });
    let task = h.task.clone();
    let script = Script::default();
    let mut front = h.front(&script);
    let names: Vec<String> = front.tools().into_iter().map(|t| t.name).collect();
    assert_eq!(names, ["web_open", "email_send"]);

    // First call: the Gate amends step 3 in and the read runs.
    let first = front.call("news_read", &json!({}));
    assert!(!first.is_error, "{first:?}");
    assert!(first.text.contains("A quiet day"), "{first:?}");
    // No refs in this output, so no note about them.
    assert!(!first.text.contains("Munix refs"), "{first:?}");
    assert!(!front.should_stop());
    // Later calls map to the amended step. It is a read, so its budget is READ_AMENDMENT_BUDGET (8).
    for _ in 0..7 {
        let again = front.call("news_read", &json!({}));
        assert!(!again.is_error, "{again:?}");
    }
    refused(
        &front.call("news_read", &json!({})),
        "denied: budget_exhausted",
    );
    assert!(
        !front.should_stop(),
        "an exhausted budget is not a takeover"
    );
    // Still not advertised, and the brief's tool list is unchanged.
    let names: Vec<String> = front.tools().into_iter().map(|t| t.name).collect();
    assert_eq!(names, ["web_open", "email_send"]);
    drop(front);

    let plan = h.gate.plan(&task).unwrap();
    assert_eq!(plan.steps.len(), 3);
    assert_eq!(plan.steps[2].id, 3);
    assert_eq!(plan.steps[2].tool.as_str(), "news.read");
    assert_eq!(h.gate.calls_made(&task, 3), Some(8));
    // The brief the agent was given is untouched.
    assert_eq!(h.brief.plan.steps.len(), 2);
}

#[test]
fn a_name_that_cannot_be_a_tool_name_is_a_takeover() {
    for name in [
        "Web Open!",
        "",
        "web..open",
        "WEB_OPEN",
        "../etc/passwd",
        &"a".repeat(80),
    ] {
        let mut h = harness();
        let before = h.ledger_len();
        let script = Script::default();
        let mut front = h.front(&script);
        refused(&front.call(name, &json!({})), "denied: off_plan");
        assert!(front.should_stop(), "{name:?}");
        assert_eq!(front.takeover(), Some(DenyCode::OffPlan));
        drop(front);
        assert_eq!(
            h.ledger_len(),
            before,
            "there is no request to log for {name:?}"
        );
        assert!(h.opened.lock().unwrap().is_empty());
    }
}

#[test]
fn arguments_that_are_not_an_object_are_wrong_type() {
    let mut h = harness();
    let script = Script::default();
    let mut front = h.front(&script);
    for bad in [
        json!("ref:u1"),
        json!(["ref:u1"]),
        json!(5),
        json!(true),
        json!(1.5),
    ] {
        refused(&front.call("web_open", &bad), "denied: wrong_type");
        refused(&front.call("email_send", &bad), "denied: wrong_type");
    }
    assert!(!front.should_stop());
    drop(front);
    assert!(h.opened.lock().unwrap().is_empty());
    assert!(h.emails().is_empty());
}

#[test]
fn missing_arguments_count_as_an_empty_object() {
    let mut h = harness();
    let script = Script::default();
    let mut front = h.front(&script);
    refused(&front.call("web_open", &Value::Null), "denied: missing_arg");
    refused(&front.call("web_open", &json!({})), "denied: missing_arg");
    assert!(!front.should_stop());
}

#[test]
fn malformed_requests_list_their_violation_codes() {
    let mut h = harness();
    let script = Script::default();
    let mut front = h.front(&script);
    let result = front.call("web_open", &json!({"url": "ref:u1", "secret_arg": 1}));
    assert!(result.is_error);
    assert!(result.text.starts_with("denied: "), "{}", result.text);
    assert!(result.text.contains("unknown_arg"), "{}", result.text);
    // Codes only: the agent's own argument name is not echoed back.
    assert!(!result.text.contains("secret_arg"));
    let result = front.call("email_send", &json!({"to": ["ref:e2"]}));
    assert_eq!(result.text, "denied: missing_arg, missing_arg");
    assert!(!front.should_stop());
}

#[test]
fn a_failing_tool_is_reported_by_code() {
    let mut h = harness();
    h.web_fails.store(true, Ordering::SeqCst);
    let url_ref = h.brief.refs[0].id.to_string();
    let script = Script::default();
    let mut front = h.front(&script);
    refused(
        &front.call("web_open", &json!({"url": url_ref})),
        "tool failed: unavailable",
    );
    assert!(!front.should_stop());
}

#[test]
fn an_exhausted_budget_is_denied_by_code() {
    let mut h = harness();
    let url_ref = h.brief.refs[0].id.to_string();
    let script = Script::default();
    let mut front = h.front(&script);
    for _ in 0..3 {
        assert!(!front.call("web_open", &json!({"url": url_ref})).is_error);
    }
    refused(
        &front.call("web_open", &json!({"url": url_ref})),
        "denied: budget_exhausted",
    );
    assert!(!front.should_stop());
}

#[test]
fn the_step_is_the_first_with_budget_left_and_falls_back_to_the_last() {
    let mut h = build(&Options {
        second_open: true,
        ..Options::default()
    });
    let url_ref = h.brief.refs[0].id.to_string();
    let script = Script::default();
    let mut front = h.front(&script);
    // Step 1 has a budget of 3 and step 4 a budget of 2: five calls run, the sixth is over budget.
    for call in 0..5 {
        let result = front.call("web_open", &json!({"url": url_ref}));
        assert!(!result.is_error, "call {call}: {result:?}");
    }
    refused(
        &front.call("web_open", &json!({"url": url_ref})),
        "denied: budget_exhausted",
    );
    drop(front);
    assert_eq!(h.gate.calls_made(&h.task, 1), Some(3));
    assert_eq!(h.gate.calls_made(&h.task, 4), Some(2));
    assert_eq!(h.opened.lock().unwrap().len(), 5);
}

#[test]
fn the_email_budget_is_one() {
    let mut h = harness();
    let script = Script::default();
    let mut front = h.front(&script);
    assert!(!front.call("email_send", &email("First")).is_error);
    refused(
        &front.call("email_send", &email("Second")),
        "denied: budget_exhausted",
    );
    drop(front);
    assert_eq!(h.emails().len(), 1);
}

#[test]
fn front_progress_records_call_times_and_delivered_counts() {
    let mut h = harness();
    let url_ref = h.brief.refs[0].id.to_string();
    let script = Script::default();
    let progress = Arc::new(FrontProgress::new());
    let initial_time = progress.last_call();
    assert_eq!(progress.delivered(), 0);

    let mut front = h.front(&script).with_progress(Arc::clone(&progress));

    // A denied / malformed call updates the last call time, but does not bump the delivered count.
    std::thread::sleep(std::time::Duration::from_millis(2));
    refused(&front.call("web_open", &json!({})), "denied: missing_arg");
    let after_denied = progress.last_call();
    assert!(after_denied > initial_time);
    assert_eq!(progress.delivered(), 0);

    // A delivered call updates the last call time and bumps the delivered count.
    std::thread::sleep(std::time::Duration::from_millis(2));
    let ok_res = front.call("web_open", &json!({"url": url_ref}));
    assert!(!ok_res.is_error, "{ok_res:?}");
    let after_delivered = progress.last_call();
    assert!(after_delivered > after_denied);
    assert_eq!(progress.delivered(), 1);

    // A user-denied call after reading untrusted content updates the time, not the delivered count.
    std::thread::sleep(std::time::Duration::from_millis(2));
    refused(
        &front.call("email_send", &email("Summary")),
        "denied: user_denied",
    );
    assert!(progress.last_call() > after_delivered);
    assert_eq!(progress.delivered(), 1);
}

#[test]
fn a_blocked_call_prints_one_line_and_one_per_destination() {
    use munix_cli::front::blocked_lines;
    use munix_gate::gate::PendingArg;
    use munix_gate::policy::DenyCode;
    let args = vec![PendingArg {
        name: "to".to_owned(),
        value: "hacker@evil.test".to_owned(),
        sources: vec!["step 1 reviews (ugc_review, trust 15)".to_owned()],
        destination: None,
    }];
    let lines = blocked_lines(
        &"email.send".parse().unwrap(),
        &DenyCode::UntrustedDestination,
        true,
        &args,
    );
    assert_eq!(
        lines,
        [
            "munix: BLOCKED email.send (untrusted_destination): takeover, the task is halted",
            "munix:   to = hacker@evil.test  <- step 1 reviews (ugc_review, trust 15)",
        ]
    );
    let lines = blocked_lines(
        &"email.send".parse().unwrap(),
        &DenyCode::Reviewer,
        false,
        &[],
    );
    assert_eq!(lines, ["munix: BLOCKED email.send (reviewer): denied"]);
}

#[test]
fn a_blocked_value_with_escapes_and_newlines_prints_escaped_on_one_line() {
    use munix_cli::front::blocked_lines;
    use munix_gate::gate::PendingArg;
    use munix_gate::policy::DenyCode;
    let args = vec![PendingArg {
        name: "to".to_owned(),
        value: "a@b.test\u{1b}[2K\nmunix: ALLOWED".to_owned(),
        sources: vec!["step 1\u{1b}]0;x\u{7}\nfake".to_owned()],
        destination: None,
    }];
    let lines = blocked_lines(
        &"email.send".parse().unwrap(),
        &DenyCode::UntrustedDestination,
        false,
        &args,
    );
    assert_eq!(lines.len(), 2);
    for line in &lines {
        assert!(!line.chars().any(|c| c.is_control()), "{line:?}");
    }
    assert!(
        lines[1].contains("a@b.test\\u{1b}[2K\\u{a}munix: ALLOWED"),
        "{}",
        lines[1]
    );
    assert!(
        lines[1].contains("step 1\\u{1b}]0;x\\u{7}\\u{a}fake"),
        "{}",
        lines[1]
    );
}

#[test]
fn an_mcp_name_resolves_to_the_catalog_tool_it_stands_for() {
    use munix_cli::front::resolve_tool;
    use munix_core::manifest::{Catalog, ToolManifest};
    let manifest = |tool: &str| {
        ToolManifest::from_yaml(&format!(
            "tool: {tool}\ndescription: A read.\ntier: 0\noutput:\n  value: {{type: int, region: user_content, confidential: public}}\n"
        ))
        .unwrap()
    };
    let catalog = Catalog::from_manifests([
        manifest("banking.get_balance"),
        manifest("banking.get_iban"),
    ])
    .unwrap();
    let planned: Vec<munix_core::ids::ToolName> = vec!["banking.get_iban".parse().unwrap()];
    // A planned tool, and a catalog tool outside the plan, by their MCP names.
    assert_eq!(
        resolve_tool("banking_get_iban", planned.iter(), &catalog)
            .unwrap()
            .as_str(),
        "banking.get_iban"
    );
    assert_eq!(
        resolve_tool("banking_get_balance", planned.iter(), &catalog)
            .unwrap()
            .as_str(),
        "banking.get_balance"
    );
    // Not in the catalog: the dotted guess, which the Gate takes over as off plan.
    assert_eq!(
        resolve_tool("banking_send_all", planned.iter(), &catalog)
            .unwrap()
            .as_str(),
        "banking.send.all"
    );
}
