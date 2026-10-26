#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end tests of the Gate: the real manifests and demo plan, a real ledger file and fake tools.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use munix_core::context::Band;
use munix_core::crypto::{Digest, Purpose, Signed, SigningKey, digest};
use munix_core::decision::{Decision, Stage, Verdict};
use munix_core::ids::TaskId;
use munix_core::label::{Confidential, Trust};
use munix_core::manifest::{Catalog, ToolManifest};
use munix_core::plan::Plan;
use munix_core::prompt::PromptEnvelope;
use munix_core::request::{Request, ViolationCode};
use munix_core::validate::Scalar;
use munix_gate::gate::{Gate, GateError, Reply, Store, StoreValue, TaskBrief};
use munix_gate::policy::DenyCode;
use munix_gate::tool::{Tool, ToolFailure};
use munix_gate::vault::{Credential, Vault};
use munix_ledger::{Entry, Ledger};
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
/// A tier 0 tool whose output is `editorial` (ceiling 75), to put the context in the Elevated band.
const NEWS_READ: &str = "
tool: news.read
description: Read the headline of the day.
tier: 0
output:
  headline: {type: text, region: editorial, confidential: public}
";

const BOSS: &str = "boss@corp.example";
const CREDENTIAL: &str = "mail-credential-xyz-0042";
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

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32]).unwrap()
}

fn task_id() -> TaskId {
    "T-demo".parse().unwrap()
}

fn manifest(yaml: &str) -> ToolManifest {
    ToolManifest::from_yaml(yaml).unwrap()
}

fn prompt_envelope() -> PromptEnvelope {
    PromptEnvelope {
        task: task_id(),
        session: "S-1".parse().unwrap(),
        nonce: "0123456789abcdef".to_owned(),
        text: format!("Read the reviews at {PROMPT_URL} and email a short summary to my boss."),
        data: Vec::new(),
    }
}

/// The demo plan with the real prompt hash, the page delivered (`unclassified` in reads), a body that may embed
/// the prompt's link and the boss's address, and an extra tier 0 step 3.
fn test_plan(prompt_hash: Digest) -> Plan {
    let mut text = DEMO_PLAN.to_owned();
    for (from, to) in [
        (
            "reads: [operator_content, product_listing, editorial, ugc_review]",
            "reads: [operator_content, product_listing, editorial, ugc_review, unclassified]",
        ),
        (
            "may_embed: {from: [prompt, step.1], min_trust: 60}",
            "may_embed: {from: [prompt, store.contacts.boss]}",
        ),
        (
            "\namendments:",
            "\n  - id: 3\n    tool: news.read\n    args: {}\n    budget: 5\namendments:",
        ),
    ] {
        assert!(text.contains(from), "demo plan changed: {from}");
        text = text.replace(from, to);
    }
    let mut plan = Plan::from_yaml(&text).unwrap();
    plan.prompt_hash = prompt_hash;
    plan
}

fn store() -> Store {
    let value = |v: &str, confidential| StoreValue {
        value: v.to_owned(),
        scalar: Scalar::Email,
        confidential,
    };
    let contacts = BTreeMap::from([
        ("boss".to_owned(), value(BOSS, Confidential::Private)),
        (
            "spam".to_owned(),
            value("spam@corp.example", Confidential::Public),
        ),
    ]);
    BTreeMap::from([("contacts".to_owned(), contacts)])
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "munix-gate-test-{}-{n}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Harness {
    gate: Gate,
    key: SigningKey,
    dir: PathBuf,
    prompt: Signed<PromptEnvelope>,
    plan: Signed<Plan>,
    store: Store,
    /// Every argument map the fake email tool received.
    sent: Arc<Mutex<Vec<Args>>>,
    /// The credential the fake email tool was handed on each call.
    credentials: Arc<Mutex<Vec<Option<String>>>>,
    /// Every url the fake web tool was asked to open.
    opened: Arc<Mutex<Vec<String>>>,
    web_fails: Arc<AtomicBool>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn harness() -> Harness {
    build(true, true)
}

fn build(register_email: bool, with_credential: bool) -> Harness {
    let key = signing_key();
    let web = manifest(WEB_OPEN);
    let email = manifest(EMAIL_SEND);
    let news = manifest(NEWS_READ);
    let digests = (
        web.digest().unwrap(),
        email.digest().unwrap(),
        news.digest().unwrap(),
    );
    let catalog = Catalog::from_manifests([web, email, news]).unwrap();
    let dir = fresh_dir();
    let ledger = Ledger::create(dir.join("ledger.jsonl")).unwrap();
    let vault = if with_credential {
        Vault::new().with(
            "vault://mail/demo".parse().unwrap(),
            Credential::new(CREDENTIAL),
        )
    } else {
        Vault::new()
    };
    let mut gate = Gate::new(key.clone(), catalog, vault, ledger);

    let sent = Arc::new(Mutex::new(Vec::new()));
    let credentials = Arc::new(Mutex::new(Vec::new()));
    let opened = Arc::new(Mutex::new(Vec::new()));
    let web_fails = Arc::new(AtomicBool::new(false));

    let (log, fails) = (opened.clone(), web_fails.clone());
    gate.register(
        "web.open".parse().unwrap(),
        digests.0,
        tool(move |a, _| {
            log.lock()
                .unwrap()
                .push(a["url"].as_str().unwrap().to_owned());
            if fails.load(Ordering::SeqCst) {
                return Err(ToolFailure::Unavailable);
            }
            Ok(args(&[
                (
                    "page",
                    json!(format!("{PAGE_TEXT} see ref:u1 and ref:e2 for more")),
                ),
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
    if register_email {
        let (log, creds) = (sent.clone(), credentials.clone());
        gate.register(
            "email.send".parse().unwrap(),
            digests.1,
            tool(move |a, c| {
                log.lock().unwrap().push(a.clone());
                creds
                    .lock()
                    .unwrap()
                    .push(c.map(|c| c.expose_secret().to_owned()));
                Ok(args(&[("message_id", json!("msg-1"))]))
            }),
        )
        .unwrap();
    }
    gate.register(
        "news.read".parse().unwrap(),
        digests.2,
        tool(|_, _| Ok(args(&[("headline", json!("A quiet day"))]))),
    )
    .unwrap();

    let prompt = Signed::sign(&key, Purpose::Prompt, prompt_envelope()).unwrap();
    let plan_body = test_plan(prompt_envelope().digest().unwrap());
    let plan = Signed::sign(&key, Purpose::Plan, plan_body).unwrap();
    Harness {
        gate,
        key,
        dir,
        prompt,
        plan,
        store: store(),
        sent,
        credentials,
        opened,
        web_fails,
    }
}

impl Harness {
    fn start(&mut self) -> TaskBrief {
        self.gate
            .start_task(&self.prompt, &self.plan, &self.store)
            .unwrap()
    }

    fn sign_plan(&self, plan: Plan) -> Signed<Plan> {
        Signed::sign(&self.key, Purpose::Plan, plan).unwrap()
    }

    fn plan_body(&self) -> Plan {
        self.plan.body.clone()
    }

    fn ledger_path(&self) -> PathBuf {
        self.dir.join("ledger.jsonl")
    }

    fn ledger_len(&self) -> usize {
        munix_ledger::verify_file(self.ledger_path()).unwrap()
    }

    fn entries(&self) -> Vec<Entry> {
        std::fs::read_to_string(self.ledger_path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn events(&self) -> Vec<String> {
        self.entries()
            .iter()
            .map(|e| e.event["event"].as_str().unwrap().to_owned())
            .collect()
    }

    fn emails_sent(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    /// Opens the prompt's page: the context drops to 10 (Lockdown) and link refs are issued.
    fn read_page(&mut self) -> Vec<String> {
        let Reply::Delivered(page) =
            self.gate
                .submit(&req(1, "web.open", json!({"url": "ref:u1"})))
        else {
            panic!("the page should have been delivered");
        };
        page.fields["links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    }

    /// Reads the headline: the context drops to 75 (Elevated).
    fn read_news(&mut self) {
        let reply = self.gate.submit(&req(3, "news.read", json!({})));
        let Reply::Delivered(news) = reply else {
            panic!("the headline should have been delivered");
        };
        assert_eq!(news.min_trust, Some(Trust::new(75)));
        assert_eq!(self.gate.context_trust(&task_id()), Some(Trust::new(75)));
    }
}

fn req(step: u32, tool: &str, args: Value) -> Request {
    Request {
        task: task_id(),
        plan: "P-demo".parse().unwrap(),
        step,
        tool: tool.parse().unwrap(),
        args: serde_json::from_value(args).unwrap(),
    }
}

/// An email to the boss ref with a plain subject and body.
fn email_to_boss(subject: &str) -> Request {
    req(
        2,
        "email.send",
        json!({"to": ["ref:e2"], "subject": subject, "body": "Summary of ref:u1 for ref:e2"}),
    )
}

fn hash_of(request: &Request) -> Digest {
    digest(request).unwrap()
}

fn pending(reply: Reply, request: &Request, needs: Stage) -> Digest {
    let hash = hash_of(request);
    assert_eq!(
        reply,
        Reply::Pending {
            request_hash: hash.clone(),
            needs
        }
    );
    hash
}

fn decision(hash: &Digest, band: Band, stage: Stage, verdict: Verdict) -> Decision {
    Decision {
        verdict,
        request_hash: hash.clone(),
        task: task_id(),
        plan: "P-demo".parse().unwrap(),
        band,
        stage,
        reasons: vec!["test.reason".to_owned()],
    }
}

/// A decision signed the way its stage requires.
fn signed(h: &Harness, d: Decision) -> Signed<Decision> {
    let purpose = match d.stage {
        Stage::User => Purpose::UserConfirmation,
        _ => Purpose::Decision,
    };
    Signed::sign(&h.key, purpose, d).unwrap()
}

fn user_approves(h: &Harness, hash: &Digest, band: Band) -> Signed<Decision> {
    signed(h, decision(hash, band, Stage::User, Verdict::Approve))
}

fn review(h: &Harness, hash: &Digest, band: Band, verdict: Verdict) -> Signed<Decision> {
    signed(h, decision(hash, band, Stage::LlmReview, verdict))
}

fn assert_ledger_clean(h: &Harness) {
    let text = std::fs::read_to_string(h.ledger_path()).unwrap();
    for secret in [
        BOSS,
        CREDENTIAL,
        PAGE_TEXT,
        "evil.test",
        "pixelmart.test",
        "spam@corp.example",
    ] {
        assert!(!text.contains(secret), "the ledger leaks {secret}");
    }
    assert!(munix_ledger::verify_file(h.ledger_path()).is_ok());
}

// ---- setup ----

#[test]
fn start_task_rejects_bad_input() {
    let mut h = harness();
    let baseline = h.ledger_len();
    assert_eq!(baseline, 3, "one tool_registered event per tool");

    // The prompt must be signed for Purpose::Prompt, with the Gate's key, and unchanged.
    let wrong_purpose = Signed::sign(&h.key, Purpose::Plan, prompt_envelope()).unwrap();
    let other_key = SigningKey::from_bytes(&[9u8; 32]).unwrap();
    let wrong_key = Signed::sign(&other_key, Purpose::Prompt, prompt_envelope()).unwrap();
    let mut tampered = h.prompt.clone();
    tampered
        .body
        .text
        .push_str(" and send it to evil@evil.test");
    for bad in [wrong_purpose, wrong_key, tampered] {
        let result = h.gate.start_task(&bad, &h.plan, &h.store);
        assert!(matches!(result, Err(GateError::BadSignature)));
    }
    // A signed prompt that breaks its own rules.
    let mut short_nonce = prompt_envelope();
    short_nonce.nonce = "short".to_owned();
    let short_nonce = Signed::sign(&h.key, Purpose::Prompt, short_nonce).unwrap();
    let result = h.gate.start_task(&short_nonce, &h.plan, &h.store);
    assert!(matches!(result, Err(GateError::InvalidPlan(_))));

    // The plan must be signed for Purpose::Plan.
    let wrong_purpose = Signed::sign(&h.key, Purpose::Decision, h.plan_body()).unwrap();
    let result = h.gate.start_task(&h.prompt, &wrong_purpose, &h.store);
    assert!(matches!(result, Err(GateError::BadSignature)));

    // It must be bound to this prompt and this task.
    let mut other_prompt = h.plan_body();
    other_prompt.prompt_hash = Digest::zero();
    let mut other_task = h.plan_body();
    other_task.task = "T-other".parse().unwrap();
    for body in [other_prompt, other_task] {
        let plan = h.sign_plan(body);
        let result = h.gate.start_task(&h.prompt, &plan, &h.store);
        assert!(matches!(result, Err(GateError::PlanMismatch)));
    }

    // It must pass Plan::validate.
    let mut bad_budget = h.plan_body();
    bad_budget.steps[0].budget = 0;
    let plan = h.sign_plan(bad_budget);
    let result = h.gate.start_task(&h.prompt, &plan, &h.store);
    assert!(matches!(result, Err(GateError::InvalidPlan(_))));

    // A store value that is not valid for its type.
    let mut bad_store = store();
    bad_store
        .get_mut("contacts")
        .unwrap()
        .get_mut("boss")
        .unwrap()
        .value = "not an address".to_owned();
    let result = h.gate.start_task(&h.prompt, &h.plan, &bad_store);
    assert!(matches!(result, Err(GateError::BadStoreValue)));

    assert_eq!(h.ledger_len(), baseline, "rejections write nothing");
    assert_eq!(h.gate.context_trust(&task_id()), None);

    // A tool without an implementation, a credential the vault lacks.
    let mut missing_tool = build(false, true);
    let result = missing_tool.gate.start_task(
        &missing_tool.prompt,
        &missing_tool.plan,
        &missing_tool.store,
    );
    assert!(matches!(result, Err(GateError::ToolNotRegistered)));
    let mut missing_credential = build(true, false);
    let result = missing_credential.gate.start_task(
        &missing_credential.prompt,
        &missing_credential.plan,
        &missing_credential.store,
    );
    assert!(matches!(result, Err(GateError::MissingCredential)));

    // The same task twice.
    h.start();
    assert_eq!(h.ledger_len(), baseline + 1);
    let result = h.gate.start_task(&h.prompt, &h.plan, &h.store);
    assert!(matches!(result, Err(GateError::TaskExists)));
    assert_eq!(h.ledger_len(), baseline + 1);
    assert_eq!(h.gate.context_trust(&task_id()), Some(Trust::FULL));
}

#[test]
fn register_checks_the_catalog_and_the_pin() {
    let key = signing_key();
    let web = manifest(WEB_OPEN);
    let pinned = web.digest().unwrap();
    let catalog = Catalog::from_manifests([web.clone()]).unwrap();
    let ledger = Ledger::create(fresh_dir().join("ledger.jsonl")).unwrap();
    let mut gate = Gate::new(key, catalog, Vault::new(), ledger);
    let noop = || tool(|_, _| Ok(Args::new()));

    let mut changed = web;
    changed.tier = 3;
    let result = gate.register(
        "web.open".parse().unwrap(),
        changed.digest().unwrap(),
        noop(),
    );
    assert!(matches!(result, Err(GateError::ManifestMismatch)));
    let result = gate.register(
        "web.open".parse().unwrap(),
        Digest::of_bytes(b"anything"),
        noop(),
    );
    assert!(matches!(result, Err(GateError::ManifestMismatch)));
    let result = gate.register("mail.read".parse().unwrap(), pinned.clone(), noop());
    assert!(matches!(result, Err(GateError::UnknownTool)));
    gate.register("web.open".parse().unwrap(), pinned.clone(), noop())
        .unwrap();
    let result = gate.register("web.open".parse().unwrap(), pinned, noop());
    assert!(matches!(result, Err(GateError::AlreadyRegistered)));
}

#[test]
fn the_brief_lists_the_prompt_url_and_the_boss() {
    let mut h = harness();
    let brief = h.start();
    assert_eq!(brief.task, task_id());
    assert_eq!(brief.plan, h.plan_body());
    let listed: Vec<(&str, &str)> = brief
        .refs
        .iter()
        .map(|r| (r.id.as_str(), r.what.as_str()))
        .collect();
    // Only the store value the plan names is issued; the other contact is not.
    assert_eq!(
        listed,
        [
            ("ref:u1", "url 1 in the prompt"),
            ("ref:e2", "store contacts.boss")
        ]
    );
    assert!(h.events().contains(&"task_started".to_owned()));
    assert_eq!(h.gate.context_trust(&task_id()), Some(Trust::FULL));
}

// ---- the pipeline ----

#[test]
fn reading_a_page_lowers_trust_and_the_email_then_needs_the_user() {
    let mut h = harness();
    h.start();

    let reply = h.gate.submit(&req(1, "web.open", json!({"url": "ref:u1"})));
    let Reply::Delivered(page) = reply else {
        panic!("expected the page");
    };
    assert_eq!(*h.opened.lock().unwrap(), [PROMPT_URL]);
    assert_eq!(page.min_trust, Some(Trust::new(10)));
    assert!(page.withheld.is_empty());
    assert_eq!(h.gate.context_trust(&task_id()), Some(Trust::new(10)));
    assert_eq!(h.gate.known_domains(), BTreeSet::from([1]));
    let links = page.fields["links"].as_array().unwrap();
    assert_eq!(links.len(), 2);
    assert!(
        links
            .iter()
            .all(|l| l.as_str().unwrap().starts_with("ref:u"))
    );
    // Page text cannot name a Gate ref.
    let text = page.fields["page"].as_str().unwrap();
    assert!(text.contains(PAGE_TEXT) && text.contains("ref-u1") && !text.contains("ref:u1"));

    // Lockdown sends a tier 3 tool to the user, even for the boss.
    let email = email_to_boss("Reviews");
    let hash = pending(h.gate.submit(&email), &email, Stage::User);
    assert_eq!(h.emails_sent(), 0);

    let approval = user_approves(&h, &hash, Band::Lockdown);
    let Reply::Delivered(done) = h.gate.decide(&approval) else {
        panic!("expected the email to run");
    };
    assert_eq!(done.fields["message_id"], json!("msg-1"));
    let sent = h.sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["to"], json!([BOSS]));
    assert_eq!(sent[0]["subject"], json!("Reviews"));
    assert_eq!(
        sent[0]["body"],
        json!(format!("Summary of {PROMPT_URL} for {BOSS}"))
    );
    assert!(!sent[0].values().any(|v| v.to_string().contains("ref:")));
    assert_eq!(
        *h.credentials.lock().unwrap(),
        [Some(CREDENTIAL.to_owned())]
    );
    drop(sent);

    // The same decision cannot run it twice.
    assert_eq!(h.gate.decide(&approval), Reply::Halted);
    assert_eq!(h.emails_sent(), 1);
    // The step's budget is used up.
    assert_eq!(
        h.gate.submit(&email_to_boss("Again")),
        Reply::Denied(DenyCode::BudgetExhausted)
    );

    let events = h.events();
    for expected in [
        "tool_registered",
        "task_started",
        "request",
        "ruling",
        "executed",
        "context_lowered",
        "decision",
    ] {
        assert!(events.contains(&expected.to_owned()), "no {expected} event");
    }
    let lowered = h
        .entries()
        .into_iter()
        .find(|e| e.event["event"] == "context_lowered")
        .unwrap();
    assert_eq!(lowered.event["from"], json!(100));
    assert_eq!(lowered.event["to"], json!(10));
    assert_ledger_clean(&h);
}

#[test]
fn a_clean_context_delivers_the_email_directly() {
    let mut h = harness();
    h.start();
    let email = email_to_boss("Reviews");
    let Reply::Delivered(done) = h.gate.submit(&email) else {
        panic!("expected delivery");
    };
    assert_eq!(done.fields["message_id"], json!("msg-1"));
    assert_eq!(h.sent.lock().unwrap()[0]["to"], json!([BOSS]));
    assert_eq!(h.emails_sent(), 1);
    // An operator_content output (ceiling 85) keeps the context Clean.
    assert_eq!(h.gate.context_trust(&task_id()), Some(Trust::new(85)));
    assert_ledger_clean(&h);
}

#[test]
fn a_destination_from_the_page_is_a_takeover() {
    // A link ref from the page, and a raw address the agent typed, are both takeover signals.
    for to in [json!("LINK"), json!("attacker@evil.test")] {
        let mut h = harness();
        h.start();
        let links = h.read_page();
        let to = if to == json!("LINK") {
            json!(links[0])
        } else {
            to
        };
        let evil = req(
            2,
            "email.send",
            json!({"to": [to], "subject": "Hi", "body": "Reviews attached"}),
        );
        assert_eq!(
            h.gate.submit(&evil),
            Reply::Takeover(DenyCode::UntrustedDestination)
        );

        // Halted until recovery: nothing runs, whatever it is, and no decision can revive it.
        assert_eq!(h.gate.submit(&email_to_boss("Hi")), Reply::Halted);
        assert_eq!(
            h.gate.submit(&req(3, "news.read", json!({}))),
            Reply::Halted
        );
        let hash = hash_of(&evil);
        assert_eq!(
            h.gate.decide(&user_approves(&h, &hash, Band::Lockdown)),
            Reply::Halted
        );
        assert_eq!(h.emails_sent(), 0);
        assert!(h.events().contains(&"takeover".to_owned()));
        assert_ledger_clean(&h);
    }
}

#[test]
fn a_raw_link_in_the_body_is_a_takeover() {
    let mut h = harness();
    h.start();
    let request = req(
        2,
        "email.send",
        json!({"to": ["ref:e2"], "subject": "Hi", "body": "Read https://evil.test/collect now"}),
    );
    assert_eq!(
        h.gate.submit(&request),
        Reply::Takeover(DenyCode::RawDestination)
    );
    assert_eq!(h.gate.submit(&email_to_boss("Hi")), Reply::Halted);
    assert_eq!(h.emails_sent(), 0);
    assert!(h.events().contains(&"takeover".to_owned()));
    assert_ledger_clean(&h);
}

#[test]
fn quoting_the_prompts_url_in_the_body_is_delivered_with_the_demo_plan() {
    let mut h = harness();
    let mut demo = Plan::from_yaml(DEMO_PLAN).unwrap();
    demo.prompt_hash = prompt_envelope().digest().unwrap();
    h.plan = h.sign_plan(demo);
    h.start();

    let body = format!("Summary of {PROMPT_URL}: 4.6 stars across 1,200 reviews.");
    let request = req(
        2,
        "email.send",
        json!({"to": ["ref:e2"], "subject": "Reviews", "body": body}),
    );
    let Reply::Delivered(done) = h.gate.submit(&request) else {
        panic!("expected delivery");
    };
    assert_eq!(done.fields["message_id"], json!("msg-1"));
    assert_eq!(h.emails_sent(), 1);
    assert_eq!(h.sent.lock().unwrap()[0]["body"], json!(body));
    assert_ledger_clean(&h);
}

#[test]
fn quoting_a_low_trust_page_link_in_the_body_is_untrusted_destination_not_raw() {
    let mut h = harness();
    let mut demo = Plan::from_yaml(&DEMO_PLAN.replace(
        "reads: [operator_content, product_listing, editorial, ugc_review]",
        "reads: [operator_content, product_listing, editorial, ugc_review, unclassified]",
    ))
    .unwrap();
    demo.prompt_hash = prompt_envelope().digest().unwrap();
    h.plan = h.sign_plan(demo);
    h.start();
    h.read_page();

    let request = req(
        2,
        "email.send",
        json!({"to": ["ref:e2"], "subject": "Hi", "body": "Read https://evil.test/collect now"}),
    );
    assert_eq!(
        h.gate.submit(&request),
        Reply::Takeover(DenyCode::UntrustedDestination)
    );
    assert_eq!(h.emails_sent(), 0);
    assert_ledger_clean(&h);
}

#[test]
fn raw_email_in_the_body_traces_known_store_values_and_rejects_unknown_ones() {
    // Known store address when may_embed allows store.contacts.boss: delivered at Clean band.
    let mut h = harness();
    h.start();
    let request = req(
        2,
        "email.send",
        json!({"to": ["ref:e2"], "subject": "Reviews", "body": format!("Prepared for {BOSS}.")}),
    );
    assert!(matches!(h.gate.submit(&request), Reply::Delivered(_)));
    assert_eq!(h.emails_sent(), 1);
    assert_ledger_clean(&h);

    // Known store address when may_embed only allows [prompt, step.1] (the demo plan): still delivered, because a
    // value the operator supplied isn't attacker-chosen.
    let mut h = harness();
    let mut demo = Plan::from_yaml(DEMO_PLAN).unwrap();
    demo.prompt_hash = prompt_envelope().digest().unwrap();
    h.plan = h.sign_plan(demo);
    h.start();
    let request = req(
        2,
        "email.send",
        json!({"to": ["ref:e2"], "subject": "Reviews", "body": format!("Prepared for {BOSS}.")}),
    );
    assert!(matches!(h.gate.submit(&request), Reply::Delivered(_)));
    assert_eq!(h.emails_sent(), 1);
    assert_ledger_clean(&h);

    // Unknown email address typed raw into the body: RawDestination.
    let mut h = harness();
    h.start();
    let request = req(
        2,
        "email.send",
        json!({"to": ["ref:e2"], "subject": "Reviews", "body": "Forward to mallory@evil.test."}),
    );
    assert_eq!(
        h.gate.submit(&request),
        Reply::Takeover(DenyCode::RawDestination)
    );
    assert_eq!(h.emails_sent(), 0);
    assert_ledger_clean(&h);
}

#[test]
fn a_credential_in_the_body_is_denied_not_sent() {
    let mut h = harness();
    h.start();
    let request = req(
        2,
        "email.send",
        json!({"to": ["ref:e2"], "subject": "Hi", "body": format!("the key is {CREDENTIAL}")}),
    );
    assert_eq!(
        h.gate.submit(&request),
        Reply::Denied(DenyCode::ConfidentialData)
    );
    assert_eq!(h.emails_sent(), 0);
    // A denial is not a takeover: the task still runs.
    assert!(matches!(
        h.gate.submit(&email_to_boss("Fine")),
        Reply::Delivered(_)
    ));
    assert_ledger_clean(&h);
}

#[test]
fn gatekeeping_of_unknown_tasks_plans_and_tools() {
    let mut h = harness();
    // No task yet.
    assert_eq!(
        h.gate.submit(&req(1, "web.open", json!({"url": "ref:u1"}))),
        Reply::Halted
    );
    h.start();
    // A wrong plan id, a tool outside the catalog, and a catalog tool on another tool's step are all takeover
    // signals: each halts the task.
    let mut wrong_plan = req(1, "web.open", json!({"url": "ref:u1"}));
    wrong_plan.plan = "P-other".parse().unwrap();
    assert_eq!(
        h.gate.submit(&wrong_plan),
        Reply::Takeover(DenyCode::OffPlan)
    );
    assert_eq!(
        h.gate.submit(&req(1, "web.open", json!({"url": "ref:u1"}))),
        Reply::Halted
    );
    assert!(h.opened.lock().unwrap().is_empty());

    for (step, tool, args) in [
        (1, "mail.read", json!({})),
        (2, "web.open", json!({"url": "ref:u1"})),
    ] {
        let mut h = harness();
        h.start();
        assert_eq!(
            h.gate.submit(&req(step, tool, args)),
            Reply::Takeover(DenyCode::OffPlan),
            "{tool}"
        );
        assert_eq!(
            h.gate.submit(&req(1, "web.open", json!({"url": "ref:u1"}))),
            Reply::Halted
        );
        assert!(h.opened.lock().unwrap().is_empty());
    }
    assert!(h.opened.lock().unwrap().is_empty());
}

#[test]
fn three_denials_on_one_step_pause_the_task() {
    let mut h = harness();
    h.start();
    let forbidden_cc = req(
        2,
        "email.send",
        json!({"to": ["ref:e2"], "cc": ["ref:e2"], "subject": "Hi", "body": "Hello"}),
    );
    let missing_subject = req(2, "email.send", json!({"to": ["ref:e2"], "body": "Hello"}));
    let no_url = req(1, "web.open", json!({}));

    // Denials are counted per step.
    assert_eq!(
        h.gate.submit(&forbidden_cc),
        Reply::Denied(DenyCode::ForbiddenArg)
    );
    for _ in 0..2 {
        let Reply::Malformed(violations) = h.gate.submit(&no_url) else {
            panic!("expected malformed");
        };
        assert_eq!(violations[0].code, ViolationCode::MissingArg);
    }
    assert!(matches!(
        h.gate.submit(&missing_subject),
        Reply::Malformed(_)
    ));
    assert!(matches!(
        h.gate.submit(&req(1, "web.open", json!({"url": "ref:u1"}))),
        Reply::Delivered(_)
    ));
    assert!(!h.events().contains(&"paused".to_owned()));

    // The third denial on step 2 pauses the task, and still answers with the denial.
    assert_eq!(
        h.gate.submit(&forbidden_cc),
        Reply::Denied(DenyCode::ForbiddenArg)
    );
    assert!(h.events().contains(&"paused".to_owned()));
    assert_eq!(h.gate.submit(&email_to_boss("Hi")), Reply::Halted);
    assert_eq!(h.gate.submit(&no_url), Reply::Halted);
    assert_eq!(h.emails_sent(), 0);
    assert_ledger_clean(&h);
}

#[test]
fn a_failing_tool_is_reported_and_counts_against_the_budget() {
    let mut h = harness();
    h.start();
    h.web_fails.store(true, Ordering::SeqCst);
    let open = req(1, "web.open", json!({"url": "ref:u1"}));
    for _ in 0..3 {
        assert_eq!(
            h.gate.submit(&open),
            Reply::Failed(ToolFailure::Unavailable)
        );
    }
    assert_eq!(h.gate.context_trust(&task_id()), Some(Trust::FULL));
    assert_eq!(
        h.gate.submit(&open),
        Reply::Denied(DenyCode::BudgetExhausted)
    );
    assert_eq!(h.opened.lock().unwrap().len(), 3);
    assert!(h.entries().iter().any(|e| {
        e.event["event"] == "executed"
            && e.event["ok"] == json!(false)
            && e.event["failure"] == json!("unavailable")
    }));
}

// ---- decisions ----

#[test]
fn decide_refuses_what_it_should() {
    let mut h = harness();
    h.start();
    h.read_page();
    let email = email_to_boss("Reviews");
    let hash = pending(h.gate.submit(&email), &email, Stage::User);
    let before = h.ledger_len();

    let other_key = SigningKey::from_bytes(&[9u8; 32]).unwrap();
    let stage_user = |verdict, purpose, key: &SigningKey| {
        Signed::sign(
            key,
            purpose,
            decision(&hash, Band::Lockdown, Stage::User, verdict),
        )
        .unwrap()
    };
    let mut wrong_task = decision(&hash, Band::Lockdown, Stage::User, Verdict::Approve);
    wrong_task.task = "T-other".parse().unwrap();
    let mut wrong_plan = decision(&hash, Band::Lockdown, Stage::User, Verdict::Approve);
    wrong_plan.plan = "P-other".parse().unwrap();
    let refused = [
        // A Decision signature on a user-stage decision.
        stage_user(Verdict::Approve, Purpose::Decision, &h.key),
        // The wrong key.
        stage_user(Verdict::Approve, Purpose::UserConfirmation, &other_key),
        // A user cannot answer with "ask the user".
        stage_user(Verdict::ConfirmUser, Purpose::UserConfirmation, &h.key),
        // Deterministic decisions are only ever made by the Gate.
        Signed::sign(
            &h.key,
            Purpose::Decision,
            decision(
                &hash,
                Band::Lockdown,
                Stage::Deterministic,
                Verdict::Approve,
            ),
        )
        .unwrap(),
        Signed::sign(
            &h.key,
            Purpose::UserConfirmation,
            decision(
                &hash,
                Band::Lockdown,
                Stage::Deterministic,
                Verdict::Approve,
            ),
        )
        .unwrap(),
        // A review cannot answer a request that needs the user.
        review(&h, &hash, Band::Lockdown, Verdict::Approve),
        // A review decision signed as a user confirmation.
        Signed::sign(
            &h.key,
            Purpose::UserConfirmation,
            decision(&hash, Band::Lockdown, Stage::LlmReview, Verdict::Approve),
        )
        .unwrap(),
        // A request hash that is not parked.
        user_approves(&h, &Digest::of_bytes(b"another request"), Band::Lockdown),
        // A stale band.
        user_approves(&h, &hash, Band::Elevated),
        user_approves(&h, &hash, Band::Clean),
        // Another plan, another task.
        signed(&h, wrong_plan),
        signed(&h, wrong_task),
    ];
    for d in &refused {
        assert_eq!(h.gate.decide(d), Reply::Halted);
    }
    assert_eq!(h.emails_sent(), 0);

    // Refusing changed nothing: the parked request is still waiting for the real decision.
    assert!(h.ledger_len() >= before);
    let real = user_approves(&h, &hash, Band::Lockdown);
    assert!(matches!(h.gate.decide(&real), Reply::Delivered(_)));
    assert_eq!(h.emails_sent(), 1);
    assert_ledger_clean(&h);
}

#[test]
fn a_review_denial_is_a_reviewer_denial_and_counts() {
    let mut h = harness();
    h.start();
    h.read_news();
    let email = email_to_boss("Reviews");
    let hash = pending(h.gate.submit(&email), &email, Stage::LlmReview);

    for verdict in [Verdict::Deny, Verdict::RequireAmendment] {
        let reply = h.gate.submit(&email);
        assert_eq!(
            reply,
            Reply::Pending {
                request_hash: hash.clone(),
                needs: Stage::LlmReview
            }
        );
        let refusal = review(&h, &hash, Band::Elevated, verdict);
        assert_eq!(h.gate.decide(&refusal), Reply::Denied(DenyCode::Reviewer));
        // The request is gone.
        assert_eq!(h.gate.decide(&refusal), Reply::Halted);
    }
    assert_eq!(h.emails_sent(), 0);

    // Two reviewer denials on step 2 so far; a third pauses the task.
    let reply = h.gate.submit(&email);
    pending(reply, &email, Stage::LlmReview);
    let refusal = review(&h, &hash, Band::Elevated, Verdict::Deny);
    assert_eq!(h.gate.decide(&refusal), Reply::Denied(DenyCode::Reviewer));
    assert!(h.events().contains(&"paused".to_owned()));
    assert_eq!(h.gate.submit(&email), Reply::Halted);
}

#[test]
fn a_review_can_approve_or_hand_over_to_the_user() {
    // The review approves.
    let mut h = harness();
    h.start();
    h.read_news();
    let email = email_to_boss("Reviews");
    let hash = pending(h.gate.submit(&email), &email, Stage::LlmReview);
    let approval = review(&h, &hash, Band::Elevated, Verdict::Approve);
    assert!(matches!(h.gate.decide(&approval), Reply::Delivered(_)));
    assert_eq!(h.sent.lock().unwrap()[0]["to"], json!([BOSS]));

    // The review asks the user; only the user can then answer.
    let mut h = harness();
    h.start();
    h.read_news();
    let email = email_to_boss("Reviews");
    let hash = pending(h.gate.submit(&email), &email, Stage::LlmReview);
    let hand_over = review(&h, &hash, Band::Elevated, Verdict::ConfirmUser);
    assert_eq!(
        h.gate.decide(&hand_over),
        Reply::Pending {
            request_hash: hash.clone(),
            needs: Stage::User
        }
    );
    let again = review(&h, &hash, Band::Elevated, Verdict::Approve);
    assert_eq!(h.gate.decide(&again), Reply::Halted);
    assert_eq!(h.emails_sent(), 0);
    let approval = user_approves(&h, &hash, Band::Elevated);
    assert!(matches!(h.gate.decide(&approval), Reply::Delivered(_)));
    assert_eq!(h.emails_sent(), 1);

    // The user may also answer a request parked for review directly.
    let mut h = harness();
    h.start();
    h.read_news();
    let email = email_to_boss("Reviews");
    let hash = pending(h.gate.submit(&email), &email, Stage::LlmReview);
    let approval = user_approves(&h, &hash, Band::Elevated);
    assert!(matches!(h.gate.decide(&approval), Reply::Delivered(_)));
    assert_ledger_clean(&h);
}

#[test]
fn a_decision_goes_stale_when_the_band_drops() {
    let mut h = harness();
    h.start();
    h.read_news();
    let email = email_to_boss("Reviews");
    let hash = pending(h.gate.submit(&email), &email, Stage::LlmReview);
    let old = review(&h, &hash, Band::Elevated, Verdict::Approve);

    // Reading the page drops the context from Elevated to Lockdown.
    h.read_page();
    assert_eq!(h.gate.context_trust(&task_id()), Some(Trust::new(10)));
    assert_eq!(h.gate.decide(&old), Reply::Halted);
    assert_eq!(h.emails_sent(), 0);

    // Asking again re-parks it for the new band, and the old decision stays dead.
    let hash = pending(h.gate.submit(&email), &email, Stage::User);
    assert_eq!(h.gate.decide(&old), Reply::Halted);
    let approval = user_approves(&h, &hash, Band::Lockdown);
    assert!(matches!(h.gate.decide(&approval), Reply::Delivered(_)));
    assert_eq!(h.emails_sent(), 1);
}

#[test]
fn an_approval_cannot_exceed_the_budget() {
    let mut h = harness();
    h.start();
    h.read_page();
    let first = email_to_boss("First");
    let second = email_to_boss("Second");
    let first_hash = pending(h.gate.submit(&first), &first, Stage::User);
    let second_hash = pending(h.gate.submit(&second), &second, Stage::User);

    let approval = user_approves(&h, &first_hash, Band::Lockdown);
    assert!(matches!(h.gate.decide(&approval), Reply::Delivered(_)));
    // The code rules again when a decision arrives: the budget of step 2 is one.
    let approval = user_approves(&h, &second_hash, Band::Lockdown);
    assert_eq!(
        h.gate.decide(&approval),
        Reply::Denied(DenyCode::BudgetExhausted)
    );
    assert_eq!(h.emails_sent(), 1);
}

// ---- what the Console and the front need to ask ----

fn other_task() -> TaskId {
    "T-other".parse().unwrap()
}

#[test]
fn plan_returns_the_task_plan() {
    let mut h = harness();
    assert_eq!(h.gate.plan(&task_id()), None, "no task yet");
    h.start();
    let plan = h.gate.plan(&task_id()).unwrap();
    assert_eq!(*plan, h.plan_body());
    assert_eq!(plan.plan, "P-demo".parse().unwrap());
    assert_eq!(plan.steps.len(), 3);
    assert_eq!(h.gate.plan(&other_task()), None);
}

#[test]
fn calls_made_counts_executed_calls_per_step() {
    let mut h = harness();
    assert_eq!(h.gate.calls_made(&task_id(), 1), None, "no task yet");
    let brief = h.start();
    assert_eq!(brief.plan.steps.len(), 3);
    for step in 0..=4 {
        assert_eq!(h.gate.calls_made(&task_id(), step), Some(0));
    }
    assert_eq!(h.gate.calls_made(&other_task(), 1), None);

    h.read_page();
    assert_eq!(h.gate.calls_made(&task_id(), 1), Some(1));
    assert_eq!(h.gate.calls_made(&task_id(), 2), Some(0));

    // Malformed, denied and parked requests do not count; neither does a request on another step.
    let no_url = req(1, "web.open", json!({}));
    assert!(matches!(h.gate.submit(&no_url), Reply::Malformed(_)));
    let forbidden_cc = req(
        2,
        "email.send",
        json!({"to": ["ref:e2"], "cc": ["ref:e2"], "subject": "Hi", "body": "Hello"}),
    );
    assert_eq!(
        h.gate.submit(&forbidden_cc),
        Reply::Denied(DenyCode::ForbiddenArg)
    );
    let email = email_to_boss("Reviews");
    let hash = pending(h.gate.submit(&email), &email, Stage::User);
    assert_eq!(h.gate.calls_made(&task_id(), 1), Some(1));
    assert_eq!(h.gate.calls_made(&task_id(), 2), Some(0));

    // An approved call counts; so does a call whose tool failed.
    let approval = user_approves(&h, &hash, Band::Lockdown);
    assert!(matches!(h.gate.decide(&approval), Reply::Delivered(_)));
    assert_eq!(h.gate.calls_made(&task_id(), 2), Some(1));
    h.web_fails.store(true, Ordering::SeqCst);
    assert_eq!(
        h.gate.submit(&req(1, "web.open", json!({"url": "ref:u1"}))),
        Reply::Failed(ToolFailure::Unavailable)
    );
    assert_eq!(h.gate.calls_made(&task_id(), 1), Some(2));
    assert_eq!(h.gate.calls_made(&task_id(), 3), Some(0));
}

#[test]
fn describe_pending_shows_real_values_and_where_they_came_from() {
    let mut h = harness();
    h.start();
    h.read_page();
    let email = email_to_boss("Reviews");
    let hash = pending(h.gate.submit(&email), &email, Stage::User);

    let view = h.gate.describe_pending(&task_id(), &hash).unwrap();
    assert_eq!(view.tool.as_str(), "email.send");
    assert_eq!(view.step, 2);
    assert_eq!(view.needs, Stage::User);
    assert_eq!(view.band, Band::Lockdown);
    let names: Vec<&str> = view.args.iter().map(|a| a.name.as_str()).collect();
    assert_eq!(names, ["body", "subject", "to"], "in name order");
    let arg = |name: &str| view.args.iter().find(|a| a.name == name).unwrap();

    // Refs are resolved to the values that will be sent; nothing says `ref:`.
    let expected_body = format!("Summary of {PROMPT_URL} for {BOSS}");
    assert_eq!(arg("body").value, expected_body);
    assert!(arg("to").value.contains(BOSS) && !arg("to").value.contains("ref:"));
    assert!(view.args.iter().all(|a| !a.value.contains("ref:")));

    // Sources, in order of appearance.
    assert_eq!(arg("to").sources, ["store contacts.boss (trust 100)"]);
    assert_eq!(
        arg("body").sources,
        ["the prompt (trust 100)", "store contacts.boss (trust 100)"]
    );
    // A plain word that traces to nothing says so.
    assert_eq!(arg("subject").sources, ["untraced"]);

    // The view matches what executing the request does.
    let approval = user_approves(&h, &hash, view.band);
    assert!(matches!(h.gate.decide(&approval), Reply::Delivered(_)));
    let sent = h.sent.lock().unwrap();
    assert_eq!(sent[0]["body"], json!(expected_body));
    drop(sent);

    // A decided request is no longer parked.
    assert_eq!(h.gate.describe_pending(&task_id(), &hash), None);
}

#[test]
fn describe_pending_names_raw_values_that_match_a_known_value_or_nothing() {
    let mut h = harness();
    h.start();
    h.read_page();
    // The boss's address typed out in full still traces to the store entry it equals.
    let typed = req(
        2,
        "email.send",
        json!({"to": [BOSS], "subject": "Reviews", "body": "Hello"}),
    );
    let hash = pending(h.gate.submit(&typed), &typed, Stage::User);
    let view = h.gate.describe_pending(&task_id(), &hash).unwrap();
    let to = view.args.iter().find(|a| a.name == "to").unwrap();
    assert_eq!(to.sources, ["store contacts.boss (trust 100)"]);
    assert!(to.value.contains(BOSS));
    // A single word that is not a known value traces to nothing.
    let body = view.args.iter().find(|a| a.name == "body").unwrap();
    assert_eq!(body.value, "Hello");
    assert_eq!(body.sources, ["untraced"]);
}

#[test]
fn describe_pending_only_knows_parked_requests_of_known_tasks() {
    let mut h = harness();
    let hash = hash_of(&email_to_boss("Reviews"));
    assert_eq!(h.gate.describe_pending(&task_id(), &hash), None, "no task");
    h.start();
    h.read_page();
    assert_eq!(
        h.gate.describe_pending(&task_id(), &hash),
        None,
        "not parked"
    );

    let email = email_to_boss("Reviews");
    let hash = pending(h.gate.submit(&email), &email, Stage::User);
    assert_eq!(h.gate.describe_pending(&other_task(), &hash), None);
    assert!(h.gate.describe_pending(&task_id(), &hash).is_some());
    let other_hash = Digest::of_bytes(b"another request");
    assert_eq!(h.gate.describe_pending(&task_id(), &other_hash), None);

    // Describing is read-only: the request is still parked and can be decided.
    let approval = user_approves(&h, &hash, Band::Lockdown);
    assert!(matches!(h.gate.decide(&approval), Reply::Delivered(_)));
}

#[test]
fn describe_pending_reports_the_review_stage_and_band() {
    let mut h = harness();
    h.start();
    h.read_news();
    let email = email_to_boss("Reviews");
    let hash = pending(h.gate.submit(&email), &email, Stage::LlmReview);
    let view = h.gate.describe_pending(&task_id(), &hash).unwrap();
    assert_eq!((view.needs, view.band), (Stage::LlmReview, Band::Elevated));
}
