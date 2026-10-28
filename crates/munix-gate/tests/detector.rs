//! The injection detector in the Gate (invariant 7): it scores free-text fields before ingest and can only lower
//! trust; a failing detector flags; nothing it sees or says reaches the ledger or the Supervisor as text.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use munix_core::crypto::{Purpose, Signed, SigningKey};
use munix_core::detect::{DETECTOR_FLAGGED, DetectError, Detector, DetectorConfig};
use munix_core::ids::TaskId;
use munix_core::label::Trust;
use munix_core::manifest::{Catalog, ToolManifest};
use munix_core::plan::Plan;
use munix_core::prompt::PromptEnvelope;
use munix_core::request::Request;
use munix_core::validate::Scalar;
use munix_gate::gate::{Gate, Reply, Store, StoreValue};
use munix_gate::ingest::Delivered;
use munix_gate::tool::Tool;
use munix_gate::vault::{Credential, Vault};
use munix_ledger::Ledger;
use serde_json::{Value, json};

const EMAIL_SEND: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../manifests/email.send.yaml"
));
const DEMO_PLAN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/demo-plan.yaml"
));

/// A page tool with free text in and out of `reads`, typed fields, and a hidden field.
const PAGE: &str = r"
tool: web.open
description: Open a web page.
tier: 1
egress: true
args:
  url: {type: url, role: destination}
output:
  page:      {type: text,    region: unclassified,    confidential: public}
  listing:   {type: text,    region: product_listing, confidential: public}
  editorial: {type: text,    region: editorial,       confidential: public}
  reviews:   {type: 'text[]', region: ugc_review,     confidential: public}
  stars:     {type: int,     region: ugc_review,      confidential: public, max: 5}
  secret:    {type: text,    region: hidden,          confidential: public}
";

const PROMPT_URL: &str = "https://pixelmart.test:8080/reviews";
/// In every free-text value the tool returns; must never reach the ledger or the Supervisor's view.
const MARKER: &str = "ZXQ-MARKER-7731";

type Args = BTreeMap<String, Value>;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("munix-detector-{}-{n}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn task_id() -> TaskId {
    "T-demo".parse().unwrap()
}

fn tool<F>(f: F) -> Box<dyn Tool>
where
    F: Fn(&Args, Option<&Credential>) -> Result<Args, munix_gate::tool::ToolFailure>
        + Send
        + Sync
        + 'static,
{
    Box::new(f)
}

fn args(pairs: &[(&str, Value)]) -> Args {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
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

fn store() -> Store {
    let boss = StoreValue {
        value: "boss@corp.example".to_owned(),
        scalar: Scalar::Email,
        confidential: munix_core::label::Confidential::Private,
    };
    BTreeMap::from([(
        "contacts".to_owned(),
        BTreeMap::from([("boss".to_owned(), boss)]),
    )])
}

/// Flags any text containing `FLAG`, or fails; records every batch of texts it was asked to score.
struct Fake {
    fail: bool,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Detector for Fake {
    fn name(&self) -> &str {
        "fake-guard"
    }
    fn score(&self, texts: &[&str]) -> Result<Vec<f32>, DetectError> {
        self.seen
            .lock()
            .unwrap()
            .extend(texts.iter().map(|t| (*t).to_owned()));
        if self.fail {
            return Err(DetectError::Unavailable);
        }
        Ok(texts
            .iter()
            .map(|t| if t.contains("FLAG") { 0.9 } else { 0.1 })
            .collect())
    }
}

struct Run {
    gate: Gate,
    ledger_path: PathBuf,
    seen: Arc<Mutex<Vec<String>>>,
}

/// `detector`: `None` for no detector, `Some(fail)` for the fake. `page` is what the tool returns.
fn setup(detector: Option<bool>, page: Args) -> Run {
    let key = SigningKey::from_bytes(&[7u8; 32]).unwrap();
    let web = ToolManifest::from_yaml(PAGE).unwrap();
    let email = ToolManifest::from_yaml(EMAIL_SEND).unwrap();
    let digests = (web.digest().unwrap(), email.digest().unwrap());
    let catalog = Catalog::from_manifests([web, email]).unwrap();
    let dir = fresh_dir();
    let ledger_path = dir.join("ledger.jsonl");
    let ledger = Ledger::create(&ledger_path).unwrap();
    let vault = Vault::new().with(
        "vault://mail/demo".parse().unwrap(),
        Credential::new("mail-credential-xyz-0042"),
    );
    let mut gate = Gate::new(key.clone(), catalog, vault, ledger);
    let seen = Arc::new(Mutex::new(Vec::new()));
    if let Some(fail) = detector {
        let fake = Fake {
            fail,
            seen: seen.clone(),
        };
        gate.set_detector(DetectorConfig::new(Arc::new(fake), 0.5).unwrap());
    }
    gate.register(
        "web.open".parse().unwrap(),
        digests.0,
        tool(move |_, _| Ok(page.clone())),
    )
    .unwrap();
    gate.register(
        "email.send".parse().unwrap(),
        digests.1,
        tool(|_, _| Ok(args(&[("message_id", json!("msg-1"))]))),
    )
    .unwrap();
    let envelope = PromptEnvelope {
        task: task_id(),
        session: "S-1".parse().unwrap(),
        nonce: "0123456789abcdef".to_owned(),
        text: format!("Read the reviews at {PROMPT_URL} and email a short summary to my boss."),
        data: Vec::new(),
    };
    let prompt = Signed::sign(&key, Purpose::Prompt, envelope.clone()).unwrap();
    let mut plan_body = Plan::from_yaml(DEMO_PLAN).unwrap();
    plan_body.prompt_hash = envelope.digest().unwrap();
    let plan = Signed::sign(&key, Purpose::Plan, plan_body).unwrap();
    gate.start_task(&prompt, &plan, &store()).unwrap();
    Run {
        gate,
        ledger_path,
        seen,
    }
}

fn clean_page() -> Args {
    args(&[
        ("page", json!(format!("page text {MARKER}"))),
        ("listing", json!(format!("Listing {MARKER}"))),
        ("editorial", json!(format!("Editorial {MARKER}"))),
        (
            "reviews",
            json!([
                format!("Review one {MARKER}"),
                format!("Review two {MARKER}")
            ]),
        ),
        ("stars", json!(4)),
        ("secret", json!(format!("hidden {MARKER}"))),
    ])
}

fn open(run: &mut Run) -> Delivered {
    match run
        .gate
        .submit(&req(1, "web.open", json!({"url": "ref:u1"})))
    {
        Reply::Delivered(d) => d,
        other => panic!("expected delivery, got {other:?}"),
    }
}

fn ledger_text(run: &Run) -> String {
    std::fs::read_to_string(&run.ledger_path).unwrap()
}

fn scored_entry(run: &Run) -> Option<Value> {
    ledger_text(run)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find_map(|v| find_event(&v))
}

fn find_event(v: &Value) -> Option<Value> {
    match v {
        Value::Object(map) => {
            if map.get("event") == Some(&json!("detector_scored")) {
                return Some(v.clone());
            }
            map.values().find_map(find_event)
        }
        Value::Array(items) => items.iter().find_map(find_event),
        _ => None,
    }
}

#[test]
fn a_flagged_field_is_labeled_5_and_lowers_context_trust() {
    let mut page = clean_page();
    page.insert(
        "listing".to_owned(),
        json!(format!("Listing FLAG {MARKER}")),
    );
    let mut run = setup(Some(false), page);
    let d = open(&mut run);
    assert_eq!(d.labels["listing"].trust, DETECTOR_FLAGGED);
    // Unflagged fields keep their region trust.
    assert!(d.labels["editorial"].trust > DETECTOR_FLAGGED);
    assert_eq!(d.labels["reviews"].trust, Trust::new(15));
    assert_eq!(d.min_trust, Some(DETECTOR_FLAGGED));
    assert_eq!(run.gate.context_trust(&task_id()), Some(DETECTOR_FLAGGED));
    let entry = scored_entry(&run).unwrap();
    assert_eq!(entry["flagged"], json!(["listing"]));
    assert_eq!(entry["failed"], json!(false));
    assert_eq!(entry["detector"], json!("fake-guard"));
    assert_eq!(entry["fields"], json!(["editorial", "listing", "reviews"]));
}

#[test]
fn unflagged_fields_keep_their_trust() {
    let mut run = setup(Some(false), clean_page());
    let d = open(&mut run);
    assert_eq!(d.labels["reviews"].trust, Trust::new(15));
    assert!(d.labels["listing"].trust > Trust::new(15));
    assert_eq!(run.gate.context_trust(&task_id()), Some(Trust::new(15)));
    let entry = scored_entry(&run).unwrap();
    assert_eq!(entry["flagged"], json!([]));
    assert!(entry["max_score"].as_f64().unwrap() < 0.5);
}

#[test]
fn a_detector_failure_flags_every_candidate() {
    let mut run = setup(Some(true), clean_page());
    let d = open(&mut run);
    for field in ["listing", "editorial", "reviews"] {
        assert_eq!(d.labels[field].trust, DETECTOR_FLAGGED, "{field}");
    }
    assert_eq!(run.gate.context_trust(&task_id()), Some(DETECTOR_FLAGGED));
    let entry = scored_entry(&run).unwrap();
    assert_eq!(entry["failed"], json!(true));
    assert_eq!(entry["max_score"], Value::Null);
    assert_eq!(entry["flagged"], json!(["editorial", "listing", "reviews"]));
}

#[test]
fn only_free_text_the_plan_reads_is_sent_to_the_detector() {
    let mut run = setup(Some(false), clean_page());
    open(&mut run);
    let mut seen = run.seen.lock().unwrap().clone();
    seen.sort();
    let mut want = vec![
        format!("Listing {MARKER}"),
        format!("Editorial {MARKER}"),
        format!("Review one {MARKER}"),
        format!("Review two {MARKER}"),
    ];
    want.sort();
    // Not the unclassified page (outside `reads`), the hidden field, or the typed `stars`.
    assert_eq!(seen, want);
}

#[test]
fn no_detector_means_no_entry_and_unchanged_output() {
    let mut with_none = setup(None, clean_page());
    let d_none = open(&mut with_none);
    assert!(scored_entry(&with_none).is_none());
    assert!(!ledger_text(&with_none).contains("detector_scored"));
    assert!(with_none.seen.lock().unwrap().is_empty());

    let mut with_fake = setup(Some(false), clean_page());
    let d_fake = open(&mut with_fake);
    // An unflagged detector changes nothing the agent gets.
    assert_eq!(d_none, d_fake);
}

#[test]
fn nothing_scored_means_no_call_and_no_entry() {
    let page = args(&[("page", json!("only unread text")), ("stars", json!(3))]);
    let mut run = setup(Some(false), page);
    open(&mut run);
    assert!(run.seen.lock().unwrap().is_empty());
    assert!(scored_entry(&run).is_none());
}

#[test]
fn neither_the_ledger_nor_the_supervisor_view_holds_scored_text() {
    let mut page = clean_page();
    page.insert(
        "listing".to_owned(),
        json!(format!("Listing FLAG {MARKER}")),
    );
    let mut run = setup(Some(false), page);
    open(&mut run);
    assert!(scored_entry(&run).is_some());
    assert!(
        !ledger_text(&run).contains(MARKER),
        "the ledger holds scored text"
    );

    // A raw destination in a lockdown context parks for review; the view must not carry the page text.
    let ask = req(
        2,
        "email.send",
        json!({"to": ["boss@corp.example"], "subject": "Summary", "body": "Short summary"}),
    );
    let Reply::Pending { request_hash, .. } = run.gate.submit(&ask) else {
        panic!("expected the request to park");
    };
    let view = run.gate.review_view(&task_id(), &request_hash).unwrap();
    let rendered = view.render();
    let serialized = serde_json::to_string(&view).unwrap();
    assert!(!rendered.contains(MARKER), "{rendered}");
    assert!(!serialized.contains(MARKER), "{serialized}");
    assert!(rendered.contains("trust=5"), "{rendered}");
}
