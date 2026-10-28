//! Third-party content never binds a tier 3 destination by trust alone, and pins (trust on first use): when the
//! user approves a request that was parked as `web_unbound`, the Gate remembers each destination that did not bind,
//! keyed by `(source, value)`. The same value from the same source binds next time; a different value, or the same
//! value from another source, does not. A pin never rescues a value that fails the plan's `from` or `min_trust`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use munix_core::crypto::{Digest, Purpose, Signed, SigningKey};
use munix_core::decision::{Decision, Stage, Verdict};
use munix_core::ids::TaskId;
use munix_core::manifest::{Catalog, ToolManifest};
use munix_core::plan::Plan;
use munix_core::prompt::PromptEnvelope;
use munix_core::request::Request;
use munix_gate::gate::{Gate, Reply, Store};
use munix_gate::pins::{MAX_PINS, Pins};
use munix_gate::policy::DenyCode;
use munix_gate::tool::Tool;
use munix_gate::vault::{Credential, Vault};
use munix_ledger::Ledger;
use serde_json::{Value, json};

const PAGE_READ: &str = r"
tool: page.read
description: Read the shop's page.
tier: 1
egress: true
args:
  url: {type: url, role: destination}
output:
  account: {type: iban, region: operator_content, confidential: public}
";

/// A mailbox: a stranger's message can carry an account number. No url argument, so its source is the tool.
const INBOX_READ: &str = r"
tool: inbox.read
description: Read the inbox.
tier: 0
args: {}
output:
  iban: {type: iban, region: message, confidential: private}
";

/// The bank's own transaction records: a trusted service's own content, not a web page.
const BANK_RECORDS: &str = r"
tool: bank.records
description: Read the bank's records.
tier: 0
args: {}
output:
  iban: {type: iban, region: operator_content, confidential: private}
";

const BANK_PAY: &str = r"
tool: bank.pay
description: Pay an account.
tier: 3
egress: true
args:
  account: {type: iban, role: destination}
  memo:    {type: text, role: content, max_len: 200}
output:
  receipt: {type: id, region: operator_content, confidential: internal}
";

const STRANGER: &str = "FR1420041010050500013M02606";
const RECORDED: &str = "NL91ABNA0417164300";
const SHOP_A: &str = "DE89370400440532013000";
const SHOP_B: &str = "GB82WEST12345698765432";

type Args = BTreeMap<String, Value>;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("munix-pins-t-{}-{n}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn task_id() -> TaskId {
    "T-pin".parse().unwrap()
}

fn req(step: u32, tool: &str, args: Value) -> Request {
    Request {
        task: task_id(),
        plan: "P-pin".parse().unwrap(),
        step,
        tool: tool.parse().unwrap(),
        args: serde_json::from_value(args).unwrap(),
    }
}

fn plan_yaml(min_trust: u8) -> String {
    format!(
        r"
plan: P-pin
task: T-pin
prompt_hash: sha256:0000000000000000000000000000000000000000000000000000000000000000
reads: [operator_content, message]
steps:
  - id: 1
    tool: page.read
    args:
      url: {{from: [prompt]}}
    budget: 3
  - id: 2
    tool: inbox.read
    args: {{}}
    budget: 3
  - id: 3
    tool: bank.records
    args: {{}}
    budget: 3
  - id: 4
    tool: bank.pay
    args:
      account: {{from: [step.1, step.2, step.3], min_trust: {min_trust}}}
      memo:    {{dlp: no_secret}}
    budget: 9
amendments:
  auto_max_tier: 1
"
    )
}

struct Cfg {
    host: &'static str,
    /// The IBAN the shop page shows.
    page_account: &'static str,
    min_trust: u8,
    /// Steps to run before the test: 1 page, 2 inbox, 3 bank records.
    pre: &'static [u32],
    /// The pin file (pinning is off when `None`).
    pins: Option<PathBuf>,
}

impl Cfg {
    fn new(pre: &'static [u32]) -> Cfg {
        Cfg {
            host: "www.shop-a.test",
            page_account: SHOP_A,
            min_trust: 60,
            pre,
            pins: None,
        }
    }
}

struct Run {
    gate: Gate,
    key: SigningKey,
    ledger_path: PathBuf,
    sent: Arc<Mutex<Vec<Args>>>,
    /// The ref each pre-read step delivered for its account.
    refs: BTreeMap<u32, String>,
}

fn setup(cfg: &Cfg) -> Run {
    let key = SigningKey::from_bytes(&[9u8; 32]).unwrap();
    let manifests: Vec<ToolManifest> = [PAGE_READ, INBOX_READ, BANK_RECORDS, BANK_PAY]
        .iter()
        .map(|y| ToolManifest::from_yaml(y).unwrap())
        .collect();
    let digests: Vec<_> = manifests.iter().map(|m| m.digest().unwrap()).collect();
    let catalog = Catalog::from_manifests(manifests).unwrap();
    let ledger_path = fresh_dir().join("ledger.jsonl");
    let ledger = Ledger::create(&ledger_path).unwrap();
    let mut gate = Gate::new(key.clone(), catalog, Vault::new(), ledger);
    let outputs = [
        ("page.read", json!({"account": cfg.page_account})),
        ("inbox.read", json!({"iban": STRANGER})),
        ("bank.records", json!({"iban": RECORDED})),
    ];
    for (i, (name, out)) in outputs.into_iter().enumerate() {
        let out: Args = serde_json::from_value(out).unwrap();
        gate.register(
            name.parse().unwrap(),
            digests[i].clone(),
            Box::new(move |_: &Args, _: Option<&Credential>| Ok(out.clone())) as Box<dyn Tool>,
        )
        .unwrap();
    }
    let sent = Arc::new(Mutex::new(Vec::new()));
    let log = sent.clone();
    gate.register(
        "bank.pay".parse().unwrap(),
        digests[3].clone(),
        Box::new(move |a: &Args, _: Option<&Credential>| {
            log.lock().unwrap().push(a.clone());
            Ok(Args::from([("receipt".to_owned(), json!("r-1"))]))
        }) as Box<dyn Tool>,
    )
    .unwrap();
    if let Some(path) = &cfg.pins {
        gate.enable_pins(path);
    }
    let envelope = PromptEnvelope {
        task: task_id(),
        session: "S-1".parse().unwrap(),
        nonce: "0123456789abcdef".to_owned(),
        text: format!("Read https://{}/ and pay the invoice.", cfg.host),
        data: Vec::new(),
    };
    let prompt = Signed::sign(&key, Purpose::Prompt, envelope.clone()).unwrap();
    let mut plan_body = Plan::from_yaml(&plan_yaml(cfg.min_trust)).unwrap();
    plan_body.prompt_hash = envelope.digest().unwrap();
    let plan = Signed::sign(&key, Purpose::Plan, plan_body).unwrap();
    gate.start_task(&prompt, &plan, &Store::new()).unwrap();
    let mut refs = BTreeMap::new();
    for step in cfg.pre {
        let (tool, field, args) = match step {
            1 => ("page.read", "account", json!({"url": "ref:u1"})),
            2 => ("inbox.read", "iban", json!({})),
            _ => ("bank.records", "iban", json!({})),
        };
        match gate.submit(&req(*step, tool, args)) {
            Reply::Delivered(d) => {
                refs.insert(*step, d.fields[field].as_str().unwrap().to_owned());
            }
            other => panic!("expected delivery, got {other:?}"),
        }
    }
    Run {
        gate,
        key,
        ledger_path,
        sent,
        refs,
    }
}

fn pay(run: &mut Run, account: &str) -> Reply {
    run.gate.submit(&req(
        4,
        "bank.pay",
        json!({"account": account, "memo": "invoice"}),
    ))
}

/// Pays the account the given pre-read step delivered (by its ref).
fn pay_step(run: &mut Run, step: u32) -> Reply {
    let account = run.refs[&step].clone();
    pay(run, &account)
}

fn user_decision(run: &mut Run, hash: &Digest, verdict: Verdict, reasons: &[&str]) -> Reply {
    let band = run.gate.describe_pending(&task_id(), hash).unwrap().band;
    let decision = Decision {
        verdict,
        request_hash: hash.clone(),
        task: task_id(),
        plan: "P-pin".parse().unwrap(),
        band,
        stage: Stage::User,
        reasons: reasons.iter().map(|r| (*r).to_owned()).collect(),
    };
    let signed = Signed::sign(&run.key, Purpose::UserConfirmation, decision).unwrap();
    run.gate.decide(&signed)
}

fn approve(run: &mut Run, reply: &Reply) -> Reply {
    let Reply::Pending {
        request_hash,
        needs,
    } = reply
    else {
        panic!("expected a parked request, got {reply:?}");
    };
    assert_eq!(*needs, Stage::User);
    user_decision(run, request_hash, Verdict::Approve, &["console.user"])
}

fn ledger_text(run: &Run) -> String {
    std::fs::read_to_string(&run.ledger_path).unwrap()
}

fn events(run: &Run, name: &str) -> Vec<Value> {
    ledger_text(run)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .flat_map(|v| find_events(&v, name))
        .collect()
}

fn find_events(v: &Value, name: &str) -> Vec<Value> {
    match v {
        Value::Object(map) => {
            if map.get("event") == Some(&json!(name)) {
                return vec![v.clone()];
            }
            map.values().flat_map(|x| find_events(x, name)).collect()
        }
        Value::Array(items) => items.iter().flat_map(|x| find_events(x, name)).collect(),
        _ => Vec::new(),
    }
}

/// The reasons of the last ruling for the payment step.
fn pay_reasons(run: &Run) -> Vec<String> {
    let ruling = events(run, "ruling")
        .into_iter()
        .rfind(|e| e["step"] == json!(4))
        .unwrap();
    ruling["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_owned())
        .collect()
}

fn has(reasons: &[String], r: &str) -> bool {
    reasons.iter().any(|x| x == r)
}

fn assert_parked_unbound(run: &Run, reply: &Reply) {
    assert!(
        matches!(
            reply,
            Reply::Pending {
                needs: Stage::User,
                ..
            }
        ),
        "{reply:?}"
    );
    assert!(has(&pay_reasons(run), "account.web_unbound"));
    assert!(run.sent.lock().unwrap().is_empty());
}

fn assert_bound(run: &Run, reply: &Reply) {
    assert!(matches!(reply, Reply::Delivered(_)), "{reply:?}");
    let reasons = pay_reasons(run);
    assert!(has(&reasons, "account.trace_ok"), "{reasons:?}");
    assert!(!has(&reasons, "account.web_unbound"), "{reasons:?}");
}

fn pins_file() -> PathBuf {
    fresh_dir().join("pins.json")
}

fn pinned_cfg(path: &Path, pre: &'static [u32]) -> Cfg {
    Cfg {
        pins: Some(path.to_path_buf()),
        ..Cfg::new(pre)
    }
}

// ---- third-party content from a non-web tool never binds ----

#[test]
fn a_strangers_message_supplies_an_iban_and_the_payment_waits_for_the_user() {
    let mut run = setup(&Cfg::new(&[2]));
    let reply = pay_step(&mut run, 2);
    assert_parked_unbound(&run, &reply);
    assert_eq!(
        events(&run, "ruling").last().unwrap()["outcome"],
        "confirm_user"
    );
}

#[test]
fn the_banks_own_records_still_bind_a_payment() {
    let mut run = setup(&Cfg::new(&[3]));
    let reply = pay_step(&mut run, 3);
    assert_bound(&run, &reply);
    assert_eq!(run.sent.lock().unwrap().len(), 1);
}

// ---- pins ----

#[test]
fn an_approved_destination_binds_next_time_from_the_same_page_and_a_different_one_does_not() {
    let path = pins_file();
    let mut first = setup(&pinned_cfg(&path, &[1]));
    let reply = pay_step(&mut first, 1);
    assert_parked_unbound(&first, &reply);
    let done = approve(&mut first, &reply);
    assert!(matches!(done, Reply::Delivered(_)), "{done:?}");
    assert_eq!(first.sent.lock().unwrap().len(), 1);

    // The ledger records the pin by digest, tool and argument only.
    let added = events(&first, "pin_added");
    assert_eq!(added.len(), 1);
    assert_eq!(
        added[0]["digest"],
        json!(Pins::digest("www.shop-a.test", SHOP_A))
    );
    assert_eq!(added[0]["tool"], "bank.pay");
    assert_eq!(added[0]["arg"], "account");
    assert!(path.exists());

    // Task 2: a fresh Gate, a fresh RefTable, the same pins file, the same page and value.
    let mut second = setup(&pinned_cfg(&path, &[1]));
    let reply = pay_step(&mut second, 1);
    assert_bound(&second, &reply);
    assert_eq!(second.sent.lock().unwrap().len(), 1);

    // Task 3: the page now shows another account. It is not pinned, so the user is asked again.
    let mut third = setup(&Cfg {
        page_account: SHOP_B,
        ..pinned_cfg(&path, &[1])
    });
    let reply = pay_step(&mut third, 1);
    assert_parked_unbound(&third, &reply);
}

#[test]
fn a_pin_from_one_page_does_not_apply_to_the_same_value_from_another_page() {
    let path = pins_file();
    let mut first = setup(&pinned_cfg(&path, &[1]));
    let reply = pay_step(&mut first, 1);
    approve(&mut first, &reply);
    assert_eq!(first.sent.lock().unwrap().len(), 1);

    let mut other = setup(&Cfg {
        host: "www.shop-b.test",
        ..pinned_cfg(&path, &[1])
    });
    let reply = pay_step(&mut other, 1);
    assert_parked_unbound(&other, &reply);
}

#[test]
fn a_third_party_tool_value_can_be_pinned_by_tool_name() {
    let path = pins_file();
    let mut first = setup(&pinned_cfg(&path, &[2]));
    let reply = pay_step(&mut first, 2);
    assert_parked_unbound(&first, &reply);
    approve(&mut first, &reply);
    assert_eq!(first.sent.lock().unwrap().len(), 1);
    let added = events(&first, "pin_added");
    assert_eq!(
        added[0]["digest"],
        json!(Pins::digest("inbox.read", STRANGER))
    );

    let mut second = setup(&pinned_cfg(&path, &[2]));
    let reply = pay_step(&mut second, 2);
    assert_bound(&second, &reply);
}

#[test]
fn a_pin_never_rescues_a_value_below_min_trust() {
    let path = pins_file();
    let mut pins = Pins::load(&path).unwrap();
    pins.add("www.shop-a.test", SHOP_A).unwrap();
    // The page's operator_content is trust 85; this plan wants 90.
    let mut run = setup(&Cfg {
        min_trust: 90,
        ..pinned_cfg(&path, &[1])
    });
    let reply = pay_step(&mut run, 1);
    assert_eq!(reply, Reply::Takeover(DenyCode::UntrustedDestination));
    assert!(has(&pay_reasons(&run), "account.trace_untrusted"));
    assert!(run.sent.lock().unwrap().is_empty());
}

#[test]
fn a_denied_request_pins_nothing_and_neither_does_a_run_with_pinning_off() {
    let path = pins_file();
    let mut run = setup(&pinned_cfg(&path, &[1]));
    let reply = pay_step(&mut run, 1);
    let Reply::Pending { request_hash, .. } = &reply else {
        panic!("{reply:?}");
    };
    user_decision(&mut run, request_hash, Verdict::Deny, &["console.user"]);
    assert!(events(&run, "pin_added").is_empty());
    assert!(!path.exists());

    let mut off = setup(&Cfg::new(&[1]));
    let reply = pay_step(&mut off, 1);
    approve(&mut off, &reply);
    assert_eq!(off.sent.lock().unwrap().len(), 1);
    assert!(events(&off, "pin_added").is_empty());
    assert!(off.gate.pins().is_none());
}

#[test]
fn the_simulated_user_never_creates_pins() {
    let path = pins_file();
    let mut run = setup(&pinned_cfg(&path, &[1]));
    let reply = pay_step(&mut run, 1);
    let Reply::Pending { request_hash, .. } = &reply else {
        panic!("{reply:?}");
    };
    // Even if a decision marked `console.simulated_user` approved it, nothing is remembered.
    user_decision(
        &mut run,
        request_hash,
        Verdict::Approve,
        &["console.simulated_user"],
    );
    assert!(events(&run, "pin_added").is_empty());
    assert!(run.gate.pins().unwrap().is_empty());
    assert!(!path.exists());
}

#[test]
fn a_malformed_pins_file_means_no_pins_and_a_pins_ignored_entry() {
    let path = pins_file();
    // A well-formed file with a pin that would bind, then corrupted.
    let mut pins = Pins::load(&path).unwrap();
    pins.add("www.shop-a.test", SHOP_A).unwrap();
    std::fs::write(&path, r#"{"version":1,"pins":[{"source":"www.shop-a.test""#).unwrap();
    let mut run = setup(&pinned_cfg(&path, &[1]));
    let ignored = events(&run, "pins_ignored");
    assert_eq!(ignored.len(), 1);
    assert_eq!(ignored[0]["reason"], "malformed");
    assert!(run.gate.pins().unwrap().is_empty());
    let reply = pay_step(&mut run, 1);
    assert_parked_unbound(&run, &reply);

    // Unknown fields are malformed too.
    std::fs::write(
        &path,
        format!(
            r#"{{"version":1,"pins":[{{"source":"www.shop-a.test","value":"{SHOP_A}","x":1}}]}}"#
        ),
    )
    .unwrap();
    let run = setup(&pinned_cfg(&path, &[1]));
    assert_eq!(events(&run, "pins_ignored").len(), 1);
}

#[test]
fn a_full_store_refuses_a_new_pin_but_the_approved_request_still_runs() {
    let path = pins_file();
    let pins: Vec<Value> = (0..MAX_PINS)
        .map(|i| json!({"source": "filler.test", "value": format!("v{i}")}))
        .collect();
    std::fs::write(&path, json!({"version": 1, "pins": pins}).to_string()).unwrap();
    let mut run = setup(&pinned_cfg(&path, &[1]));
    assert!(events(&run, "pins_ignored").is_empty());
    let reply = pay_step(&mut run, 1);
    approve(&mut run, &reply);
    assert_eq!(run.sent.lock().unwrap().len(), 1);
    assert!(events(&run, "pin_added").is_empty());
    let refused = events(&run, "pin_refused");
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["reason"], "full");
    assert!(
        !run.gate
            .pins()
            .unwrap()
            .is_pinned("www.shop-a.test", SHOP_A)
    );
}

#[test]
fn pin_strings_never_reach_the_ledger_or_the_review_view() {
    let host = "uniq-pin-host-4m8w.test";
    let path = pins_file();
    let mut run = setup(&Cfg {
        host,
        ..pinned_cfg(&path, &[1])
    });
    let reply = pay_step(&mut run, 1);
    let Reply::Pending { request_hash, .. } = &reply else {
        panic!("{reply:?}");
    };
    let view = run.gate.review_view(&task_id(), request_hash).unwrap();
    let shown = format!("{}{}", view.render(), serde_json::to_string(&view).unwrap());
    approve(&mut run, &reply);
    assert_eq!(events(&run, "pin_added").len(), 1);
    let ledger = ledger_text(&run);
    for secret in [host, SHOP_A] {
        assert!(!shown.contains(secret), "{shown}");
        assert!(!ledger.contains(secret), "{ledger}");
    }
}
