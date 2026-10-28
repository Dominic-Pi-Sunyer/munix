//! Domain binding: trust says how likely a region is to carry an attack, not who chose a value, so trust alone
//! must not authorize an outgoing tier 3 destination taken from web content. A destination a web page supplied
//! must also name that page's own domain; if it does not, the request is parked for the user (`web_unbound`).
//! Tier 0-2 tools, tools without egress, and prompt and store values are not affected by the rule.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use munix_core::crypto::{Purpose, Signed, SigningKey};
use munix_core::decision::Stage;
use munix_core::ids::TaskId;
use munix_core::manifest::{Catalog, ToolManifest};
use munix_core::plan::Plan;
use munix_core::prompt::PromptEnvelope;
use munix_core::request::Request;
use munix_core::validate::Scalar;
use munix_gate::gate::{Gate, Reply, Store, StoreValue};
use munix_gate::ingest::Delivered;
use munix_gate::policy::DenyCode;
use munix_gate::tool::Tool;
use munix_gate::vault::{Credential, Vault};
use munix_ledger::Ledger;
use serde_json::{Value, json};

const EMAIL_SEND: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../manifests/email.send.yaml"
));

/// Opens the page; its typed fields carry the page's domain.
const PAGE_READ: &str = r"
tool: page.read
description: Read the shop's contact page.
tier: 1
egress: true
args:
  url: {type: url, role: destination}
output:
  contact: {type: email, region: operator_content, confidential: public}
  site:    {type: url,   region: operator_content, confidential: public}
  account: {type: iban,  region: operator_content, confidential: public}
";

/// Tier 3 with egress, url destination.
const WEB_POST: &str = r"
tool: web.post
description: Post a form to a web address.
tier: 3
egress: true
args:
  target: {type: url, role: destination}
  body:   {type: text, role: content, max_len: 200}
output:
  receipt: {type: id, region: operator_content, confidential: internal}
";

/// Tier 3 with egress, iban destination.
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

/// Tier 2 with egress.
const NOTE_SHARE: &str = r"
tool: note.share
description: Share a note by mail.
tier: 2
egress: true
args:
  to:   {type: email, role: destination}
  body: {type: text,  role: content, max_len: 200}
output:
  receipt: {type: id, region: operator_content, confidential: internal}
";

/// Tier 3 without egress (the rule is about outgoing destinations only).
const MAIL_LOCAL: &str = r"
tool: mail.local
description: File a message locally.
tier: 3
args:
  to:   {type: email, role: destination}
  body: {type: text,  role: content, max_len: 200}
output:
  receipt: {type: id, region: operator_content, confidential: internal}
";

type Args = BTreeMap<String, Value>;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn fresh_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("munix-bind-{}-{n}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn task_id() -> TaskId {
    "T-bind".parse().unwrap()
}

fn req(step: u32, tool: &str, args: Value) -> Request {
    Request {
        task: task_id(),
        plan: "P-bind".parse().unwrap(),
        step,
        tool: tool.parse().unwrap(),
        args: serde_json::from_value(args).unwrap(),
    }
}

fn plan_yaml(min_trust: u8) -> String {
    format!(
        r"
plan: P-bind
task: T-bind
prompt_hash: sha256:0000000000000000000000000000000000000000000000000000000000000000
reads: [operator_content]
steps:
  - id: 1
    tool: page.read
    args:
      url: {{from: [prompt]}}
    budget: 3
  - id: 2
    tool: email.send
    args:
      to:          {{from: [prompt, store.contacts.boss, step.1], min_trust: {min_trust}}}
      cc:          {{forbid: true}}
      attachments: {{forbid: true}}
      subject:     {{dlp: no_secret}}
      body:        {{dlp: no_secret}}
    budget: 5
  - id: 3
    tool: web.post
    args:
      target: {{from: [prompt, step.1], min_trust: {min_trust}}}
    budget: 5
  - id: 4
    tool: bank.pay
    args:
      account: {{from: [prompt, step.1], min_trust: {min_trust}}}
    budget: 5
  - id: 5
    tool: note.share
    args:
      to: {{from: [prompt, step.1], min_trust: {min_trust}}}
    budget: 5
  - id: 6
    tool: mail.local
    args:
      to: {{from: [prompt, step.1], min_trust: {min_trust}}}
    budget: 5
amendments:
  auto_max_tier: 1
"
    )
}

struct Run {
    gate: Gate,
    ledger_path: PathBuf,
    /// Every call a send-style tool actually executed: (tool, args).
    sent: Arc<Mutex<Vec<(String, Args)>>>,
    page: Delivered,
}

/// A task that reads `https://{host}/` (the page returns `page`) under a plan with `min_trust`.
fn setup(host: &str, page: Value, min_trust: u8, prompt_extra: &str) -> Run {
    let key = SigningKey::from_bytes(&[9u8; 32]).unwrap();
    let manifests: Vec<ToolManifest> = [
        PAGE_READ, EMAIL_SEND, WEB_POST, BANK_PAY, NOTE_SHARE, MAIL_LOCAL,
    ]
    .iter()
    .map(|y| ToolManifest::from_yaml(y).unwrap())
    .collect();
    let digests: Vec<_> = manifests.iter().map(|m| m.digest().unwrap()).collect();
    let catalog = Catalog::from_manifests(manifests).unwrap();
    let dir = fresh_dir();
    let ledger_path = dir.join("ledger.jsonl");
    let ledger = Ledger::create(&ledger_path).unwrap();
    let vault = Vault::new().with(
        "vault://mail/demo".parse().unwrap(),
        Credential::new("mail-credential-xyz-0042"),
    );
    let mut gate = Gate::new(key.clone(), catalog, vault, ledger);
    let page_args: Args = serde_json::from_value(page).unwrap();
    gate.register(
        "page.read".parse().unwrap(),
        digests[0].clone(),
        Box::new(move |_: &Args, _: Option<&Credential>| Ok(page_args.clone())) as Box<dyn Tool>,
    )
    .unwrap();
    let sent = Arc::new(Mutex::new(Vec::new()));
    for (i, name) in [
        "email.send",
        "web.post",
        "bank.pay",
        "note.share",
        "mail.local",
    ]
    .into_iter()
    .enumerate()
    {
        let log = sent.clone();
        gate.register(
            name.parse().unwrap(),
            digests[i + 1].clone(),
            Box::new(move |a: &Args, _: Option<&Credential>| {
                log.lock().unwrap().push((name.to_owned(), a.clone()));
                let mut out = Args::new();
                let field = if name == "email.send" {
                    "message_id"
                } else {
                    "receipt"
                };
                out.insert(field.to_owned(), json!("r-1"));
                Ok(out)
            }) as Box<dyn Tool>,
        )
        .unwrap();
    }
    let envelope = PromptEnvelope {
        task: task_id(),
        session: "S-1".parse().unwrap(),
        nonce: "0123456789abcdef".to_owned(),
        text: format!("Read https://{host}/ and contact the shop. {prompt_extra}"),
        data: Vec::new(),
    };
    let prompt = Signed::sign(&key, Purpose::Prompt, envelope.clone()).unwrap();
    let mut plan_body = Plan::from_yaml(&plan_yaml(min_trust)).unwrap();
    plan_body.prompt_hash = envelope.digest().unwrap();
    let plan = Signed::sign(&key, Purpose::Plan, plan_body).unwrap();
    let mut store = Store::new();
    store.insert(
        "contacts".to_owned(),
        BTreeMap::from([(
            "boss".to_owned(),
            StoreValue {
                value: "boss@corp.test".to_owned(),
                scalar: Scalar::Email,
                confidential: munix_core::label::Confidential::Public,
            },
        )]),
    );
    gate.start_task(&prompt, &plan, &store).unwrap();
    let page = match gate.submit(&req(1, "page.read", json!({"url": "ref:u1"}))) {
        Reply::Delivered(d) => d,
        other => panic!("expected delivery, got {other:?}"),
    };
    Run {
        gate,
        ledger_path,
        sent,
        page,
    }
}

fn field(run: &Run, name: &str) -> String {
    run.page.fields[name].as_str().unwrap().to_owned()
}

fn email(run: &mut Run, to: &str) -> Reply {
    run.gate.submit(&req(
        2,
        "email.send",
        json!({"to": [to], "subject": "Hi", "body": "Hello."}),
    ))
}

fn post(run: &mut Run, target: &str) -> Reply {
    run.gate
        .submit(&req(3, "web.post", json!({"target": target, "body": "x"})))
}

fn pay(run: &mut Run, account: &str) -> Reply {
    run.gate.submit(&req(
        4,
        "bank.pay",
        json!({"account": account, "memo": "x"}),
    ))
}

fn share(run: &mut Run, to: &str) -> Reply {
    run.gate
        .submit(&req(5, "note.share", json!({"to": to, "body": "x"})))
}

fn wipe(run: &mut Run, to: &str) -> Reply {
    run.gate
        .submit(&req(6, "mail.local", json!({"to": to, "body": "x"})))
}

fn ledger_text(run: &Run) -> String {
    std::fs::read_to_string(&run.ledger_path).unwrap()
}

/// The last logged ruling for `step`: (outcome, reasons).
fn last_ruling(run: &Run, step: u32) -> (String, Vec<String>) {
    let ruling = ledger_text(run)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .flat_map(|v| find_events(&v, "ruling"))
        .rfind(|e| e["step"] == json!(step))
        .unwrap();
    let reasons = ruling["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_owned())
        .collect();
    (ruling["outcome"].as_str().unwrap().to_owned(), reasons)
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

fn has(reasons: &[String], r: &str) -> bool {
    reasons.iter().any(|x| x == r)
}

fn sent_count(run: &Run) -> usize {
    run.sent.lock().unwrap().len()
}

/// Asserts the email to the page's `contact` was parked as unbound, with nothing sent.
fn assert_parked_unbound(run: &Run, reply: &Reply, step: u32) {
    let Reply::Pending { needs, .. } = reply else {
        panic!("expected the request to park, got {reply:?}");
    };
    assert_eq!(*needs, Stage::User);
    let (outcome, reasons) = last_ruling(run, step);
    assert_eq!(outcome, "confirm_user");
    let arg = match step {
        3 => "target",
        4 => "account",
        _ => "to",
    };
    assert!(has(&reasons, &format!("{arg}.web_unbound")), "{reasons:?}");
    assert!(!has(&reasons, &format!("{arg}.trace_ok")), "{reasons:?}");
    assert_eq!(sent_count(run), 0);
}

/// Sends the page's typed contact through `email.send` and reports whether the Gate allowed it.
fn contact_binds(page_host: &str, contact: &str) -> bool {
    let mut run = setup(page_host, json!({"contact": contact}), 60, "");
    let value = field(&run, "contact");
    let reply = email(&mut run, &value);
    let (outcome, reasons) = last_ruling(&run, 2);
    if matches!(reply, Reply::Delivered(_)) {
        assert_eq!(outcome, "allow");
        assert!(has(&reasons, "to.trace_ok"), "{reasons:?}");
        assert_eq!(sent_count(&run), 1);
        true
    } else {
        assert_parked_unbound(&run, &reply, 2);
        false
    }
}

#[test]
fn a_hacked_page_contact_off_the_pages_domain_parks_for_the_user() {
    let mut run = setup(
        "www.store.test",
        json!({"contact": "attacker@evil.test"}),
        60,
        "",
    );
    // Trust passes (operator_content is 85, min_trust 60) and the context is still Clean.
    assert_eq!(run.page.labels["contact"].trust.value(), 85);
    let value = field(&run, "contact");
    let reply = email(&mut run, &value);
    assert_parked_unbound(&run, &reply, 2);
    // The band's own reason is still on record.
    assert!(has(&last_ruling(&run, 2).1, "band.clean"));
}

#[test]
fn a_contact_on_a_parent_of_the_pages_host_is_allowed_as_before() {
    assert!(contact_binds("www.store.test", "support@store.test"));
}

#[test]
fn the_pages_own_host_binds() {
    assert!(contact_binds("www.store.test", "sales@www.store.test"));
    assert!(contact_binds("www.store.test", "sales@WWW.Store.Test"));
}

#[test]
fn a_subdomain_of_the_page_host_binds() {
    assert!(contact_binds("store.test", "a@shop.store.test"));
}

#[test]
fn a_suffix_without_a_dot_does_not_bind() {
    assert!(!contact_binds("store.test", "a@evilstore.test"));
}

#[test]
fn the_page_host_as_a_label_prefix_of_another_domain_does_not_bind() {
    assert!(!contact_binds("store.test", "a@store.test.evil.test"));
}

#[test]
fn a_url_destination_on_the_pages_host_binds_and_another_host_does_not() {
    let mut run = setup(
        "store.test",
        json!({"site": "https://store.test/contact"}),
        60,
        "",
    );
    let value = field(&run, "site");
    let reply = post(&mut run, &value);
    assert!(matches!(reply, Reply::Delivered(_)), "{reply:?}");
    let (outcome, reasons) = last_ruling(&run, 3);
    assert_eq!(outcome, "allow");
    assert!(has(&reasons, "target.trace_ok"), "{reasons:?}");

    let mut run = setup("store.test", json!({"site": "https://evil.test/"}), 60, "");
    let value = field(&run, "site");
    let reply = post(&mut run, &value);
    assert_parked_unbound(&run, &reply, 3);

    // A port and a deeper subdomain on the page's own host still bind.
    let mut run = setup(
        "store.test",
        json!({"site": "https://api.store.test:8443/x"}),
        60,
        "",
    );
    let value = field(&run, "site");
    let reply = post(&mut run, &value);
    assert!(matches!(reply, Reply::Delivered(_)), "{reply:?}");
}

#[test]
fn an_iban_from_a_web_page_has_no_host_and_parks() {
    let mut run = setup(
        "store.test",
        json!({"account": "DE89370400440532013000"}),
        60,
        "",
    );
    let value = field(&run, "account");
    let reply = pay(&mut run, &value);
    assert_parked_unbound(&run, &reply, 4);
}

#[test]
fn prompt_and_store_values_have_no_web_domain_and_are_unaffected() {
    let mut run = setup(
        "store.test",
        json!({"contact": "attacker@evil.test"}),
        60,
        "Also write to ceo@corp.test and pay DE89370400440532013000.",
    );
    // An address typed in the prompt: allowed, whatever page was read.
    let reply = email(&mut run, "ceo@corp.test");
    assert!(matches!(reply, Reply::Delivered(_)), "{reply:?}");
    let (outcome, reasons) = last_ruling(&run, 2);
    assert_eq!(outcome, "allow");
    assert!(has(&reasons, "to.trace_ok"), "{reasons:?}");
    // An address in an operator store: allowed.
    let reply = email(&mut run, "boss@corp.test");
    assert!(matches!(reply, Reply::Delivered(_)), "{reply:?}");
    assert!(has(&last_ruling(&run, 2).1, "to.trace_ok"));
    // An IBAN the user typed: allowed, though an IBAN names no host.
    let reply = pay(&mut run, "DE89370400440532013000");
    assert!(matches!(reply, Reply::Delivered(_)), "{reply:?}");
    assert!(has(&last_ruling(&run, 4).1, "account.trace_ok"));
    assert_eq!(sent_count(&run), 3);
}

#[test]
fn the_rule_does_not_apply_to_tier_2_egress_or_to_tier_3_without_egress() {
    let mut run = setup(
        "www.store.test",
        json!({"contact": "attacker@evil.test"}),
        60,
        "",
    );
    let contact = field(&run, "contact");
    let reply = share(&mut run, &contact);
    assert!(matches!(reply, Reply::Delivered(_)), "{reply:?}");
    let (outcome, reasons) = last_ruling(&run, 5);
    assert_eq!(outcome, "allow");
    assert!(has(&reasons, "to.trace_ok"), "{reasons:?}");
    assert!(!has(&reasons, "to.web_unbound"));

    let reply = wipe(&mut run, &contact);
    assert!(matches!(reply, Reply::Delivered(_)), "{reply:?}");
    let (outcome, reasons) = last_ruling(&run, 6);
    assert_eq!(outcome, "allow");
    assert!(has(&reasons, "to.trace_ok"), "{reasons:?}");
    assert_eq!(sent_count(&run), 2);
}

#[test]
fn a_value_that_fails_the_plain_rule_is_still_a_takeover_not_parked() {
    // Never read from the page and not typed by the user: untraced.
    let mut run = setup("store.test", json!({"contact": "shop@store.test"}), 60, "");
    let reply = email(&mut run, "nobody@store.test");
    assert_eq!(reply, Reply::Takeover(DenyCode::UntrustedDestination));
    assert!(has(&last_ruling(&run, 2).1, "to.trace_untrusted"));
    assert_eq!(sent_count(&run), 0);

    // Traced to the page but below the plan's min_trust (85 < 90): also trace_untrusted, not web_unbound.
    let mut run = setup(
        "store.test",
        json!({"contact": "attacker@evil.test"}),
        90,
        "",
    );
    let value = field(&run, "contact");
    let reply = email(&mut run, &value);
    assert_eq!(reply, Reply::Takeover(DenyCode::UntrustedDestination));
    let reasons = last_ruling(&run, 2).1;
    assert!(has(&reasons, "to.trace_untrusted"), "{reasons:?}");
    assert!(!has(&reasons, "to.web_unbound"), "{reasons:?}");
}

#[test]
fn hosts_never_reach_the_review_view_or_the_ledger_but_the_console_shows_the_address() {
    let page_host = "uniq-page-host-7q3x.test";
    let attacker_host = "uniq-attacker-host-5k2z.test";
    let contact = format!("attacker@{attacker_host}");
    let mut run = setup(page_host, json!({"contact": contact}), 60, "");
    let value = field(&run, "contact");
    let reply = email(&mut run, &value);
    assert_parked_unbound(&run, &reply, 2);
    let Reply::Pending { request_hash, .. } = reply else {
        panic!("expected a parked request");
    };

    // The Supervisor's review view: no host, rendered or serialized.
    let view = run.gate.review_view(&task_id(), &request_hash).unwrap();
    let rendered = view.render();
    let serialized = serde_json::to_string(&view).unwrap();
    for host in [page_host, attacker_host] {
        assert!(!rendered.contains(host), "{rendered}");
        assert!(!serialized.contains(host), "{serialized}");
    }
    assert!(rendered.contains("to.web_unbound"), "{rendered}");

    // The ledger: no host and no address.
    let ledger = ledger_text(&run);
    for host in [page_host, attacker_host] {
        assert!(!ledger.contains(host), "{ledger}");
    }

    // The Console's pending view is the user's own screen: it shows the address and carries the flag.
    let pending = run
        .gate
        .describe_pending(&task_id(), &request_hash)
        .unwrap();
    assert!(pending.web_unbound);
    assert!(
        pending
            .args
            .iter()
            .any(|a| a.name == "to" && a.value.contains(&contact)),
        "{pending:?}"
    );
}

#[test]
fn an_allowed_request_is_not_flagged_web_unbound_on_the_console() {
    // A destination on the page's own domain carries no `web_unbound` reason.
    let mut run = setup("www.store.test", json!({"contact": "a@store.test"}), 60, "");
    let value = field(&run, "contact");
    let reply = email(&mut run, &value);
    assert!(matches!(reply, Reply::Delivered(_)), "{reply:?}");
    assert!(!has(&last_ruling(&run, 2).1, "to.web_unbound"));
}
