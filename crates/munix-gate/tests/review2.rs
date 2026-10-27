#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Second review pass: what an automatic amendment records and how the Supervisor can tell amended steps from
//! signed ones.

use std::collections::BTreeMap;
use std::path::PathBuf;

use munix_core::crypto::{Purpose, Signed, SigningKey, digest};
use munix_core::ids::TaskId;
use munix_core::manifest::{Catalog, ToolManifest};
use munix_core::plan::{Dlp, Plan};
use munix_core::prompt::PromptEnvelope;
use munix_core::request::Request;
use munix_gate::gate::{Gate, Reply, Store};
use munix_gate::tool::{Tool, ToolFailure};
use munix_gate::vault::{Credential, Vault};
use munix_ledger::{Entry, Ledger};
use serde_json::{Value, json};

const PROBE: &str = "
tool: probe.a
description: A harmless read.
tier: 0
output:
  value: {type: text, region: operator_content, confidential: public}
";
const PING: &str = "
tool: link.ping
description: Ping a link.
tier: 1
egress: true
args:
  url:  {type: url,  role: destination}
  memo: {type: text, role: content, optional: true}
output:
  ack: {type: id, region: operator_content, confidential: internal}
";

type Args = BTreeMap<String, Value>;

fn tool<F>(f: F) -> Box<dyn Tool>
where
    F: Fn(&Args, Option<&Credential>) -> Result<Args, ToolFailure> + Send + Sync + 'static,
{
    Box::new(f)
}

fn task() -> TaskId {
    "T-r2".parse().unwrap()
}

struct Setup {
    gate: Gate,
    dir: PathBuf,
    plan: Signed<Plan>,
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start() -> Setup {
    let key = SigningKey::from_bytes(&[9u8; 32]).unwrap();
    let probe = ToolManifest::from_yaml(PROBE).unwrap();
    let ping = ToolManifest::from_yaml(PING).unwrap();
    let digests = (probe.digest().unwrap(), ping.digest().unwrap());
    let catalog = Catalog::from_manifests([probe, ping]).unwrap();
    let dir = std::env::temp_dir().join(format!("munix-review2-{}", std::process::id()));
    let dir = dir.join(format!("{:?}", std::thread::current().id()).replace(['(', ')'], "_"));
    std::fs::create_dir_all(&dir).unwrap();
    let ledger = Ledger::create(dir.join("ledger.jsonl")).unwrap();
    let mut gate = Gate::new(key.clone(), catalog, Vault::new(), ledger);
    let ok = tool(|_, _| Ok(BTreeMap::from([("value".to_owned(), json!("fine"))])));
    gate.register("probe.a".parse().unwrap(), digests.0, ok)
        .unwrap();
    let ack = tool(|_, _| Ok(BTreeMap::from([("ack".to_owned(), json!("ack-1"))])));
    gate.register("link.ping".parse().unwrap(), digests.1, ack)
        .unwrap();

    let envelope = PromptEnvelope {
        task: task(),
        session: "S-1".parse().unwrap(),
        nonce: "0123456789abcdef".to_owned(),
        text: "Ping https://pixelmart.test:8080/reviews please.".to_owned(),
        data: Vec::new(),
    };
    let prompt = Signed::sign(&key, Purpose::Prompt, envelope.clone()).unwrap();
    let body = Plan::from_yaml(&format!(
        "
plan: P-r2
task: T-r2
prompt_hash: \"{}\"
reads: [operator_content]
steps:
  - id: 1
    tool: probe.a
    args: {{}}
    budget: 2
amendments:
  auto_max_tier: 1
",
        envelope.digest().unwrap().as_str()
    ))
    .unwrap();
    let plan = Signed::sign(&key, Purpose::Plan, body).unwrap();
    let store: Store = BTreeMap::new();
    gate.start_task(&prompt, &plan, &store).unwrap();
    Setup { gate, dir, plan }
}

fn req(step: u32, tool: &str, args: Value) -> Request {
    Request {
        task: task(),
        plan: "P-r2".parse().unwrap(),
        step,
        tool: tool.parse().unwrap(),
        args: serde_json::from_value(args).unwrap(),
    }
}

fn entries(s: &Setup) -> Vec<Value> {
    std::fs::read_to_string(s.dir.join("ledger.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Entry>(l).unwrap().event)
        .collect()
}

#[test]
fn signed_steps_counts_the_signed_plan_and_not_amendments() {
    let mut s = start();
    assert_eq!(s.gate.signed_steps(&task()), Some(1));
    assert_eq!(s.gate.signed_steps(&"T-other".parse().unwrap()), None);
    // An off-plan tier 1 call is amended in: the Gate's plan grows, the signed count does not.
    let ask = req(0, "link.ping", json!({"url": "ref:u1"}));
    let reply = s.gate.submit(&ask);
    assert!(matches!(reply, Reply::Delivered(_)), "{reply:?}");
    assert_eq!(s.gate.plan(&task()).unwrap().steps.len(), 2);
    assert_eq!(s.gate.signed_steps(&task()), Some(1));
}

#[test]
fn the_amended_entry_ties_request_amended_request_and_signed_plan() {
    let mut s = start();
    let ask = req(0, "link.ping", json!({"url": "ref:u1"}));
    assert!(matches!(s.gate.submit(&ask), Reply::Delivered(_)));

    let events = entries(&s);
    let request = events.iter().find(|e| e["event"] == "request").unwrap();
    let amended = events.iter().find(|e| e["event"] == "amended").unwrap();
    let ruling = events.iter().find(|e| e["event"] == "ruling").unwrap();
    let at = |name: &str| events.iter().position(|e| e["event"] == name).unwrap();
    assert!(at("request") < at("amended") && at("amended") < at("ruling"));

    // `request` logged the original hash; `amended` repeats it and adds the rewritten one, which the ruling uses.
    assert_eq!(request["request_hash"], amended["request_hash"]);
    assert_eq!(request["request_hash"], digest(&ask).unwrap().as_str());
    assert_ne!(amended["amended_request_hash"], amended["request_hash"]);
    assert_eq!(amended["amended_request_hash"], ruling["request_hash"]);
    let rewritten = Request { step: 2, ..ask };
    assert_eq!(
        amended["amended_request_hash"],
        digest(&rewritten).unwrap().as_str()
    );
    // The signed plan's digest is the one `task_started` wrote.
    let started = events
        .iter()
        .find(|e| e["event"] == "task_started")
        .unwrap();
    assert_eq!(amended["plan_digest"], started["plan_digest"]);
    assert_eq!(
        amended["plan_digest"],
        s.plan.body.digest().unwrap().as_str()
    );
}

#[test]
fn an_amended_egress_content_argument_gets_no_private_dlp() {
    let mut s = start();
    let ask = req(0, "link.ping", json!({"url": "ref:u1"}));
    assert!(matches!(s.gate.submit(&ask), Reply::Delivered(_)));
    let plan = s.gate.plan(&task()).unwrap();
    let step = plan.steps.last().unwrap();
    assert_eq!(step.args["memo"].dlp, Some(Dlp::NoPrivate));
    assert!(step.args["memo"].may_embed.is_none());
}
