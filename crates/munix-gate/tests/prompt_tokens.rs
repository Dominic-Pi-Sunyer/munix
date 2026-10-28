#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Names and bare hosts the user typed trace to the prompt: an `id` or `text` destination whose value is exactly a
//! whole token of the prompt gets a prompt match. Nothing else changes: `url`, `email`, `iban` and `phone`
//! destinations, content scanning and the brief behave as before.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use munix_core::crypto::{Purpose, Signed, SigningKey};
use munix_core::ids::TaskId;
use munix_core::label::{Author, Capacity, Confidential, Label, RegionType, Source, Trust};
use munix_core::manifest::{Catalog, ToolManifest};
use munix_core::plan::Plan;
use munix_core::prompt::PromptEnvelope;
use munix_core::request::Request;
use munix_core::validate::Scalar;
use munix_gate::facts::{ArgFacts, Origin};
use munix_gate::gate::{Gate, Reply, Store};
use munix_gate::policy::DenyCode;
use munix_gate::refs::RefTable;
use munix_gate::tool::Tool;
use munix_gate::trace::trace_request;
use munix_gate::vault::{Credential, Vault};
use munix_ledger::Ledger;
use serde_json::{Value, json};

const CHAT: &str = "tool: chat.post\ndescription: Post a message in a channel.\ntier: 2\negress: true\nargs:\n  channel: {type: id,   role: destination}\n  site:    {type: text, role: destination, optional: true}\n  link:    {type: url,  role: destination, optional: true}\n  body:    {type: text, role: content, max_len: 4000}\noutput:\n  status: {type: enum, region: operator_content, confidential: public, values: [done]}\n";

fn prompt_label() -> Label {
    Label {
        source: Source::Prompt,
        region: RegionType::UserContent,
        author: Author::User,
        trust: Trust::FULL,
        confidential: Confidential::Internal,
        capacity: Capacity::FreeText,
    }
}

fn table(prompt: &str) -> RefTable {
    // The same split `Gate::start_task` uses, through the real start_task in the end-to-end test below.
    let mut refs = RefTable::new();
    refs.record_prompt_tokens(
        prompt
            .split_whitespace()
            .map(|t| t.trim_matches(|c| "()[]<>\"',.;:!?".contains(c)))
            .filter(|t| !t.is_empty() && t.len() <= 200)
            .map(str::to_owned),
        prompt_label(),
    );
    refs
}

fn trace(refs: &RefTable, args: Value) -> BTreeMap<String, ArgFacts> {
    let manifest = ToolManifest::from_yaml(CHAT).unwrap();
    let args: BTreeMap<String, Value> = serde_json::from_value(args).unwrap();
    trace_request(&manifest.args, &args, refs, &[])
}

fn channel_origin(refs: &RefTable, channel: &str) -> Vec<Origin> {
    trace(refs, json!({"channel": channel, "body": "hi"}))["channel"].values[0]
        .matches
        .iter()
        .map(|m| m.origin.clone())
        .collect()
}

#[test]
fn a_bare_host_typed_in_the_prompt_traces_to_the_prompt() {
    let refs = table("Read the content on webpage www.informations.com.");
    let facts = trace(
        &refs,
        json!({"channel": "x", "site": "www.informations.com", "body": "hi"}),
    );
    let m = &facts["site"].values[0].matches;
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].origin, Origin::Prompt);
    assert_eq!(m[0].trust, Trust::FULL);
    assert_eq!(m[0].id, None);
}

#[test]
fn a_quoted_channel_name_traces() {
    let refs = table("Please post it to the 'general' channel");
    assert_eq!(channel_origin(&refs, "general"), vec![Origin::Prompt]);
}

#[test]
fn matching_is_exact_and_case_sensitive() {
    let refs = table("send it to Alice");
    assert_eq!(channel_origin(&refs, "Alice"), vec![Origin::Prompt]);
    assert!(channel_origin(&refs, "alice").is_empty());
    assert!(channel_origin(&refs, "Alic").is_empty());
    assert!(channel_origin(&refs, "Alice ").is_empty());
}

#[test]
fn a_prefix_the_prompt_describes_does_not_trace_a_longer_name() {
    let refs = table("Add Charlie to the channel starting with External");
    assert!(channel_origin(&refs, "External_0").is_empty());
    assert_eq!(channel_origin(&refs, "External"), vec![Origin::Prompt]);
}

#[test]
fn a_url_destination_still_needs_a_scheme_url_in_the_prompt() {
    let refs = table("Read www.informations.com please");
    let facts = trace(
        &refs,
        json!({"channel": "x", "link": "www.informations.com", "body": "hi"}),
    );
    assert!(facts["link"].values[0].matches.is_empty());
}

#[test]
fn content_text_with_prompt_words_gets_no_new_facts() {
    let body = "Alice general www.informations.com External please read";
    let with = table("send it to Alice in general via www.informations.com External");
    let without = RefTable::new();
    let a = trace(&with, json!({"channel": "x", "body": body}));
    let b = trace(&without, json!({"channel": "x", "body": body}));
    assert_eq!(a["body"], b["body"]);
    assert!(a["body"].embedded.is_empty());
    assert_eq!(a["body"].confidential, Confidential::Public);
    assert!(with.find_value("Alice").is_empty());
    assert!(with.is_empty());
}

#[test]
fn a_low_trust_output_that_equals_a_prompt_token_traces_with_both_matches() {
    let mut refs = table("send it to Alice");
    let low = Label {
        source: Source::Prompt,
        region: RegionType::UgcPost,
        author: Author::Unknown,
        trust: Trust::new(15),
        confidential: Confidential::Public,
        capacity: Capacity::FreeText,
    };
    let origin = Origin::Step {
        step: 1,
        field: "names".to_owned(),
    };
    refs.issue("Alice", Scalar::Id, origin.clone(), low);
    let facts = trace(&refs, json!({"channel": "Alice", "body": "hi"}));
    let t = &facts["channel"].values[0];
    assert_eq!(t.matches.len(), 2);
    assert_eq!(t.matches[0].origin, origin);
    assert_eq!(t.matches[0].trust, Trust::new(15));
    assert_eq!(t.matches[1].origin, Origin::Prompt);
    let prompt = [munix_core::plan::SourcePath::Prompt];
    assert!(t.satisfies(&prompt, Some(Trust::new(60))));
    let step = [munix_core::plan::SourcePath::Step {
        step: 1,
        field: None,
    }];
    assert!(!t.satisfies(&step, Some(Trust::new(60))));
}

// ---- end to end through the Gate ----

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn gate_with_task(prompt_text: &str) -> (Gate, TaskId) {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir: PathBuf =
        std::env::temp_dir().join(format!("munix-prompt-tokens-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key = SigningKey::from_bytes(&[7u8; 32]).unwrap();
    let chat = ToolManifest::from_yaml(CHAT).unwrap();
    let digest = chat.digest().unwrap();
    let catalog = Catalog::from_manifests([chat]).unwrap();
    let ledger = Ledger::create(dir.join("ledger.jsonl")).unwrap();
    let mut gate = Gate::new(key.clone(), catalog, Vault::new(), ledger);
    let imp: Box<dyn Tool> = Box::new(|_: &BTreeMap<String, Value>, _: Option<&Credential>| {
        Ok(BTreeMap::from([("status".to_owned(), json!("done"))]))
    });
    gate.register("chat.post".parse().unwrap(), digest, imp)
        .unwrap();
    let task: TaskId = "T-chat".parse().unwrap();
    let envelope = PromptEnvelope {
        task: task.clone(),
        session: "S-1".parse().unwrap(),
        nonce: "0123456789abcdef".to_owned(),
        text: prompt_text.to_owned(),
        data: Vec::new(),
    };
    let prompt = Signed::sign(&key, Purpose::Prompt, envelope.clone()).unwrap();
    let plan_yaml = "plan: P-chat\ntask: T-chat\nprompt_hash: sha256:0000000000000000000000000000000000000000000000000000000000000000\nreads: [operator_content]\nsteps:\n  - id: 1\n    tool: chat.post\n    args:\n      channel: {from: [prompt]}\n      site: {forbid: true}\n      link: {forbid: true}\n      body: {dlp: no_secret}\n    budget: 2\namendments:\n  auto_max_tier: 1\n";
    let mut body = Plan::from_yaml(plan_yaml).unwrap();
    body.prompt_hash = envelope.digest().unwrap();
    let plan = Signed::sign(&key, Purpose::Plan, body).unwrap();
    let brief = gate.start_task(&prompt, &plan, &Store::new()).unwrap();
    // The brief lists no prompt-token refs.
    assert!(brief.refs.is_empty());
    (gate, task)
}

fn post(task: &TaskId, channel: &str) -> Request {
    Request {
        task: task.clone(),
        plan: "P-chat".parse().unwrap(),
        step: 1,
        tool: "chat.post".parse().unwrap(),
        args: serde_json::from_value(json!({"channel": channel, "body": "hello"})).unwrap(),
    }
}

#[test]
fn a_prompt_word_destination_is_allowed_end_to_end() {
    let (mut gate, task) = gate_with_task("Post the summary to the 'general' channel.");
    assert!(matches!(
        gate.submit(&post(&task, "general")),
        Reply::Delivered(_)
    ));
}

#[test]
fn a_word_not_in_the_prompt_is_untrusted_end_to_end() {
    let (mut gate, task) = gate_with_task("Post the summary to the 'general' channel.");
    assert_eq!(
        gate.submit(&post(&task, "External_0")),
        Reply::Takeover(DenyCode::UntrustedDestination)
    );
}

#[test]
fn a_scheme_in_front_of_a_typed_host_still_traces_but_nothing_after_it() {
    let refs = table("Read the content on webpage www.informations.com.");
    let site = |v: &str| {
        trace(&refs, json!({"channel": "x", "site": v, "body": "hi"}))["site"].values[0]
            .matches
            .len()
    };
    assert_eq!(site("https://www.informations.com"), 1);
    assert_eq!(site("HTTP://www.informations.com/"), 1);
    assert_eq!(site("https://www.informations.com//"), 0);
    assert_eq!(site("https://www.informations.com/x"), 0);
    assert_eq!(site("https://www.informations.com?q=1"), 0);
    assert_eq!(site("ftp://www.informations.com"), 0);
    assert_eq!(site("https://"), 0);
}
