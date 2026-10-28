#![allow(clippy::unwrap_used, clippy::expect_used)]

//! DLP across encodings and splits, ruled on by the real policy with the real email manifest and demo plan.
//! The Gate calls `trace_request` for each request, so these tests run its output through `policy::evaluate`.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use munix_core::context::Band;
use munix_core::label::{Author, Capacity, Confidential, Label, RegionType, Source, Trust};
use munix_core::manifest::ToolManifest;
use munix_core::plan::Plan;
use munix_core::validate::Scalar;
use munix_gate::facts::{ArgFacts, Origin};
use munix_gate::policy::{DenyCode, Facts, Outcome, Ruling, evaluate};
use munix_gate::refs::RefTable;
use munix_gate::trace::trace_request;
use munix_gate::vault::Credential;
use serde_json::{Value, json};

const EMAIL_SEND: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../manifests/email.send.yaml"
));
const DEMO_PLAN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/demo-plan.yaml"
));

const CREDENTIAL: &str = "mail-credential-xyz-0042";
const SALARY: &str = "alice-salary-185000";

fn label(confidential: Confidential) -> Label {
    Label {
        source: Source::Prompt,
        region: RegionType::UserContent,
        author: Author::User,
        trust: Trust::new(20),
        confidential,
        capacity: Capacity::FreeText,
    }
}

/// A table holding the boss's address (trusted, public) and one confidential value from a store.
fn table(value: &str, confidential: Confidential) -> (RefTable, String) {
    let mut refs = RefTable::new();
    let boss = refs.issue(
        "boss@corp.example",
        Scalar::Email,
        Origin::Store {
            name: "contacts".to_owned(),
            key: "boss".to_owned(),
        },
        Label {
            trust: Trust::new(100),
            ..label(Confidential::Public)
        },
    );
    refs.issue(
        value,
        Scalar::Text,
        Origin::Store {
            name: "payroll".to_owned(),
            key: "alice".to_owned(),
        },
        label(confidential),
    );
    (refs, boss.as_str().to_owned())
}

fn rule(refs: &RefTable, boss: &str, subject: &str, body: &str, creds: &[&Credential]) -> Ruling {
    let manifest = ToolManifest::from_yaml(EMAIL_SEND).unwrap();
    let plan = Plan::from_yaml(DEMO_PLAN).unwrap();
    let args: BTreeMap<String, Value> = [
        ("to", json!([boss])),
        ("subject", json!(subject)),
        ("body", json!(body)),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect();
    let facts: BTreeMap<String, ArgFacts> = trace_request(&manifest.args, &args, refs, creds);
    let tool = "email.send".parse().unwrap();
    evaluate(&Facts {
        plan: &plan,
        step: 2,
        tool: &tool,
        manifest: &manifest,
        calls_so_far: 0,
        band: Band::Clean,
        args: &facts,
        hosts: &BTreeMap::new(),
        pins: None,
    })
}

fn assert_confidential_deny(r: &Ruling) {
    assert_eq!(
        r.outcome,
        Outcome::Deny(DenyCode::ConfidentialData),
        "{:?}",
        r.reasons
    );
}

fn percent_encode_all(s: &str) -> String {
    s.bytes().map(|b| format!("%{b:02X}")).collect()
}

#[test]
fn an_honest_email_is_still_allowed() {
    let (refs, boss) = table(SALARY, Confidential::Secret);
    let c = Credential::new(CREDENTIAL);
    let r = rule(
        &refs,
        &boss,
        "Weekly summary",
        "hello%20world, all good",
        &[&c],
    );
    assert_eq!(r.outcome, Outcome::Allow, "{:?}", r.reasons);
}

#[test]
fn a_url_encoded_credential_is_denied() {
    let (refs, boss) = table(SALARY, Confidential::Secret);
    let c = Credential::new(CREDENTIAL);
    let body = format!("see?k={}", percent_encode_all(CREDENTIAL));
    let r = rule(&refs, &boss, "Summary", &body, &[&c]);
    assert_confidential_deny(&r);
    assert!(r.reasons.iter().any(|x| x == "body.credential"));
}

#[test]
fn a_url_encoded_secret_store_value_is_denied() {
    let (refs, boss) = table("alice salary 185000", Confidential::Secret);
    let r = rule(&refs, &boss, "Summary", "x=alice+salary+185000", &[]);
    assert_confidential_deny(&r);
    assert!(r.reasons.iter().any(|x| x == "body.confidential"));
}

#[test]
fn base64_and_hex_of_a_secret_store_value_are_denied() {
    let (refs, boss) = table(SALARY, Confidential::Secret);
    for enc in [STANDARD_NO_PAD.encode(SALARY), hex::encode(SALARY)] {
        let r = rule(&refs, &boss, "Summary", &format!("data: {enc}"), &[]);
        assert_confidential_deny(&r);
    }
}

#[test]
fn a_secret_split_across_subject_and_body_is_denied() {
    let (refs, boss) = table(SALARY, Confidential::Secret);
    let r = rule(&refs, &boss, "Re: alice-salary-", "185000 as agreed", &[]);
    assert_confidential_deny(&r);
}

#[test]
fn a_credential_split_across_subject_and_body_is_denied() {
    let (refs, boss) = table(SALARY, Confidential::Secret);
    let c = Credential::new(CREDENTIAL);
    let (a, b) = CREDENTIAL.split_at(12);
    let r = rule(&refs, &boss, a, b, &[&c]);
    assert_confidential_deny(&r);
    assert!(r.reasons.iter().any(|x| x.ends_with(".credential")));
}

#[test]
fn a_short_value_split_across_arguments_is_not_caught() {
    let (refs, boss) = table("pin1234", Confidential::Secret);
    let r = rule(&refs, &boss, "pin1", "234", &[]);
    assert_eq!(r.outcome, Outcome::Allow, "{:?}", r.reasons);
}

#[test]
fn a_private_value_wholly_in_the_body_does_not_taint_the_subject() {
    let (refs, boss) = table(SALARY, Confidential::Private);
    let manifest = ToolManifest::from_yaml(EMAIL_SEND).unwrap();
    let args: BTreeMap<String, Value> = [
        ("to", json!([boss])),
        ("subject", json!("Weekly summary")),
        ("body", json!(format!("figure: {SALARY}"))),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect();
    let facts = trace_request(&manifest.args, &args, &refs, &[]);
    assert_eq!(facts["body"].confidential, Confidential::Private);
    assert_eq!(facts["subject"].confidential, Confidential::Public);
}
