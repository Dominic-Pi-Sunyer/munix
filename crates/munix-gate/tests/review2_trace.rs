#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Review 2 fixes in the tracer: non-string selectors are traced to the step that delivered them (and denied when
//! nothing did), normalization uses Unicode white space, and the split check fails closed on size and checks
//! every ordered pair of pieces. Selector tests run the real ingest, tracer and policy.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use munix_core::context::Band;
use munix_core::label::{Author, Capacity, Confidential, Label, RegionType, Source, Trust};
use munix_core::manifest::{ArgSpec, ToolManifest};
use munix_core::plan::Plan;
use munix_core::validate::Scalar;
use munix_gate::facts::{ArgFacts, Origin};
use munix_gate::ingest::ingest;
use munix_gate::policy::{DenyCode, Facts, Outcome, Ruling, evaluate};
use munix_gate::refs::RefTable;
use munix_gate::trace::trace_request;
use serde_json::{Value, json};

const LIST: &str = "tool: bank.list\ndescription: List scheduled transactions.\ntier: 0\noutput:\n  ids: {type: \"int[]\", region: operator_content}\n  note: {type: text, region: ugc_review}\n  review_ids: {type: \"int[]\", region: ugc_review}\n  mode: {type: enum, values: [daily, weekly], region: operator_content}\n";
const UPDATE: &str = "tool: bank.update\ndescription: Change one scheduled transaction.\ntier: 1\nargs:\n  id:     {type: int, role: selector}\n  ids:    {type: \"int[]\", role: selector, optional: true}\n  mode:   {type: enum, role: selector, values: [daily, weekly], optional: true}\n  amount: {type: number, role: control}\n";
const PLAN: &str = "plan: P-bank\ntask: T-bank\nprompt_hash: sha256:0000000000000000000000000000000000000000000000000000000000000000\nreads: [operator_content, ugc_review]\nsteps:\n  - id: 1\n    tool: bank.list\n    args: {}\n    budget: 3\n  - id: 2\n    tool: bank.update\n    args:\n      id:   {from: [step.1.ids], min_trust: 60}\n      ids:  {from: [step.1.ids], min_trust: 60}\n      mode: {from: [step.1.mode]}\n    budget: 3\namendments:\n  auto_max_tier: 1\n";

fn deliver(refs: &mut RefTable, fields: &[(&str, Value)]) {
    let manifest = ToolManifest::from_yaml(LIST).unwrap();
    let reads: BTreeSet<RegionType> = [RegionType::OperatorContent, RegionType::UgcReview].into();
    let output = fields
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    let source = Source::Tool {
        tool: "bank.list".parse().unwrap(),
    };
    ingest(
        &manifest,
        1,
        &source,
        &reads,
        output,
        &BTreeSet::new(),
        refs,
    )
    .unwrap();
}

fn rule_update(refs: &RefTable, args: &[(&str, Value)]) -> Ruling {
    let manifest = ToolManifest::from_yaml(UPDATE).unwrap();
    let plan = Plan::from_yaml(PLAN).unwrap();
    let args: BTreeMap<String, Value> = args
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    let facts: BTreeMap<String, ArgFacts> = trace_request(&manifest.args, &args, refs, &[]);
    let tool = "bank.update".parse().unwrap();
    evaluate(&Facts {
        plan: &plan,
        step: 2,
        tool: &tool,
        manifest: &manifest,
        calls_so_far: 0,
        band: Band::Clean,
        args: &facts,
    })
}

#[test]
fn an_int_selector_delivered_by_an_earlier_step_passes() {
    let mut refs = RefTable::new();
    deliver(&mut refs, &[("ids", json!([7, 9]))]);
    let r = rule_update(&refs, &[("id", json!(9)), ("amount", json!(1.5))]);
    assert_eq!(r.outcome, Outcome::Allow, "{:?}", r.reasons);
    assert!(r.reasons.iter().any(|x| x == "id.trace_ok"));
    // Every element of a list selector must have been delivered.
    let r = rule_update(
        &refs,
        &[
            ("id", json!(7)),
            ("ids", json!([7, 9])),
            ("amount", json!(1)),
        ],
    );
    assert_eq!(r.outcome, Outcome::Allow, "{:?}", r.reasons);
}

#[test]
fn an_int_selector_no_step_delivered_is_denied() {
    let mut refs = RefTable::new();
    deliver(&mut refs, &[("ids", json!([7, 9]))]);
    for args in [
        vec![("id", json!(8)), ("amount", json!(1))],
        vec![
            ("id", json!(7)),
            ("ids", json!([7, 8])),
            ("amount", json!(1)),
        ],
        // The right digits as another type are a different value.
        vec![("id", json!(7.5)), ("amount", json!(1))],
    ] {
        let r = rule_update(&refs, &args);
        assert_eq!(
            r.outcome,
            Outcome::Deny(DenyCode::UntrustedDestination),
            "{args:?} {:?}",
            r.reasons
        );
    }
    // Nothing delivered at all.
    let r = rule_update(&RefTable::new(), &[("id", json!(7)), ("amount", json!(1))]);
    assert_eq!(r.outcome, Outcome::Deny(DenyCode::UntrustedDestination));
    assert!(r.reasons.iter().any(|x| x == "id.trace_untrusted"));
}

#[test]
fn an_int_delivered_by_a_low_trust_region_is_denied_below_min_trust() {
    let mut refs = RefTable::new();
    // `review_ids` come from step 1 but from a review (trust 30), and the rule wants 60 and field `ids`.
    deliver(&mut refs, &[("review_ids", json!([5]))]);
    let r = rule_update(&refs, &[("id", json!(5)), ("amount", json!(1))]);
    assert_eq!(r.outcome, Outcome::Deny(DenyCode::UntrustedDestination));
    // The same value also delivered by a trusted field passes: one good origin is enough.
    deliver(&mut refs, &[("ids", json!([5]))]);
    let r = rule_update(&refs, &[("id", json!(5)), ("amount", json!(1))]);
    assert_eq!(r.outcome, Outcome::Allow, "{:?}", r.reasons);
}

#[test]
fn a_low_trust_field_with_the_right_name_still_fails_min_trust() {
    // Same field name as the rule, but delivered at trust 30 by a review region.
    let mut refs = RefTable::new();
    refs.record_scalar(
        &json!(5),
        Origin::Step {
            step: 1,
            field: "ids".to_owned(),
        },
        Label {
            region: RegionType::UgcReview,
            trust: Trust::new(30),
            ..label()
        },
    );
    let r = rule_update(&refs, &[("id", json!(5)), ("amount", json!(1))]);
    assert_eq!(r.outcome, Outcome::Deny(DenyCode::UntrustedDestination));
}

#[test]
fn enum_selectors_are_traced_too_and_prompt_numerals_are_not_recorded() {
    let mut refs = RefTable::new();
    deliver(&mut refs, &[("mode", json!("weekly")), ("ids", json!([1]))]);
    let ok = rule_update(
        &refs,
        &[
            ("id", json!(1)),
            ("mode", json!("weekly")),
            ("amount", json!(1)),
        ],
    );
    assert_eq!(ok.outcome, Outcome::Allow, "{:?}", ok.reasons);
    let bad = rule_update(
        &refs,
        &[
            ("id", json!(1)),
            ("mode", json!("daily")),
            ("amount", json!(1)),
        ],
    );
    assert_eq!(bad.outcome, Outcome::Deny(DenyCode::UntrustedDestination));
    // Only tool outputs are recorded: a table built from the prompt has no scalars.
    let mut prompt_only = RefTable::new();
    prompt_only.issue("42", Scalar::Text, Origin::Prompt, label());
    assert!(prompt_only.find_scalar(&json!(42)).is_empty());
}

#[test]
fn string_tracing_is_unchanged() {
    let mut refs = RefTable::new();
    let id = refs.issue(
        "boss@corp.example",
        Scalar::Email,
        Origin::Store {
            name: "contacts".to_owned(),
            key: "boss".to_owned(),
        },
        Label {
            trust: Trust::new(100),
            ..label()
        },
    );
    let specs: BTreeMap<String, ArgSpec> =
        BTreeMap::from([("to".to_owned(), spec("email[]", "destination"))]);
    let args = BTreeMap::from([("to".to_owned(), json!([id.as_str(), "evil@x.test"]))]);
    let facts = trace_request(&specs, &args, &refs, &[]);
    let values = &facts["to"].values;
    assert_eq!(values.len(), 2);
    assert_eq!(values[0].matches.len(), 1);
    assert!(values[1].matches.is_empty());
}

// ---- DLP: Unicode white space and the split check ----

fn label() -> Label {
    Label {
        source: Source::Prompt,
        region: RegionType::UserContent,
        author: Author::User,
        trust: Trust::new(20),
        confidential: Confidential::Public,
        capacity: Capacity::FreeText,
    }
}

fn secret_label() -> Label {
    Label {
        confidential: Confidential::Secret,
        ..label()
    }
}

fn spec(ty: &str, role: &str) -> ArgSpec {
    serde_json::from_value(json!({"type": ty, "role": role})).unwrap()
}

fn store(key: &str) -> Origin {
    Origin::Store {
        name: "payroll".to_owned(),
        key: key.to_owned(),
    }
}

fn text_specs(names: &[String]) -> BTreeMap<String, ArgSpec> {
    names
        .iter()
        .map(|n| (n.clone(), spec("text", "content")))
        .collect()
}

#[test]
fn a_value_with_unicode_spaces_inserted_is_still_caught() {
    let mut refs = RefTable::new();
    refs.issue(
        "alice-salary-185000",
        Scalar::Text,
        store("alice"),
        secret_label(),
    );
    let specs = text_specs(&["body".to_owned()]);
    for gap in ['\u{a0}', '\u{2003}', '\u{3000}', '\u{2009}'] {
        let spaced: String = "alice-salary-185000"
            .chars()
            .flat_map(|c| [c, gap])
            .collect();
        let args = BTreeMap::from([("body".to_owned(), json!(format!("see {spaced} ok")))]);
        let facts = trace_request(&specs, &args, &refs, &[]);
        assert_eq!(facts["body"].confidential, Confidential::Secret, "{gap:?}");
    }
}

const BUDGET: Duration = Duration::from_secs(2);

#[test]
fn a_request_over_the_size_bound_is_raised_to_secret() {
    let mut refs = RefTable::new();
    refs.issue(
        "alice-salary-185000",
        Scalar::Text,
        store("alice"),
        secret_label(),
    );
    let names = vec!["a".to_owned(), "b".to_owned()];
    let specs = text_specs(&names);
    let pad = "z".repeat(40 * 1024);
    let args = BTreeMap::from([
        ("a".to_owned(), json!(format!("alice-salary-{pad}"))),
        ("b".to_owned(), json!(format!("{pad}185000"))),
    ]);
    let started = Instant::now();
    let facts = trace_request(&specs, &args, &refs, &[]);
    assert!(started.elapsed() < BUDGET);
    for name in &names {
        assert_eq!(facts[name].confidential, Confidential::Secret);
        assert!(facts[name].split_unchecked);
    }
    // One huge piece alone is not a split: nothing to join, nothing raised.
    let one = BTreeMap::from([("a".to_owned(), json!("z".repeat(70 * 1024)))]);
    let facts = trace_request(&specs, &one, &refs, &[]);
    assert_eq!(facts["a"].confidential, Confidential::Public);
    assert!(!facts["a"].split_unchecked);
    // A small request is unaffected.
    let small = BTreeMap::from([
        ("a".to_owned(), json!("hi")),
        ("b".to_owned(), json!("there")),
    ]);
    let facts = trace_request(&specs, &small, &refs, &[]);
    assert_eq!(facts["a"].confidential, Confidential::Public);
    assert!(!facts["b"].split_unchecked);
}

#[test]
fn the_policy_denies_an_oversize_request_with_a_fixed_reason() {
    let manifest = ToolManifest::from_yaml(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../manifests/email.send.yaml"
    )))
    .unwrap();
    let plan = Plan::from_yaml(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/demo-plan.yaml"
    )))
    .unwrap();
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
            ..label()
        },
    );
    let pad = "z".repeat(33 * 1024);
    let args: BTreeMap<String, Value> = BTreeMap::from([
        ("to".to_owned(), json!([boss.as_str()])),
        ("subject".to_owned(), json!("Summary")),
        ("body".to_owned(), json!(format!("{pad}\n{pad}"))),
    ]);
    let facts = trace_request(&manifest.args, &args, &refs, &[]);
    let tool = "email.send".parse().unwrap();
    let r = evaluate(&Facts {
        plan: &plan,
        step: 2,
        tool: &tool,
        manifest: &manifest,
        calls_so_far: 0,
        band: Band::Clean,
        args: &facts,
    });
    assert_eq!(r.outcome, Outcome::Deny(DenyCode::ConfidentialData));
    assert!(r.reasons.iter().any(|x| x == "body.split_unchecked"));
}

#[test]
fn a_split_across_two_of_many_pieces_is_found_in_any_order() {
    let mut refs = RefTable::new();
    refs.issue(
        "alice-salary-185000",
        Scalar::Text,
        store("alice"),
        secret_label(),
    );
    let names: Vec<String> = (0..8).map(|i| format!("p{i}")).collect();
    let specs = text_specs(&names);
    let (head, tail) = "alice-salary-185000".split_at(11);
    // The halves sit in two arguments that are neither neighbours nor in name order or its reverse.
    for (first, second, sep) in [(5usize, 2usize, ""), (6, 1, " "), (3, 4, "")] {
        let mut args: BTreeMap<String, Value> = names
            .iter()
            .map(|n| (n.clone(), json!("filler text")))
            .collect();
        args.insert(names[first].clone(), json!(format!("note: {head}")));
        args.insert(names[second].clone(), json!(format!("{tail}{sep}")));
        // `head` then `tail` is the reading order only for the pair (first, second).
        let facts = trace_request(&specs, &args, &refs, &[]);
        assert!(
            names
                .iter()
                .all(|n| facts[n].confidential == Confidential::Secret),
            "{first} {second}"
        );
    }
    // Pieces that do not form the value leave everything public.
    let args: BTreeMap<String, Value> = names
        .iter()
        .map(|n| (n.clone(), json!("filler text")))
        .collect();
    let facts = trace_request(&specs, &args, &refs, &[]);
    assert!(
        names
            .iter()
            .all(|n| facts[n].confidential == Confidential::Public)
    );
}

#[test]
fn a_space_joined_split_across_many_pieces_is_found() {
    let mut refs = RefTable::new();
    refs.issue(
        "alice salary 185000",
        Scalar::Text,
        store("alice"),
        secret_label(),
    );
    let names: Vec<String> = (0..6).map(|i| format!("p{i}")).collect();
    let specs = text_specs(&names);
    let mut args: BTreeMap<String, Value> =
        names.iter().map(|n| (n.clone(), json!("filler"))).collect();
    args.insert("p4".to_owned(), json!("alice salary"));
    args.insert("p1".to_owned(), json!("185000"));
    let facts = trace_request(&specs, &args, &refs, &[]);
    assert_eq!(facts["p0"].confidential, Confidential::Secret);
}

#[test]
fn a_hundred_pieces_within_the_bound_are_checked_quickly() {
    let mut refs = RefTable::new();
    for i in 0..60 {
        let level = if i % 2 == 0 {
            Confidential::Secret
        } else {
            Confidential::Private
        };
        refs.issue(
            &format!("confidential-value-number-{i:04}-padding"),
            Scalar::Text,
            store(&format!("k{i}")),
            Label {
                confidential: level,
                ..label()
            },
        );
    }
    let names: Vec<String> = (0..100).map(|i| format!("p{i:03}")).collect();
    let specs = text_specs(&names);
    // About 60 KiB in total, in 100 pieces of 600 bytes.
    let filler = "lorem ipsum dolor sit amet ".repeat(22);
    let args: BTreeMap<String, Value> = names.iter().map(|n| (n.clone(), json!(filler))).collect();
    let total: usize = args.values().map(|v| v.as_str().unwrap().len()).sum();
    assert!((50_000..=64 * 1024).contains(&total), "{total}");
    let started = Instant::now();
    let facts = trace_request(&specs, &args, &refs, &[]);
    let took = started.elapsed();
    assert!(took < BUDGET, "{took:?}");
    assert!(
        facts
            .values()
            .all(|f| f.confidential == Confidential::Public && !f.split_unchecked)
    );
    // And it finds a split among the hundred.
    let value = "confidential-value-number-0000-padding";
    let (head, tail) = value.split_at(20);
    let mut args = args;
    args.insert(
        "p077".to_owned(),
        json!(format!("{}{head}", "x".repeat(300))),
    );
    args.insert(
        "p013".to_owned(),
        json!(format!("{tail}{}", "y".repeat(300))),
    );
    let started = Instant::now();
    let facts = trace_request(&specs, &args, &refs, &[]);
    assert!(started.elapsed() < BUDGET, "{:?}", started.elapsed());
    assert_eq!(facts["p000"].confidential, Confidential::Secret);
}
