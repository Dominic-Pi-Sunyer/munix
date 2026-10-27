#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Regression tests for the review-hardening pass: bounded tracing cost, normalized DLP matching, the
//! quarantine rule changes and core's default length cap.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use munix_core::label::{Author, Capacity, Confidential, Label, RegionType, Source, Trust};
use munix_core::manifest::ArgSpec;
use munix_core::request::{DEFAULT_MAX_TEXT_LEN, ViolationCode, check_arg_value};
use munix_core::validate::Scalar;
use munix_gate::facts::Origin;
use munix_gate::quarantine::{Cause, Item, choose, item_hash};
use munix_gate::refs::RefTable;
use munix_gate::trace::{raw_destinations, trace_arg, trace_request};
use munix_gate::vault::Credential;
use serde_json::{Value, json};

fn spec(ty: &str, role: &str) -> ArgSpec {
    serde_json::from_value(json!({"type": ty, "role": role})).unwrap()
}

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

fn store(key: &str) -> Origin {
    Origin::Store {
        name: "contacts".to_owned(),
        key: key.to_owned(),
    }
}

const BUDGET: Duration = Duration::from_secs(2);
const BIG: usize = 200_000;

// ---- bounded cost of the raw-destination tokenizer ----

#[test]
fn a_glued_run_of_scheme_urls_is_counted_but_stored_once() {
    let token = "x://".repeat(BIG / 4);
    let started = Instant::now();
    let facts = trace_arg(
        &spec("text", "content"),
        &json!(token),
        &RefTable::new(),
        &[],
    );
    let count = raw_destinations(&token);
    assert!(started.elapsed() < BUDGET, "{:?}", started.elapsed());
    // Every `://` that has something after it still counts; the last one has nothing after it.
    let expected = u32::try_from(BIG / 4 - 1).unwrap();
    assert_eq!(facts.raw_destinations, expected);
    assert_eq!(count, expected);
    assert!(facts.embedded.is_empty());
    // The same glued URL made of a known value is traced once, not once per `://`.
    let mut refs = RefTable::new();
    let glued = "x://x://x://x";
    refs.issue(
        glued,
        Scalar::Text,
        Origin::Prompt,
        label(Confidential::Public),
    );
    let facts = trace_arg(&spec("text", "content"), &json!(glued), &refs, &[]);
    assert_eq!(facts.raw_destinations, 0);
    assert_eq!(facts.embedded.len(), 1);
}

#[test]
fn a_long_run_of_email_addresses_in_one_token_is_traced_fast() {
    let token = "a@b.c".repeat(BIG / 5);
    let started = Instant::now();
    let facts = trace_arg(
        &spec("text", "content"),
        &json!(token),
        &RefTable::new(),
        &[],
    );
    assert!(started.elapsed() < BUDGET, "{:?}", started.elapsed());
    assert!(facts.raw_destinations > 0);
    // Counted at most once per `@`.
    assert!(facts.raw_destinations as usize <= BIG / 5);
    assert!(facts.embedded.is_empty());
}

#[test]
fn a_long_host_run_and_dotted_runs_are_traced_fast() {
    for token in [
        "a.".repeat(BIG / 2),
        "a-".repeat(BIG / 2),
        format!("{}@evil.com", "a".repeat(BIG)),
        "@".repeat(BIG),
    ] {
        let started = Instant::now();
        let _ = raw_destinations(&token);
        assert!(started.elapsed() < BUDGET, "{:?}", started.elapsed());
    }
}

// ---- normalized DLP ----

fn boss_table(level: Confidential) -> RefTable {
    let mut refs = RefTable::new();
    refs.issue(
        "boss@corp.example",
        Scalar::Email,
        store("boss"),
        label(level),
    );
    refs
}

#[test]
fn copies_that_differ_in_case_or_spacing_are_still_confidential() {
    let refs = boss_table(Confidential::Private);
    let content = spec("text", "content");
    for text in [
        "Forward to boss@corp.example",
        "Forward to BOSS@CORP.EXAMPLE",
        "Forward to Boss@Corp.Example",
        "Forward to b o s s@corp.example",
        "Forward to boss @ corp . example",
        "Forward to b\u{200b}o\u{200b}s\u{200b}s@corp.example",
        "Forward to bo\u{ad}ss@corp.example",
        "Forward to boss@\ncorp.example",
    ] {
        let facts = trace_arg(&content, &json!(text), &refs, &[]);
        assert_eq!(facts.confidential, Confidential::Private, "{text:?}");
    }
    let facts = trace_arg(
        &content,
        &json!("Forward to somebody@else.example"),
        &refs,
        &[],
    );
    assert_eq!(facts.confidential, Confidential::Public);
}

#[test]
fn normalized_matching_raises_to_the_entrys_own_level_and_needs_six_characters() {
    let content = spec("text", "content");
    let refs = boss_table(Confidential::Secret);
    let facts = trace_arg(&content, &json!("B O S S@CORP.EXAMPLE"), &refs, &[]);
    assert_eq!(facts.confidential, Confidential::Secret);
    // A value under six characters is not looked for in any form.
    let mut short = RefTable::new();
    short.issue(
        "pin 7",
        Scalar::Text,
        store("pin"),
        label(Confidential::Secret),
    );
    let facts = trace_arg(&content, &json!("the PIN7 is out"), &short, &[]);
    assert_eq!(facts.confidential, Confidential::Public);
}

#[test]
fn credentials_are_found_case_and_space_insensitively() {
    let content = spec("text", "content");
    let c = Credential::new("Mail-Credential-XYZ-0042");
    for text in [
        "key: Mail-Credential-XYZ-0042",
        "key: mail-credential-xyz-0042",
        "key: MAIL-CREDENTIAL-XYZ-0042",
        "key: mail -credential - xyz-0042",
        "key: m a i l-credential-xyz-0042",
    ] {
        let facts = trace_arg(&content, &json!(text), &RefTable::new(), &[&c]);
        assert!(facts.contains_credential, "{text:?}");
    }
    let facts = trace_arg(&content, &json!("key: nothing"), &RefTable::new(), &[&c]);
    assert!(!facts.contains_credential);
}

// ---- the cost of trace_request ----

fn four_text_specs() -> BTreeMap<String, ArgSpec> {
    ["a", "b", "c", "d"]
        .into_iter()
        .map(|n| (n.to_owned(), spec("text", "content")))
        .collect()
}

fn big_table() -> RefTable {
    let mut refs = RefTable::new();
    for i in 0..200 {
        let level = if i % 2 == 0 {
            Confidential::Secret
        } else {
            Confidential::Private
        };
        refs.issue(
            &format!("confidential-value-number-{i:04}-padding"),
            Scalar::Text,
            store(&format!("k{i}")),
            label(level),
        );
    }
    refs
}

#[test]
fn a_60_kib_request_with_200_refs_is_traced_quickly() {
    let refs = big_table();
    let filler = "lorem ipsum dolor sit amet ".repeat(15 * 1024 / 27);
    let args: BTreeMap<String, Value> = ["a", "b", "c", "d"]
        .into_iter()
        .map(|n| (n.to_owned(), json!(filler)))
        .collect();
    let total: usize = args.values().map(|v| v.as_str().unwrap().len()).sum();
    assert!((55_000..=64 * 1024).contains(&total), "{total}");
    let started = Instant::now();
    let facts = trace_request(&four_text_specs(), &args, &refs, &[]);
    assert!(started.elapsed() < BUDGET, "{:?}", started.elapsed());
    assert!(
        facts
            .values()
            .all(|f| f.confidential == Confidential::Public)
    );
}

#[test]
fn the_split_check_still_runs_for_small_requests_and_is_skipped_for_huge_ones() {
    let mut refs = RefTable::new();
    let secret = "alice-salary-185000";
    refs.issue(
        secret,
        Scalar::Text,
        store("alice"),
        label(Confidential::Secret),
    );
    let (head, tail) = secret.split_at(12);
    let specs = four_text_specs();
    let small: BTreeMap<String, Value> =
        BTreeMap::from([("a".to_owned(), json!(head)), ("b".to_owned(), json!(tail))]);
    let facts = trace_request(&specs, &small, &refs, &[]);
    assert_eq!(facts["a"].confidential, Confidential::Secret);
    let pad = "z".repeat(40 * 1024);
    let huge: BTreeMap<String, Value> = BTreeMap::from([
        ("a".to_owned(), json!(format!("{head}{pad}"))),
        ("b".to_owned(), json!(format!("{pad}{tail}"))),
    ]);
    let started = Instant::now();
    let facts = trace_request(&specs, &huge, &refs, &[]);
    assert!(started.elapsed() < BUDGET);
    // Over 64 KiB in total: only the per-argument checks ran, and neither piece holds the whole secret.
    assert_eq!(facts["a"].confidential, Confidential::Public);
}

// ---- core's default text cap ----

#[test]
fn core_rejects_text_over_the_default_cap() {
    let s = spec("text", "content");
    let ok = "a".repeat(DEFAULT_MAX_TEXT_LEN);
    assert_eq!(check_arg_value(&s, &json!(ok)), Ok(()));
    let over = "a".repeat(DEFAULT_MAX_TEXT_LEN + 1);
    assert_eq!(
        check_arg_value(&s, &json!(over)),
        Err(ViolationCode::TooLong)
    );
}

// ---- quarantine rule changes ----

fn items(entries: &[(&str, u8)]) -> Vec<Item> {
    entries
        .iter()
        .enumerate()
        .map(|(i, (text, trust))| Item {
            step: 1,
            field: format!("f{i}"),
            index: None,
            hash: item_hash(text),
            region: RegionType::Unclassified,
            trust: Trust::new(*trust),
            text: (*text).to_owned(),
        })
        .collect()
}

#[test]
fn quarantine_ignores_short_needles_and_widens_when_only_trusted_items_match() {
    let list = items(&[
        ("I love box.io", 80),
        ("Reviews: great", 30),
        ("Plain text", 60),
    ]);
    // `x.io` is too short to be a needle: it is as if nothing matched.
    assert_eq!(
        choose(&list, &["x.io".to_owned()], Trust::new(50)),
        vec![(1, Cause::LowTrustFallback)]
    );
    // A trusted-only match also withholds the low-trust items.
    assert_eq!(
        choose(&list, &["love box.io".to_owned()], Trust::new(50)),
        vec![(0, Cause::TracedValue), (1, Cause::LowTrustFallback)]
    );
    // A low-trust match keeps the narrow rule.
    let list = items(&[
        ("see love box.io", 80),
        ("also love box.io", 30),
        ("other", 20),
    ]);
    assert_eq!(
        choose(&list, &["love box.io".to_owned()], Trust::new(50)),
        vec![(1, Cause::TracedValue)]
    );
}

#[test]
fn a_split_across_long_pieces_is_still_found_at_their_edges() {
    let secret = "alice-salary-185000";
    let mut refs = RefTable::new();
    refs.issue(
        secret,
        Scalar::Text,
        store("alice"),
        label(Confidential::Secret),
    );
    let (head, tail) = secret.split_at(9);
    let pad = "lorem ipsum ".repeat(1500);
    let specs = four_text_specs();
    let pieces = |a: String, b: String, c: String| -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("a".to_owned(), json!(a)),
            ("b".to_owned(), json!(b)),
            ("c".to_owned(), json!(c)),
        ])
    };
    // Either half may sit in any argument, in any position, with long filler around it.
    let cases = [
        pieces(format!("{pad}{head}"), format!("{tail}{pad}"), pad.clone()),
        pieces(pad.clone(), format!("{pad}{head}"), format!("{tail}{pad}")),
        pieces(format!("{tail}{pad}"), pad.clone(), format!("{pad}{head}")),
        // Padding of white space after the first half does not hide it.
        pieces(
            format!("{head}{}", " ".repeat(20_000)),
            tail.to_owned(),
            pad.clone(),
        ),
        // Nor does mixed case, or an escape that is itself split.
        pieces(
            format!("{pad}ALICE-sal"),
            format!("ary-185000{pad}"),
            pad.clone(),
        ),
        pieces(
            format!("{pad}alice-salary-18500%"),
            format!("30{pad}"),
            pad.clone(),
        ),
        pieces(
            format!("{pad}alice-salary-185%"),
            "30%".to_owned(),
            format!("30%30{pad}"),
        ),
    ];
    for (n, args) in cases.into_iter().enumerate() {
        let facts = trace_request(&specs, &args, &refs, &[]);
        assert_eq!(facts["a"].confidential, Confidential::Secret, "case {n}");
    }
    // A decoy that only looks similar stays clean.
    let args = pieces(format!("{pad}alice-salary-18"), format!("9999{pad}"), pad);
    let facts = trace_request(&specs, &args, &refs, &[]);
    assert_eq!(facts["a"].confidential, Confidential::Public);
}
