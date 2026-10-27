//! The Provenance Tracer and DLP Scanner: work out where each argument value came from and what it carries.
//!
//! Runs after `Request::check_shape`, so every value already has the manifest's shape.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use munix_core::ids::{RefId, find_embedded};
use munix_core::manifest::{ArgRole, ArgSpec};
use munix_core::validate::Scalar;
use serde_json::Value;

use crate::facts::{ArgFacts, Traced};
use crate::refs::RefTable;
use crate::vault::Credential;

/// Traces one argument.
///
/// - Destination and selector arguments with a string-shaped type: each value (each list element) becomes one
///   [`crate::facts::Traced`] in `values`. A `ref:` value resolves through the table (unknown refs are counted in
///   `unknown_refs` and traced as untraced); a raw value matches every table entry with exactly that value.
/// - Content text: refs embedded in it (`munix_core::ids::find_embedded`) go to `embedded`; raw links and
///   addresses (found by the [`raw_destinations`] tokenizer) whose cleaned token text exactly matches one or more
///   table entries also go to `embedded` with those entries' matches and raise `confidential`, while untraced ones
///   are counted in `raw_destinations`; `confidential` is the most confidential of the embedded (or traced raw)
///   entries' labels and of table entries (at least 6 characters long) whose value is copied into the text;
///   `contains_credential` is set when any credential appears in the text plainly, base64 encoded (standard or
///   URL-safe, with or without padding) or hex encoded (either case).
/// - Content `ref`/`ref[]` values (such as attachments) resolve like embedded refs.
/// - Everything else (control arguments, numbers, bools, enums) gives default facts.
pub fn trace_arg(
    spec: &ArgSpec,
    value: &Value,
    refs: &RefTable,
    credentials: &[&Credential],
) -> ArgFacts {
    let mut facts = ArgFacts::default();
    let scalar = spec.ty.scalar;
    if !scalar.is_string_shaped() {
        return facts;
    }
    match spec.role {
        ArgRole::Destination | ArgRole::Selector => {
            for item in items(value) {
                let traced = match item {
                    Some(raw) => trace_value(raw, refs, &mut facts.unknown_refs),
                    None => Traced::untraced(),
                };
                facts.values.push(traced);
            }
        }
        ArgRole::Content if scalar == Scalar::Ref => {
            for raw in items(value).into_iter().flatten() {
                match raw.parse::<RefId>() {
                    Ok(id) => note_embedded(&id, refs, &mut facts),
                    Err(_) => {
                        facts.unknown_refs = facts.unknown_refs.saturating_add(1);
                        facts.embedded.push(Traced::untraced());
                    }
                }
            }
        }
        ArgRole::Content => {
            for text in items(value).into_iter().flatten() {
                scan_text(text, refs, credentials, &mut facts);
            }
        }
        ArgRole::Control => {}
    }
    facts
}

/// The string values of an argument: one for a string, one per element for a list, `None` for anything that is
/// not a string (shape checks ran first, so that does not happen in practice). `null` gives nothing.
fn items(value: &Value) -> Vec<Option<&str>> {
    match value {
        Value::Null => Vec::new(),
        Value::String(s) => vec![Some(s.as_str())],
        Value::Array(a) => a.iter().map(Value::as_str).collect(),
        _ => vec![None],
    }
}

/// Traces one destination or selector value: a `ref:` token resolves through the table, a raw string matches
/// every entry holding exactly that string.
fn trace_value(raw: &str, refs: &RefTable, unknown_refs: &mut u32) -> Traced {
    if raw.starts_with("ref:")
        && let Ok(id) = raw.parse::<RefId>()
    {
        return match refs.get(&id) {
            Some(entry) => Traced {
                matches: vec![entry.to_match(id)],
            },
            None => {
                *unknown_refs = unknown_refs.saturating_add(1);
                Traced::untraced()
            }
        };
    }
    Traced {
        matches: refs
            .find_value(raw)
            .into_iter()
            .map(|(id, entry)| entry.to_match(id.clone()))
            .collect(),
    }
}

/// Records one embedded ref (or ref value): resolved ones raise `confidential`, unknown ones are counted and
/// traced as untraced.
fn note_embedded(id: &RefId, refs: &RefTable, facts: &mut ArgFacts) {
    match refs.get(id) {
        Some(entry) => {
            facts.confidential = facts.confidential.max(entry.label.confidential);
            facts.embedded.push(Traced {
                matches: vec![entry.to_match(id.clone())],
            });
        }
        None => {
            facts.unknown_refs = facts.unknown_refs.saturating_add(1);
            facts.embedded.push(Traced::untraced());
        }
    }
}

/// Scans one piece of content text and folds what it finds into `facts`.
fn scan_text(text: &str, refs: &RefTable, credentials: &[&Credential], facts: &mut ArgFacts) {
    for (_, _, id) in find_embedded(text) {
        note_embedded(&id, refs, facts);
    }
    for token in raw_destination_tokens(text) {
        let entries = refs.find_value(&token);
        if entries.is_empty() {
            facts.raw_destinations = facts.raw_destinations.saturating_add(1);
        } else {
            for (_, entry) in &entries {
                facts.confidential = facts.confidential.max(entry.label.confidential);
            }
            facts.embedded.push(Traced {
                matches: entries
                    .into_iter()
                    .map(|(id, entry)| entry.to_match(id.clone()))
                    .collect(),
            });
        }
    }
    for (_, entry) in refs.iter() {
        if entry.value.len() >= MIN_COPIED_LEN && text.contains(entry.value.as_str()) {
            facts.confidential = facts.confidential.max(entry.label.confidential);
        }
    }
    if !facts.contains_credential && text_has_credential(text, credentials) {
        facts.contains_credential = true;
    }
}

/// Known values shorter than this are not treated as copied into text (too many accidental hits).
const MIN_COPIED_LEN: usize = 6;

/// Credentials shorter than this are only checked plainly.
const MIN_ENCODED_LEN: usize = 8;

fn text_has_credential(text: &str, credentials: &[&Credential]) -> bool {
    // Encoded copies may be wrapped across lines, so the encoded checks look at the text without whitespace.
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let compact_lower = compact.to_ascii_lowercase();
    credentials.iter().any(|credential| {
        let secret = credential.expose_secret();
        if secret.is_empty() {
            return false;
        }
        if text.contains(secret) {
            return true;
        }
        let bytes = secret.as_bytes();
        if bytes.len() < MIN_ENCODED_LEN {
            return false;
        }
        compact_lower.contains(&hex::encode(bytes))
            || base64_needles(bytes)
                .iter()
                .any(|needle| compact.contains(needle.as_str()))
    })
}

/// The base64 strings that show up wherever `secret` is encoded, whatever its byte offset inside the encoded
/// data: for each of the three alignments, the characters fully determined by the secret's own bytes. Both
/// alphabets; padding is not part of any needle, so padded and unpadded text both match.
fn base64_needles(secret: &[u8]) -> Vec<String> {
    let mut needles = Vec::new();
    for shift in 0..3usize {
        let mut buf = vec![0u8; shift];
        buf.extend_from_slice(secret);
        let start = (shift * 8).div_ceil(6);
        let end = (buf.len() * 8) / 6;
        if end <= start {
            continue;
        }
        for encoded in [STANDARD_NO_PAD.encode(&buf), URL_SAFE_NO_PAD.encode(&buf)] {
            if let Some(part) = encoded.get(start..end) {
                needles.push(part.to_owned());
            }
        }
    }
    needles
}

/// Counts raw links and addresses in free text: `scheme://` URLs (any scheme), `www.` hosts, email addresses,
/// and bare host names whose last label is a common top-level domain (`com net org io co ai dev app xyz info
/// biz me us uk de ru cn tk top site online shop` and the reserved `test example invalid localhost`). Detection is
/// case-insensitive, ignores trailing punctuation, and does not count anything inside an embedded `ref:` token.
/// Numbers such as `4.6` or `1,200` are not host names. When [`trace_arg`] scans content text, any token whose
/// cleaned text exactly matches a [`RefTable`] value is traced in `embedded` instead of counted in
/// `raw_destinations`.
pub fn raw_destinations(text: &str) -> u32 {
    u32::try_from(raw_destination_tokens(text).len()).unwrap_or(u32::MAX)
}

/// Extracts each raw destination token from `text` in order of appearance.
pub(crate) fn raw_destination_tokens(text: &str) -> Vec<String> {
    let cleaned = strip_refs_and_normalize(text);
    let mut out = Vec::new();
    for token in cleaned.split(is_separator).filter(|t| !t.is_empty()) {
        tokens_in_token(token, &mut out);
    }
    out
}

/// Top-level domains (and reserved names) that make a bare host name count as a destination.
const TLDS: &[&str] = &[
    "com",
    "net",
    "org",
    "io",
    "co",
    "ai",
    "dev",
    "app",
    "xyz",
    "info",
    "biz",
    "me",
    "us",
    "uk",
    "de",
    "ru",
    "cn",
    "tk",
    "top",
    "site",
    "online",
    "shop",
    "test",
    "example",
    "invalid",
    "localhost",
];

/// Replaces embedded `ref:` tokens with a space (so nothing inside one is scanned) and turns the Unicode dots
/// that browsers read as `.` into `.`.
fn strip_refs_and_normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (start, end, _) in find_embedded(text) {
        push_normalized(&mut out, &text[last..start]);
        out.push(' ');
        last = end;
    }
    push_normalized(&mut out, &text[last..]);
    out
}

fn push_normalized(out: &mut String, part: &str) {
    out.extend(part.chars().map(|c| match c {
        '\u{3002}' | '\u{FF0E}' | '\u{FF61}' => '.',
        other => other,
    }));
}

/// Characters that end a token: white space and quoting or bracketing characters that cannot be part of a host.
fn is_separator(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '<' | '>'
                | '"'
                | '\''
                | '`'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '|'
                | '\\'
                | ','
                | ';'
        )
}

fn is_host_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

fn is_local_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'%' | b'+')
}

fn is_host_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn trim_host(s: &str) -> &str {
    s.trim_matches(|c| c == '.' || c == '-')
}

/// Extracts the raw destination tokens in one token (already free of white space and quoting characters).
fn tokens_in_token(token: &str, out: &mut Vec<String>) {
    // Any `scheme://` with something after it: collect each and stop, the URL covers what follows.
    let urls = token
        .match_indices("://")
        .filter(|(at, _)| at + 3 < token.len())
        .count();
    if urls > 0 {
        let trimmed = token.trim_end_matches(['.', ':', '!', '?']);
        for _ in 0..urls {
            out.push(trimmed.to_owned());
        }
        return;
    }
    let bytes = token.as_bytes();
    // Byte ranges already counted as part of an email address.
    let mut consumed: Vec<(usize, usize)> = Vec::new();
    for (at, &b) in bytes.iter().enumerate() {
        if b != b'@' {
            continue;
        }
        let mut start = at;
        while start > 0 && is_local_byte(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = at + 1;
        while end < bytes.len() && is_host_byte(bytes[end]) {
            end += 1;
        }
        let domain = trim_host(&token[at + 1..end]);
        if start < at && domain.contains('.') && domain.split('.').all(is_host_label) {
            out.push(trim_host(&token[start..end]).to_owned());
            consumed.push((start, end));
        }
    }
    let mut i = 0;
    while i < bytes.len() {
        if !is_host_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_host_byte(bytes[i]) {
            i += 1;
        }
        if consumed.iter().any(|&(s, e)| start >= s && start < e) {
            continue;
        }
        let run = &token[start..i];
        let host = trim_host(run);
        if host.is_empty() {
            continue;
        }
        let host_end = start + run.find(host).unwrap_or(0) + host.len();
        if is_bare_host(host, &token[host_end..]) {
            out.push(host.to_owned());
        }
    }
}

/// True when `host` (a run of letters, digits, dots and hyphens) is a `www.` host or ends in a listed top-level
/// domain. `rest` is what follows it in the token; a lone `localhost` counts only with a port or path.
fn is_bare_host(host: &str, rest: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    let labels: Vec<&str> = lower.split('.').collect();
    if !labels.iter().all(|l| is_host_label(l)) {
        return false;
    }
    match labels.as_slice() {
        [only] => {
            *only == "localhost"
                && (rest.starts_with('/')
                    || rest
                        .strip_prefix(':')
                        .is_some_and(|p| p.starts_with(|c: char| c.is_ascii_digit())))
        }
        [first, .., last] => *first == "www" || TLDS.contains(last),
        [] => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::facts::Origin;
    use munix_core::label::{Author, Capacity, Confidential, Label, RegionType, Source, Trust};
    use munix_core::manifest::ArgType;
    use serde_json::json;

    fn label(trust: u8, confidential: Confidential) -> Label {
        Label {
            source: Source::Prompt,
            region: RegionType::UserContent,
            author: Author::User,
            trust: Trust::new(trust),
            confidential,
            capacity: Capacity::FreeText,
        }
    }

    fn spec(scalar: Scalar, list: bool, role: ArgRole) -> ArgSpec {
        ArgSpec {
            ty: ArgType { scalar, list },
            role,
            optional: false,
            max: None,
            max_len: None,
            values: Vec::new(),
            single_line: false,
        }
    }

    fn step(n: u32, field: &str) -> Origin {
        Origin::Step {
            step: n,
            field: field.to_owned(),
        }
    }

    fn cred(s: &str) -> Credential {
        Credential::new(s)
    }

    // ---- raw_destinations ----

    #[test]
    fn plain_prose_and_numbers_count_zero() {
        assert_eq!(raw_destinations(""), 0);
        assert_eq!(raw_destinations("A fine product."), 0);
        assert_eq!(raw_destinations("4.6 stars across 1,200 reviews"), 0);
        assert_eq!(raw_destinations("Price: $1,299.99 (was 1,499.00)."), 0);
        assert_eq!(raw_destinations("Version 1.2.3 shipped on 2026-10-26."), 0);
        assert_eq!(
            raw_destinations("e.g. this, i.e. that, U.S. only, Ph.D."),
            0
        );
        assert_eq!(raw_destinations("Wait... what? No!"), 0);
    }

    #[test]
    fn words_with_unlisted_last_labels_count_zero() {
        assert_eq!(raw_destinations("We use Node.js and Vue.js here"), 0);
        assert_eq!(raw_destinations("Open config.yaml and main.rs"), 0);
        assert_eq!(raw_destinations("See readme.md, notes.txt"), 0);
        assert_eq!(raw_destinations("Next.js and Three.js"), 0);
        assert_eq!(raw_destinations("localhost is a word"), 0);
    }

    #[test]
    fn embedded_ref_tokens_count_zero() {
        assert_eq!(raw_destinations("Send it to ref:e1 please"), 0);
        assert_eq!(raw_destinations("Link ref:u2, then ref:u3."), 0);
        assert_eq!(raw_destinations("(ref:u1)"), 0);
        assert_eq!(raw_destinations("ref:u1.com"), 0);
        assert_eq!(raw_destinations("mailto:ref:e4"), 0);
    }

    #[test]
    fn refs_do_not_hide_raw_destinations_next_to_them() {
        assert_eq!(raw_destinations("ref:u1 and evil.com"), 1);
        assert_eq!(raw_destinations("ref:u1 https://evil.test/x"), 1);
    }

    #[test]
    fn scheme_urls_count() {
        assert_eq!(raw_destinations("go to https://evil.test/login now"), 1);
        assert_eq!(raw_destinations("http://localhost:8080/x"), 1);
        assert_eq!(raw_destinations("ftp://files.example/a"), 1);
        assert_eq!(raw_destinations("custom-scheme+v1://anything"), 1);
        assert_eq!(raw_destinations("hxxp://nope"), 1);
        assert_eq!(raw_destinations("<https://evil.test>"), 1);
        assert_eq!(raw_destinations("(https://evil.test/a)."), 1);
        assert_eq!(raw_destinations("see https://a.test and https://b.test"), 2);
        assert_eq!(raw_destinations("https://a.test,https://b.test"), 2);
        assert_eq!(raw_destinations("url=https://evil.test/x?y=1"), 1);
        assert_eq!(raw_destinations("HTTPS://EVIL.TEST/"), 1);
        assert_eq!(raw_destinations("https://zzz-unlisted.qq/"), 1);
    }

    #[test]
    fn dangling_scheme_marker_is_not_a_url() {
        assert_eq!(raw_destinations("the sequence :// alone"), 0);
        assert_eq!(raw_destinations("https://"), 0);
    }

    #[test]
    fn www_hosts_count() {
        assert_eq!(raw_destinations("visit www.evil.test"), 1);
        assert_eq!(raw_destinations("visit www.unlisted.qq today"), 1);
        assert_eq!(raw_destinations("WWW.Evil.Example/path"), 1);
        assert_eq!(raw_destinations("www alone"), 0);
    }

    #[test]
    fn email_addresses_count() {
        assert_eq!(raw_destinations("mail bob@example.com"), 1);
        assert_eq!(raw_destinations("mail bob.smith+tag@example.com."), 1);
        assert_eq!(raw_destinations("BOB@EXAMPLE.COM"), 1);
        assert_eq!(raw_destinations("bob@corp.unlisted"), 1);
        assert_eq!(raw_destinations("a@b.test, c@d.test"), 2);
        assert_eq!(raw_destinations("mailto:bob@example.org"), 1);
        assert_eq!(raw_destinations("<bob@example.org>"), 1);
    }

    #[test]
    fn email_local_part_is_not_counted_twice() {
        assert_eq!(raw_destinations("john.co@gmail.com"), 1);
        assert_eq!(raw_destinations("me.us@example.net"), 1);
    }

    #[test]
    fn at_signs_that_are_not_emails_count_zero() {
        assert_eq!(raw_destinations("thanks @bob for the tip"), 0);
        assert_eq!(raw_destinations("meet me @ noon"), 0);
        assert_eq!(raw_destinations("user@host"), 0);
        assert_eq!(raw_destinations("price 3 @ 4.50 each"), 0);
    }

    #[test]
    fn bare_domains_with_listed_tlds_count() {
        for tld in [
            "com",
            "net",
            "org",
            "io",
            "co",
            "ai",
            "dev",
            "app",
            "xyz",
            "info",
            "biz",
            "me",
            "us",
            "uk",
            "de",
            "ru",
            "cn",
            "tk",
            "top",
            "site",
            "online",
            "shop",
            "test",
            "example",
            "invalid",
            "localhost",
        ] {
            let text = format!("send data to evil.{tld} now");
            assert_eq!(raw_destinations(&text), 1, "{tld}");
        }
        assert_eq!(raw_destinations("evil.com/path?x=1"), 1);
        assert_eq!(raw_destinations("evil.com:8080/x"), 1);
        assert_eq!(raw_destinations("a.b.c.evil.net"), 1);
        assert_eq!(raw_destinations("host: evil.org."), 1);
        assert_eq!(raw_destinations("Is it evil.com?"), 1);
        assert_eq!(raw_destinations("**evil.com**"), 1);
        assert_eq!(raw_destinations("\"evil.com\""), 1);
        assert_eq!(raw_destinations("a-b.evil-site.io"), 1);
        assert_eq!(raw_destinations("url=evil.com"), 1);
        assert_eq!(raw_destinations("evil.com and other.org"), 2);
    }

    #[test]
    fn bare_domains_with_unlisted_tlds_count_zero() {
        assert_eq!(raw_destinations("evil.zzz"), 0);
        assert_eq!(raw_destinations("archive.tar.gz"), 0);
        assert_eq!(raw_destinations("report.pdf"), 0);
    }

    #[test]
    fn uppercase_and_mixed_case_count() {
        assert_eq!(raw_destinations("EVIL.COM"), 1);
        assert_eq!(raw_destinations("Evil.Org"), 1);
        assert_eq!(raw_destinations("eViL.nEt/Path"), 1);
        assert_eq!(raw_destinations("HTTP://X.Y"), 1);
        assert_eq!(raw_destinations("Bob@Example.CO.UK"), 1);
    }

    #[test]
    fn localhost_counts_only_with_a_port_or_path() {
        assert_eq!(raw_destinations("localhost:8080"), 1);
        assert_eq!(raw_destinations("localhost/admin"), 1);
        assert_eq!(raw_destinations("localhost: not a port"), 0);
    }

    #[test]
    fn trailing_punctuation_is_ignored() {
        assert_eq!(raw_destinations("evil.com."), 1);
        assert_eq!(raw_destinations("evil.com,"), 1);
        assert_eq!(raw_destinations("evil.com!"), 1);
        assert_eq!(raw_destinations("evil.com)"), 1);
        assert_eq!(raw_destinations("evil.com..."), 1);
        assert_eq!(raw_destinations("-evil.com-"), 1);
    }

    #[test]
    fn unicode_dots_do_not_hide_hosts() {
        assert_eq!(raw_destinations("evil\u{3002}com"), 1);
        assert_eq!(raw_destinations("evil\u{FF0E}com"), 1);
        assert_eq!(raw_destinations("evil\u{FF61}com"), 1);
    }

    #[test]
    fn mixed_text_adds_up() {
        let text = "Reviews: 4.6 stars across 1,200 reviews. Contact bob@example.com or visit www.shop.test, \
                    or https://x.test/a. Built with Node.js. Ref ref:u1.";
        assert_eq!(raw_destinations(text), 3);
    }

    #[test]
    fn non_ascii_text_does_not_panic() {
        assert_eq!(
            raw_destinations("caf\u{e9} na\u{ef}ve \u{4f60}\u{597d} evil.com \u{1f600}"),
            1
        );
        assert_eq!(raw_destinations("\u{e9}@\u{e9}.com"), 0);
        assert_eq!(raw_destinations("x@\u{e9}.com"), 0);
    }

    // ---- trace_arg: destinations and selectors ----

    #[test]
    fn destination_ref_resolves_through_the_table() {
        let mut refs = RefTable::new();
        let id = refs.issue(
            "bob@a.test",
            Scalar::Email,
            Origin::Prompt,
            label(90, Confidential::Private),
        );
        let facts = trace_arg(
            &spec(Scalar::Email, false, ArgRole::Destination),
            &json!(id.as_str()),
            &refs,
            &[],
        );
        assert_eq!(facts.values.len(), 1);
        assert_eq!(facts.values[0].matches.len(), 1);
        let m = &facts.values[0].matches[0];
        assert_eq!(m.id, Some(id));
        assert_eq!(m.origin, Origin::Prompt);
        assert_eq!(m.trust, Trust::new(90));
        assert_eq!(m.confidential, Confidential::Private);
        assert_eq!(facts.unknown_refs, 0);
        assert_eq!(facts.raw_destinations, 0);
        assert!(!facts.contains_credential);
    }

    #[test]
    fn unknown_destination_ref_is_counted_and_untraced() {
        let refs = RefTable::new();
        let facts = trace_arg(
            &spec(Scalar::Url, false, ArgRole::Destination),
            &json!("ref:u9"),
            &refs,
            &[],
        );
        assert_eq!(facts.values, vec![Traced::untraced()]);
        assert_eq!(facts.unknown_refs, 1);
    }

    #[test]
    fn raw_destination_value_matches_every_table_entry() {
        let mut refs = RefTable::new();
        refs.issue(
            "bob@a.test",
            Scalar::Email,
            Origin::Prompt,
            label(90, Confidential::Public),
        );
        refs.issue(
            "bob@a.test",
            Scalar::Email,
            step(1, "from"),
            label(10, Confidential::Public),
        );
        refs.issue(
            "eve@a.test",
            Scalar::Email,
            Origin::Prompt,
            label(90, Confidential::Public),
        );
        let facts = trace_arg(
            &spec(Scalar::Email, false, ArgRole::Destination),
            &json!("bob@a.test"),
            &refs,
            &[],
        );
        assert_eq!(facts.values.len(), 1);
        let origins: Vec<&Origin> = facts.values[0].matches.iter().map(|m| &m.origin).collect();
        assert_eq!(origins, vec![&Origin::Prompt, &step(1, "from")]);
        assert_eq!(facts.values[0].best_trust(), Trust::new(90));
        assert_eq!(facts.unknown_refs, 0);
    }

    #[test]
    fn untraced_raw_destination_has_no_matches() {
        let mut refs = RefTable::new();
        refs.issue(
            "bob@a.test",
            Scalar::Email,
            Origin::Prompt,
            label(90, Confidential::Public),
        );
        let facts = trace_arg(
            &spec(Scalar::Email, false, ArgRole::Destination),
            &json!("mallory@evil.test"),
            &refs,
            &[],
        );
        assert_eq!(facts.values, vec![Traced::untraced()]);
        assert_eq!(facts.values[0].best_trust(), Trust::ZERO);
    }

    #[test]
    fn destination_lists_give_one_traced_per_element() {
        let mut refs = RefTable::new();
        let a = refs.issue(
            "a@a.test",
            Scalar::Email,
            Origin::Prompt,
            label(90, Confidential::Public),
        );
        refs.issue(
            "b@a.test",
            Scalar::Email,
            Origin::UserData,
            label(70, Confidential::Public),
        );
        let facts = trace_arg(
            &spec(Scalar::Email, true, ArgRole::Destination),
            &json!([a.as_str(), "b@a.test", "c@a.test", "ref:e77"]),
            &refs,
            &[],
        );
        assert_eq!(facts.values.len(), 4);
        assert_eq!(facts.values[0].matches[0].origin, Origin::Prompt);
        assert_eq!(facts.values[1].matches[0].origin, Origin::UserData);
        assert!(facts.values[2].matches.is_empty());
        assert!(facts.values[3].matches.is_empty());
        assert_eq!(facts.unknown_refs, 1);
    }

    #[test]
    fn selectors_are_traced_like_destinations() {
        let mut refs = RefTable::new();
        refs.issue(
            "msg-42",
            Scalar::Id,
            step(2, "id"),
            label(30, Confidential::Public),
        );
        let facts = trace_arg(
            &spec(Scalar::Id, false, ArgRole::Selector),
            &json!("msg-42"),
            &refs,
            &[],
        );
        assert_eq!(facts.values.len(), 1);
        assert_eq!(facts.values[0].matches[0].origin, step(2, "id"));
        assert!(facts.embedded.is_empty());
    }

    #[test]
    fn non_string_elements_in_destinations_are_untraced() {
        let refs = RefTable::new();
        let facts = trace_arg(
            &spec(Scalar::Email, true, ArgRole::Destination),
            &json!([7, null]),
            &refs,
            &[],
        );
        assert_eq!(facts.values, vec![Traced::untraced(), Traced::untraced()]);
    }

    #[test]
    fn destination_ref_scalar_resolves_refs() {
        let mut refs = RefTable::new();
        let id = refs.issue(
            "x",
            Scalar::Text,
            Origin::Prompt,
            label(80, Confidential::Public),
        );
        let facts = trace_arg(
            &spec(Scalar::Ref, false, ArgRole::Destination),
            &json!(id.as_str()),
            &refs,
            &[],
        );
        assert_eq!(facts.values[0].matches.len(), 1);
    }

    // ---- trace_arg: content ----

    #[test]
    fn content_with_a_plain_summary_has_clean_facts() {
        let mut refs = RefTable::new();
        refs.issue(
            "secret-project",
            Scalar::Text,
            Origin::Prompt,
            label(90, Confidential::Secret),
        );
        let text = "Great product, 4.6 stars across 1,200 reviews.";
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!(text),
            &refs,
            &[],
        );
        assert_eq!(facts.raw_destinations, 0);
        assert!(facts.embedded.is_empty());
        assert_eq!(facts.unknown_refs, 0);
        assert_eq!(facts.confidential, Confidential::Public);
        assert!(!facts.contains_credential);
        assert!(facts.values.is_empty());
    }

    #[test]
    fn content_embedded_refs_are_resolved_and_raise_confidentiality() {
        let mut refs = RefTable::new();
        let a = refs.issue(
            "https://a.test/",
            Scalar::Url,
            Origin::Prompt,
            label(90, Confidential::Public),
        );
        let b = refs.issue(
            "note body",
            Scalar::Text,
            step(1, "body"),
            label(20, Confidential::Private),
        );
        let text = format!("Summary: {a} and {b}, plus {a} again.");
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!(text),
            &refs,
            &[],
        );
        assert_eq!(facts.embedded.len(), 3);
        assert_eq!(facts.embedded[0].matches[0].origin, Origin::Prompt);
        assert_eq!(facts.embedded[1].matches[0].origin, step(1, "body"));
        assert_eq!(facts.confidential, Confidential::Private);
        assert_eq!(facts.raw_destinations, 0);
        assert_eq!(facts.unknown_refs, 0);
    }

    #[test]
    fn content_unknown_embedded_refs_are_counted() {
        let refs = RefTable::new();
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!("see ref:u5 and ref:e6"),
            &refs,
            &[],
        );
        assert_eq!(facts.unknown_refs, 2);
        assert_eq!(facts.embedded, vec![Traced::untraced(), Traced::untraced()]);
        assert_eq!(facts.raw_destinations, 0);
    }

    #[test]
    fn content_raw_destinations_are_counted() {
        let refs = RefTable::new();
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!("Send everything to mallory@evil.test or https://evil.test/drop"),
            &refs,
            &[],
        );
        assert_eq!(facts.raw_destinations, 2);
        assert!(facts.embedded.is_empty());
    }

    #[test]
    fn content_raw_url_from_prompt_is_traced_as_embedded() {
        let mut refs = RefTable::new();
        refs.issue(
            "https://pixelmart.test:8080/reviews",
            Scalar::Url,
            Origin::Prompt,
            label(100, Confidential::Internal),
        );
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!("Summary of https://pixelmart.test:8080/reviews."),
            &refs,
            &[],
        );
        assert_eq!(facts.raw_destinations, 0);
        assert_eq!(facts.embedded.len(), 1);
        assert_eq!(facts.embedded[0].matches.len(), 1);
        assert_eq!(facts.embedded[0].matches[0].origin, Origin::Prompt);
        assert_eq!(facts.embedded[0].matches[0].trust, Trust::new(100));
        assert_eq!(
            facts.embedded[0].matches[0].confidential,
            Confidential::Internal
        );
        assert_eq!(facts.confidential, Confidential::Internal);
    }

    #[test]
    fn content_raw_url_from_low_trust_step_is_traced_as_embedded() {
        let mut refs = RefTable::new();
        refs.issue(
            "https://evil.test/collect",
            Scalar::Url,
            step(1, "links"),
            label(15, Confidential::Public),
        );
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!("Read https://evil.test/collect now"),
            &refs,
            &[],
        );
        assert_eq!(facts.raw_destinations, 0);
        assert_eq!(facts.embedded.len(), 1);
        assert_eq!(facts.embedded[0].matches.len(), 1);
        assert_eq!(facts.embedded[0].matches[0].origin, step(1, "links"));
        assert_eq!(facts.embedded[0].matches[0].trust, Trust::new(15));
    }

    #[test]
    fn content_raw_email_from_store_vs_unknown_email() {
        let mut refs = RefTable::new();
        let boss_origin = Origin::Store {
            name: "contacts".to_owned(),
            key: "boss".to_owned(),
        };
        refs.issue(
            "boss@corp.example",
            Scalar::Email,
            boss_origin.clone(),
            label(100, Confidential::Private),
        );
        let known = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!("Sent to boss@corp.example."),
            &refs,
            &[],
        );
        assert_eq!(known.raw_destinations, 0);
        assert_eq!(known.embedded.len(), 1);
        assert_eq!(known.embedded[0].matches[0].origin, boss_origin);
        assert_eq!(known.embedded[0].matches[0].trust, Trust::new(100));
        assert_eq!(known.confidential, Confidential::Private);

        let unknown = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!("Contact mallory@evil.test."),
            &refs,
            &[],
        );
        assert_eq!(unknown.raw_destinations, 1);
        assert!(unknown.embedded.is_empty());

        let both = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!("From boss@corp.example to mallory@evil.test"),
            &refs,
            &[],
        );
        assert_eq!(both.raw_destinations, 1);
        assert_eq!(both.embedded.len(), 1);
        assert_eq!(both.embedded[0].matches[0].origin, boss_origin);
    }

    #[test]
    fn content_raw_destination_matching_is_exact_case() {
        let mut refs = RefTable::new();
        refs.issue(
            "https://pixelmart.test:8080/reviews",
            Scalar::Url,
            Origin::Prompt,
            label(100, Confidential::Public),
        );
        refs.issue(
            "boss@corp.example",
            Scalar::Email,
            Origin::Prompt,
            label(100, Confidential::Public),
        );
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!("HTTPS://PIXELMART.TEST:8080/reviews and BOSS@CORP.EXAMPLE"),
            &refs,
            &[],
        );
        assert_eq!(facts.raw_destinations, 2);
        assert!(facts.embedded.is_empty());
    }

    #[test]
    fn content_raw_destination_matching_multiple_entries_combines_matches() {
        let mut refs = RefTable::new();
        refs.issue(
            "https://pixelmart.test:8080/reviews",
            Scalar::Url,
            Origin::Prompt,
            label(100, Confidential::Internal),
        );
        refs.issue(
            "https://pixelmart.test:8080/reviews",
            Scalar::Url,
            step(1, "links"),
            label(15, Confidential::Private),
        );
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!("See https://pixelmart.test:8080/reviews"),
            &refs,
            &[],
        );
        assert_eq!(facts.raw_destinations, 0);
        assert_eq!(facts.embedded.len(), 1);
        assert_eq!(facts.embedded[0].matches.len(), 2);
        assert_eq!(facts.embedded[0].best_trust(), Trust::new(100));
        assert_eq!(facts.confidential, Confidential::Private);
    }

    #[test]
    fn content_copying_a_known_value_raises_confidentiality() {
        let mut refs = RefTable::new();
        refs.issue(
            "4111-2222-3333",
            Scalar::Text,
            step(1, "card"),
            label(20, Confidential::Secret),
        );
        refs.issue(
            "tiny",
            Scalar::Text,
            step(1, "tiny"),
            label(20, Confidential::Private),
        );
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!("the number is 4111-2222-3333, ok"),
            &refs,
            &[],
        );
        assert_eq!(facts.confidential, Confidential::Secret);
        // The copied value is not an embedded ref.
        assert!(facts.embedded.is_empty());
    }

    #[test]
    fn content_copying_a_short_known_value_is_ignored() {
        let mut refs = RefTable::new();
        refs.issue(
            "12345",
            Scalar::Text,
            step(1, "pin"),
            label(20, Confidential::Secret),
        );
        refs.issue(
            "abcde",
            Scalar::Text,
            step(1, "x"),
            label(20, Confidential::Secret),
        );
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!("12345 and abcde"),
            &refs,
            &[],
        );
        assert_eq!(facts.confidential, Confidential::Public);
        // Exactly six characters counts.
        refs.issue(
            "123456",
            Scalar::Text,
            step(1, "pin6"),
            label(20, Confidential::Private),
        );
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!("code 123456"),
            &refs,
            &[],
        );
        assert_eq!(facts.confidential, Confidential::Private);
    }

    #[test]
    fn content_confidential_is_the_highest_of_embedded_and_copied() {
        let mut refs = RefTable::new();
        let a = refs.issue(
            "alpha-value",
            Scalar::Text,
            Origin::Prompt,
            label(90, Confidential::Internal),
        );
        refs.issue(
            "beta-value-long",
            Scalar::Text,
            step(1, "b"),
            label(10, Confidential::Secret),
        );
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!(format!("{a} then beta-value-long")),
            &refs,
            &[],
        );
        assert_eq!(facts.confidential, Confidential::Secret);
    }

    #[test]
    fn content_lists_combine_all_elements() {
        let mut refs = RefTable::new();
        let a = refs.issue(
            "hello world",
            Scalar::Text,
            Origin::Prompt,
            label(90, Confidential::Private),
        );
        let facts = trace_arg(
            &spec(Scalar::Text, true, ArgRole::Content),
            &json!([format!("one {a}"), "two evil.com", "three ref:u9"]),
            &refs,
            &[],
        );
        assert_eq!(facts.embedded.len(), 2);
        assert_eq!(facts.raw_destinations, 1);
        assert_eq!(facts.unknown_refs, 1);
        assert_eq!(facts.confidential, Confidential::Private);
    }

    #[test]
    fn content_ref_values_resolve_like_embedded_refs() {
        let mut refs = RefTable::new();
        let file = refs.issue(
            "report.pdf",
            Scalar::Text,
            step(2, "file"),
            label(25, Confidential::Private),
        );
        let facts = trace_arg(
            &spec(Scalar::Ref, true, ArgRole::Content),
            &json!([file.as_str(), "ref:v88"]),
            &refs,
            &[],
        );
        assert_eq!(facts.embedded.len(), 2);
        assert_eq!(facts.embedded[0].matches[0].origin, step(2, "file"));
        assert!(facts.embedded[1].matches.is_empty());
        assert_eq!(facts.unknown_refs, 1);
        assert_eq!(facts.confidential, Confidential::Private);
        assert!(facts.values.is_empty());
        assert_eq!(facts.raw_destinations, 0);
    }

    #[test]
    fn content_ref_value_that_is_not_a_ref_is_unknown() {
        let refs = RefTable::new();
        let facts = trace_arg(
            &spec(Scalar::Ref, false, ArgRole::Content),
            &json!("not-a-ref"),
            &refs,
            &[],
        );
        assert_eq!(facts.unknown_refs, 1);
        assert_eq!(facts.embedded, vec![Traced::untraced()]);
    }

    #[test]
    fn control_and_non_string_arguments_give_default_facts() {
        let mut refs = RefTable::new();
        refs.issue(
            "12345678",
            Scalar::Text,
            Origin::Prompt,
            label(90, Confidential::Secret),
        );
        let c = cred("sk-live-ABCDEFGH");
        let default = ArgFacts::default();
        let control = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Control),
            &json!("evil.com sk-live-ABCDEFGH ref:u1"),
            &refs,
            &[&c],
        );
        assert_eq!(control, default);
        for scalar in [Scalar::Bool, Scalar::Int, Scalar::Number, Scalar::Enum] {
            for role in [
                ArgRole::Destination,
                ArgRole::Content,
                ArgRole::Selector,
                ArgRole::Control,
            ] {
                let facts = trace_arg(&spec(scalar, false, role), &json!(5), &refs, &[&c]);
                assert_eq!(facts, default, "{scalar:?} {role:?}");
            }
        }
    }

    #[test]
    fn null_content_gives_default_facts() {
        let refs = RefTable::new();
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &Value::Null,
            &refs,
            &[],
        );
        assert_eq!(facts, ArgFacts::default());
    }

    // ---- credentials ----

    const SECRET: &str = "sk-live-9f8e7d6c5b4a";

    fn content_has_credential(text: &str, secrets: &[&str]) -> bool {
        let creds: Vec<Credential> = secrets.iter().map(|s| cred(s)).collect();
        let refs_to: Vec<&Credential> = creds.iter().collect();
        trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!(text),
            &RefTable::new(),
            &refs_to,
        )
        .contains_credential
    }

    #[test]
    fn plain_credential_is_found() {
        assert!(content_has_credential(
            &format!("my key is {SECRET} ok"),
            &[SECRET]
        ));
        assert!(content_has_credential(SECRET, &[SECRET]));
        assert!(!content_has_credential("my key is sk-live-0000", &[SECRET]));
        assert!(!content_has_credential("nothing here", &[SECRET]));
        assert!(!content_has_credential("anything", &[]));
    }

    #[test]
    fn base64_credentials_are_found_in_every_form() {
        let std_pad = base64::engine::general_purpose::STANDARD.encode(SECRET);
        let std_nopad = STANDARD_NO_PAD.encode(SECRET);
        let url_pad = base64::engine::general_purpose::URL_SAFE.encode(SECRET);
        let url_nopad = URL_SAFE_NO_PAD.encode(SECRET);
        for enc in [std_pad, std_nopad, url_pad, url_nopad] {
            assert!(
                content_has_credential(&format!("blob: {enc}"), &[SECRET]),
                "{enc}"
            );
            assert!(content_has_credential(&enc, &[SECRET]), "{enc}");
        }
    }

    #[test]
    fn base64_with_url_safe_characters_is_found() {
        // Bytes that produce '+' and '/' in the standard alphabet and '-' and '_' in the URL-safe one.
        let secret = "\u{fb}\u{ff}\u{be}\u{ff}\u{fb}\u{ff}\u{be}\u{ff}";
        let std = STANDARD_NO_PAD.encode(secret);
        let url = URL_SAFE_NO_PAD.encode(secret);
        assert_ne!(std, url);
        assert!(content_has_credential(&std, &[secret]));
        assert!(content_has_credential(&url, &[secret]));
    }

    #[test]
    fn base64_credential_inside_larger_encoded_data_is_found() {
        for prefix in ["", "a", "ab", "abc", "abcd", "abcde"] {
            let blob = format!("{prefix}{SECRET} and more");
            for enc in [STANDARD_NO_PAD.encode(&blob), URL_SAFE_NO_PAD.encode(&blob)] {
                assert!(
                    content_has_credential(&format!("data={enc}"), &[SECRET]),
                    "prefix {prefix:?}"
                );
            }
        }
    }

    #[test]
    fn wrapped_base64_is_found() {
        let enc = STANDARD_NO_PAD.encode(SECRET);
        let (a, b) = enc.split_at(enc.len() / 2);
        assert!(content_has_credential(&format!("{a}\n{b}"), &[SECRET]));
        assert!(content_has_credential(&format!("{a} {b}"), &[SECRET]));
    }

    #[test]
    fn hex_credentials_are_found_in_either_case() {
        let lower = hex::encode(SECRET);
        let upper = lower.to_ascii_uppercase();
        assert!(content_has_credential(&format!("hex {lower}"), &[SECRET]));
        assert!(content_has_credential(&format!("hex {upper}"), &[SECRET]));
        let mixed: String = lower
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        assert!(content_has_credential(&mixed, &[SECRET]));
        assert!(!content_has_credential("deadbeef", &[SECRET]));
    }

    #[test]
    fn short_credentials_are_only_checked_plainly() {
        let short = "hunter2";
        assert!(content_has_credential("pw hunter2", &[short]));
        assert!(!content_has_credential(
            &STANDARD_NO_PAD.encode(short),
            &[short]
        ));
        assert!(!content_has_credential(&hex::encode(short), &[short]));
        // Exactly eight bytes gets the encoded checks.
        let eight = "hunter22";
        assert!(content_has_credential(
            &STANDARD_NO_PAD.encode(eight),
            &[eight]
        ));
        assert!(content_has_credential(&hex::encode(eight), &[eight]));
    }

    #[test]
    fn empty_credentials_never_match() {
        assert!(!content_has_credential("anything at all", &[""]));
        assert!(!content_has_credential("", &[""]));
    }

    #[test]
    fn any_of_several_credentials_matches() {
        assert!(content_has_credential(
            "tok_second_value",
            &["tok_first_value", "tok_second_value"]
        ));
    }

    #[test]
    fn credential_in_a_list_element_is_found() {
        let c = cred(SECRET);
        let facts = trace_arg(
            &spec(Scalar::Text, true, ArgRole::Content),
            &json!(["fine", format!("leak {SECRET}")]),
            &RefTable::new(),
            &[&c],
        );
        assert!(facts.contains_credential);
    }

    #[test]
    fn credentials_are_not_checked_in_destinations() {
        let c = cred(SECRET);
        let facts = trace_arg(
            &spec(Scalar::Text, false, ArgRole::Destination),
            &json!(SECRET),
            &RefTable::new(),
            &[&c],
        );
        assert!(!facts.contains_credential);
        assert_eq!(facts.values, vec![Traced::untraced()]);
    }
}
