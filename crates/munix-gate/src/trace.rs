//! The Provenance Tracer and DLP Scanner: work out where each argument value came from and what it carries.
//!
//! Runs after `Request::check_shape`, so every value already has the manifest's shape.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use munix_core::ids::{RefId, find_embedded};
use munix_core::label::Confidential;
use munix_core::manifest::{ArgRole, ArgSpec};
use munix_core::validate::{Scalar, is_hidden_format_char};
use serde_json::Value;

use crate::facts::{ArgFacts, Match, Traced};
use crate::refs::RefTable;
use crate::vault::Credential;

/// Traces one argument.
///
/// - Destination and selector arguments with a string-shaped type: each value (each list element) becomes one
///   [`crate::facts::Traced`] in `values`. A `ref:` value resolves through the table (unknown refs are counted in
///   `unknown_refs` and traced as untraced); a raw value matches every table entry with exactly that value. For
///   an `id` or `text` argument (a name or bare host the user typed, with no scheme to recognize) a raw value that
///   is exactly (case-sensitive) a whole token of the prompt also gets one more match, origin `Prompt` with the
///   prompt label (trust 100) and no ref id. Prompt tokens are never table entries, so they are not found in
///   content text; `url`, `email`, `iban` and `phone` arguments are unchanged.
/// - Content text: refs embedded in it (`munix_core::ids::find_embedded`) go to `embedded`; raw links and
///   addresses (found by the [`raw_destinations`] tokenizer) whose cleaned token text exactly matches one or more
///   table entries also go to `embedded` with those entries' matches and raise `confidential`, while untraced ones
///   are counted in `raw_destinations`; `confidential` is the most confidential of the embedded (or traced raw)
///   entries' labels and of table entries (at least 6 characters long) whose value is copied into the text;
///   `contains_credential` is set when any credential appears in the text plainly, base64 encoded (standard or
///   URL-safe, with or without padding) or hex encoded (either case). Known values and credentials are looked
///   for in the raw text and in its percent-decoded form (`%XX`, `+` as a space, decoded once), exactly and also
///   normalized (lowercased, without white space and invisible format characters; the value must still have at
///   least 6 characters after that). A run of glued `scheme://` URLs in one token counts once per `://` in
///   `raw_destinations` but is traced once in `embedded`. Table entries
///   labelled `private` or `secret` (at least 8 characters long) are also found base64 or hex encoded, and
///   raise `confidential` to their level exactly like a plain copy.
/// - Content `ref`/`ref[]` values (such as attachments) resolve like embedded refs.
/// - Destination and selector arguments of a non-string type (int, number, bool, enum): each value (each list
///   element) is matched exactly (canonical JSON equality) against the scalar values the Gate delivered from tool
///   outputs (`RefTable::find_scalar`), so a numeric id must have come from a step output to pass a `from` rule.
///   A value nothing delivered is traced as untraced. Prompt numerals are not recorded.
/// - Everything else (control arguments, content numbers, bools, enums) gives default facts.
pub fn trace_arg(
    spec: &ArgSpec,
    value: &Value,
    refs: &RefTable,
    credentials: &[&Credential],
) -> ArgFacts {
    let mut facts = ArgFacts::default();
    let scalar = spec.ty.scalar;
    if !scalar.is_string_shaped() {
        if matches!(spec.role, ArgRole::Destination | ArgRole::Selector) {
            for item in scalar_items(value) {
                facts.values.push(Traced {
                    matches: refs.find_scalar(item),
                });
            }
        }
        return facts;
    }
    match spec.role {
        ArgRole::Destination | ArgRole::Selector => {
            for item in items(value) {
                let traced = match item {
                    Some(raw) => trace_value(raw, scalar, refs, &mut facts.unknown_refs),
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

/// The values of a non-string argument: one for a scalar, one per element for a list. `null` gives nothing.
/// An element that is not a scalar is still listed (it matches nothing, so it is untraced).
fn scalar_items(value: &Value) -> Vec<&Value> {
    match value {
        Value::Null => Vec::new(),
        Value::Array(a) => a.iter().collect(),
        other => vec![other],
    }
}

/// Traces one destination or selector value: a `ref:` token resolves through the table, a raw string matches
/// every entry holding exactly that string, plus (for `id` and `text`) the prompt-token match if `raw` is one.
fn trace_value(raw: &str, scalar: Scalar, refs: &RefTable, unknown_refs: &mut u32) -> Traced {
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
    let mut matches: Vec<Match> = refs
        .find_value(raw)
        .into_iter()
        .map(|(id, entry)| entry.to_match(id.clone()))
        .collect();
    if matches!(scalar, Scalar::Id | Scalar::Text)
        && let Some(m) = refs.find_prompt_token(raw)
    {
        matches.push(m);
    }
    Traced { matches }
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
    for (token, count) in raw_destination_counts(text) {
        let entries = refs.find_value(&token);
        if entries.is_empty() {
            // A link or host the user typed in the prompt is theirs, not a raw destination; it is embedded from the
            // prompt (`RefTable::find_prompt_token`), so it raises `confidential` like a prompt ref would.
            match refs.find_prompt_token(&token) {
                Some(m) => {
                    facts.confidential = facts.confidential.max(m.confidential);
                    facts.embedded.push(Traced { matches: vec![m] });
                }
                None => facts.raw_destinations = facts.raw_destinations.saturating_add(count),
            }
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
    let views = views_of(text);
    if let Some(level) = known_value_level(&views, refs, MIN_COPIED_LEN, Confidential::Public, &[])
    {
        facts.confidential = facts.confidential.max(level);
    }
    if !facts.contains_credential && text_has_credential(&views, credentials, 1) {
        facts.contains_credential = true;
    }
}

/// Known values shorter than this are not treated as copied into text (too many accidental hits).
const MIN_COPIED_LEN: usize = 6;

/// Values shorter than this are only checked plainly: no base64 or hex form is looked for.
const MIN_ENCODED_LEN: usize = 8;

/// Values shorter than this are ignored when looking for one split across several content arguments.
const MIN_SPLIT_LEN: usize = 8;

/// One way of reading a piece of text, prepared for matching.
struct View {
    text: String,
    /// `text` without white space (encoded copies may be wrapped across lines).
    compact: String,
    compact_lower: String,
    /// `text` lowercased, without white space or invisible format characters (see [`normalize`]).
    norm: String,
}

impl View {
    fn new(text: &str) -> View {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        let compact_lower = compact.to_ascii_lowercase();
        View {
            text: text.to_owned(),
            compact,
            compact_lower,
            norm: normalize(text),
        }
    }
}

/// Lowercases `text` and drops white space (any Unicode white space, as [`View::compact`] does) and the invisible format characters that core refuses in free
/// text (zero-width, bidi, tag and similar), so that a copy that differs only in case, spacing or hidden
/// characters reads the same as the original.
fn normalize(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace() && !is_hidden_format_char(*c))
        .flat_map(char::to_lowercase)
        .collect()
}

/// The raw text and, when it differs, its percent-decoded form.
fn views_of(text: &str) -> Vec<View> {
    let mut views = vec![View::new(text)];
    if text.contains(['%', '+']) {
        let decoded = percent_decode(text);
        if decoded != text {
            views.push(View::new(&decoded));
        }
    }
    views
}

/// Decodes `%XX` pairs and turns `+` into a space, once (the result is not decoded again). A `%` not followed by
/// two hex digits is left as it is. Bytes that do not form valid UTF-8 become the replacement character.
fn percent_decode(text: &str) -> String {
    String::from_utf8_lossy(&percent_decode_bytes(text)).into_owned()
}

/// [`percent_decode`] before the bytes are read as UTF-8.
fn percent_decode_bytes(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let pair = bytes.get(i + 1).zip(bytes.get(i + 2));
                match pair.and_then(|(&hi, &lo)| Some(hex_digit(hi)? << 4 | hex_digit(lo)?)) {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    out
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Everything needed to look for one value in text, computed once per value (and per call), not per view.
struct Needle<'a> {
    /// The value itself, when it has at least `min_plain` bytes.
    plain: Option<&'a str>,
    /// The value lowercased and without white space or invisible characters, when that has at least
    /// `max(min_plain, MIN_COPIED_LEN)` characters.
    norm: Option<String>,
    /// Hex and base64 forms, when asked for and the value has at least [`MIN_ENCODED_LEN`] bytes.
    hex: Option<String>,
    base64: Vec<String>,
}

impl<'a> Needle<'a> {
    /// `encoded` also looks for the hex and base64 forms of a value.
    fn new(value: &'a str, min_plain: usize, encoded: bool) -> Needle<'a> {
        let plain = (!value.is_empty() && value.len() >= min_plain).then_some(value);
        let norm = Some(normalize(value))
            .filter(|n| !value.is_empty() && n.chars().count() >= min_plain.max(MIN_COPIED_LEN));
        let encoded = encoded && !value.is_empty() && value.len() >= MIN_ENCODED_LEN;
        Needle {
            plain,
            norm,
            hex: encoded.then(|| hex::encode(value.as_bytes())),
            base64: if encoded {
                base64_needles(value.as_bytes())
            } else {
                Vec::new()
            },
        }
    }

    /// True when the value shows up in any view: exactly, normalized, hex or base64 encoded.
    fn in_views(&self, views: &[View]) -> bool {
        views.iter().any(|v| {
            self.plain.is_some_and(|p| v.text.contains(p))
                || self.norm.as_deref().is_some_and(|n| v.norm.contains(n))
                || self
                    .hex
                    .as_deref()
                    .is_some_and(|h| v.compact_lower.contains(h))
                || self.base64.iter().any(|n| v.compact.contains(n.as_str()))
        })
    }
}

/// The most confidential level among table entries found in `views`: plainly (or normalized) when at least
/// `min_plain` characters long, and encoded when labelled `private` or `secret`. Entries below `floor` are
/// skipped, and so are entries found whole in any of the `alone` view sets (one per piece of text; those are
/// handled per argument). `None` when nothing is found.
fn known_value_level(
    views: &[View],
    refs: &RefTable,
    min_plain: usize,
    floor: Confidential,
    alone: &[Vec<View>],
) -> Option<Confidential> {
    let mut found: Option<Confidential> = None;
    for (_, entry) in refs.iter() {
        let level = entry.label.confidential;
        if level < floor || found.is_some_and(|f| f >= level) {
            continue;
        }
        let needle = Needle::new(&entry.value, min_plain, level >= Confidential::Private);
        if needle.in_views(views) && !alone.iter().any(|v| needle.in_views(v)) {
            found = Some(level);
        }
    }
    found
}

fn text_has_credential(views: &[View], credentials: &[&Credential], min_plain: usize) -> bool {
    credentials
        .iter()
        .any(|credential| Needle::new(credential.expose_secret(), min_plain, true).in_views(views))
}

/// The orders in which `n` pieces of text are joined to look for a split value: every order for up to
/// [`MAX_PERMUTED_PIECES`] pieces (an attacker picks which argument carries which half), otherwise name order and
/// its reverse (every ordered pair is checked separately, see [`trace_request`]).
fn orderings(n: usize) -> Vec<Vec<usize>> {
    let mut all: Vec<Vec<usize>> = vec![Vec::new()];
    if n > MAX_PERMUTED_PIECES {
        return vec![(0..n).collect(), (0..n).rev().collect()];
    }
    for _ in 0..n {
        let mut next = Vec::new();
        for partial in &all {
            for i in 0..n {
                if !partial.contains(&i) {
                    let mut longer = partial.clone();
                    longer.push(i);
                    next.push(longer);
                }
            }
        }
        all = next;
    }
    all
}

/// Above this many total bytes of content text the split check does not run; the request's content arguments are
/// raised to `Secret` instead (it cannot be shown clean), so one request cannot cost more than a bounded amount of
/// scanning and a split cannot hide behind padding.
const MAX_SPLIT_CHECK_BYTES: usize = 64 * 1024;

/// Up to this many pieces of content text are joined in every order (at most 24 orders).
const MAX_PERMUTED_PIECES: usize = 4;

/// What the split check looks for, prepared once per request: the needles of every credential and of every
/// `private` or `secret` table entry that is not found whole inside a single piece (those are per-argument
/// business), the strongest first, and what has been found so far.
struct SplitScan<'a> {
    credentials: Vec<Needle<'a>>,
    known: Vec<(Confidential, Needle<'a>)>,
    credential: bool,
    level: Option<Confidential>,
}

impl<'a> SplitScan<'a> {
    fn new(refs: &'a RefTable, credentials: &[&'a Credential], alone: &[Vec<View>]) -> Self {
        let whole = |n: &Needle<'_>| alone.iter().any(|v| n.in_views(v));
        let credentials = credentials
            .iter()
            .map(|c| Needle::new(c.expose_secret(), MIN_SPLIT_LEN, true))
            .filter(|n| !whole(n))
            .collect();
        let mut known: Vec<(Confidential, Needle<'a>)> = refs
            .iter()
            .filter(|(_, e)| e.label.confidential >= Confidential::Private)
            .map(|(_, e)| {
                (
                    e.label.confidential,
                    Needle::new(&e.value, MIN_SPLIT_LEN, true),
                )
            })
            .filter(|(_, n)| !whole(n))
            .collect();
        known.sort_by_key(|(level, _)| std::cmp::Reverse(*level));
        SplitScan {
            credentials,
            known,
            credential: false,
            level: None,
        }
    }

    /// Looks for the prepared needles in the views of one join.
    fn scan(&mut self, views: &[View]) {
        if !self.credential {
            self.credential = self.credentials.iter().any(|n| n.in_views(views));
        }
        for (level, needle) in &self.known {
            // Strongest first: once a level is found, nothing weaker can add to it.
            if self.level.is_some_and(|found| found >= *level) {
                break;
            }
            if needle.in_views(views) {
                self.level = Some(*level);
            }
        }
    }
}

/// Pair pre-filter. A value that is in a join of two pieces but not inside either alone must cross the join, so
/// two bytes that are next to each other in the value sit at the join: the last byte of the first piece and the
/// first byte of the second (or, in the space-separated join, the space and one of them). So a pair can be skipped
/// when no such byte pair is adjacent in any prepared needle of the matching kind. It is a necessary condition
/// only, so skipping is always safe; a pair that passes still gets the full check. This keeps the cost of
/// checking every ordered pair of up to 100 pieces to a few lookups per pair instead of a search per needle.
struct EdgeFilter {
    /// Adjacent byte pairs of the plain needles (checked against `Forms::text`).
    text: BTreeSet<(u8, u8)>,
    /// Of the base64 needles (`Forms::compact`).
    compact: BTreeSet<(u8, u8)>,
    /// Of the hex needles (`Forms::compact_lower`).
    compact_lower: BTreeSet<(u8, u8)>,
    /// Of the normalized needles (`Forms::norm`).
    norm: BTreeSet<(u8, u8)>,
}

impl EdgeFilter {
    fn new(scan: &SplitScan<'_>) -> EdgeFilter {
        let mut filter = EdgeFilter {
            text: BTreeSet::new(),
            compact: BTreeSet::new(),
            compact_lower: BTreeSet::new(),
            norm: BTreeSet::new(),
        };
        let needles = scan
            .credentials
            .iter()
            .chain(scan.known.iter().map(|(_, n)| n));
        for needle in needles {
            add_pairs(&mut filter.text, needle.plain);
            add_pairs(&mut filter.norm, needle.norm.as_deref());
            add_pairs(&mut filter.compact_lower, needle.hex.as_deref());
            for b64 in &needle.base64 {
                add_pairs(&mut filter.compact, Some(b64));
            }
        }
        filter
    }

    /// False only when no needle can sit across the join of `a` then `b` in any reading the join check builds.
    fn may_cross(&self, a: &Part, b: &Part) -> bool {
        if a.risky || b.risky {
            return true;
        }
        if self.forms_may_cross(&a.raw, &b.raw) {
            return true;
        }
        (a.marked || b.marked)
            && self.forms_may_cross(
                a.decoded.as_ref().unwrap_or(&a.raw),
                b.decoded.as_ref().unwrap_or(&b.raw),
            )
    }

    fn forms_may_cross(&self, a: &Forms, b: &Forms) -> bool {
        let at = |set: &BTreeSet<(u8, u8)>, x: &str, y: &str| -> bool {
            x.as_bytes()
                .last()
                .zip(y.as_bytes().first())
                .is_some_and(|(l, f)| set.contains(&(*l, *f)))
        };
        let next_to_space = |x: &str, y: &str| -> bool {
            x.as_bytes()
                .last()
                .is_some_and(|l| self.text.contains(&(*l, b' ')))
                || y.as_bytes()
                    .first()
                    .is_some_and(|f| self.text.contains(&(b' ', *f)))
        };
        at(&self.text, &a.text, &b.text)
            || next_to_space(&a.text, &b.text)
            || at(&self.compact, &a.compact, &b.compact)
            || at(&self.compact_lower, &a.compact_lower, &b.compact_lower)
            || at(&self.norm, &a.norm, &b.norm)
    }
}

fn add_pairs(set: &mut BTreeSet<(u8, u8)>, needle: Option<&str>) {
    if let Some(n) = needle {
        set.extend(n.as_bytes().windows(2).map(|w| (w[0], w[1])));
    }
}

/// Traces every argument of one request, and additionally looks for a value split across its content arguments.
///
/// Each argument with a spec gets [`trace_arg`] facts. Then the text of all content arguments (string-shaped,
/// not refs; list elements in order) is joined, once with no separator and once with a single space, and the
/// joined text is checked for credentials and for table entries labelled `private` or `secret` (plain,
/// percent-decoded, base64 or hex; values shorter than 8 characters are ignored). The joins are every order of
/// the pieces when there are at most four, so it does not matter which argument carries which half; with more
/// pieces they are name order, its reverse, and every ordered pair of two pieces (at most 100 pieces, so at most
/// 9,900 pairs, each cut down to the text near the piece ends, reusing needles prepared once). Only a value that
/// is not found whole inside any single piece counts as split. A hit raises EVERY content argument to that level
/// (`contains_credential` for a credential), so the strictest `dlp` rule among them decides. Needs at least two
/// non-empty pieces of content text.
///
/// Fail closed on size: when the pieces add up to more than 64 KiB the split check does not run, and instead every
/// content argument is raised to `Secret` and marked `split_unchecked` (the policy then records the fixed reason
/// `<arg>.split_unchecked`), because a request that large cannot be shown free of a split value. Rules with
/// `no_secret` or stricter deny it; the per-argument checks still ran.
pub fn trace_request(
    specs: &BTreeMap<String, ArgSpec>,
    args: &BTreeMap<String, Value>,
    refs: &RefTable,
    credentials: &[&Credential],
) -> BTreeMap<String, ArgFacts> {
    let mut out = BTreeMap::new();
    let mut content_names: Vec<&String> = Vec::new();
    let mut pieces: Vec<&str> = Vec::new();
    for (name, value) in args {
        let Some(spec) = specs.get(name) else {
            continue;
        };
        out.insert(name.clone(), trace_arg(spec, value, refs, credentials));
        if spec.role == ArgRole::Content
            && spec.ty.scalar.is_string_shaped()
            && spec.ty.scalar != Scalar::Ref
        {
            content_names.push(name);
            pieces.extend(items(value).into_iter().flatten().filter(|t| !t.is_empty()));
        }
    }
    if pieces.len() < 2 {
        return out;
    }
    let total: usize = pieces.iter().map(|p| p.len()).sum();
    if total > MAX_SPLIT_CHECK_BYTES {
        for name in content_names {
            if let Some(facts) = out.get_mut(name) {
                facts.confidential = facts.confidential.max(Confidential::Secret);
                facts.split_unchecked = true;
            }
        }
        return out;
    }
    let (credential, level) = split_hits(&pieces, refs, credentials, true);
    for name in content_names {
        if let Some(facts) = out.get_mut(name) {
            facts.contains_credential |= credential;
            if let Some(level) = level {
                facts.confidential = facts.confidential.max(level);
            }
        }
    }
    out
}

/// Looks for credentials and `private`/`secret` table entries split across `pieces` (at least two, within the size
/// bound). Returns whether a credential and which confidentiality level was found. `prefilter` turns the pair
/// pre-filter on (always on outside tests, which compare it with the unfiltered check).
fn split_hits(
    pieces: &[&str],
    refs: &RefTable,
    credentials: &[&Credential],
    prefilter: bool,
) -> (bool, Option<Confidential>) {
    // A value found whole inside one piece is that argument's own business (`trace_arg`), not a split.
    let alone: Vec<Vec<View>> = pieces.iter().map(|p| views_of(p)).collect();
    // A value that is not inside one piece but is inside a join must cross a boundary, so only the text near each
    // piece's ends matters: long pieces are cut down to their first and last `width` bytes before joining.
    let longest = refs
        .iter()
        .filter(|(_, e)| e.label.confidential >= Confidential::Private)
        .map(|(_, e)| e.value.len())
        .chain(credentials.iter().map(|c| c.expose_secret().len()))
        .max()
        .unwrap_or(0);
    let width = longest.saturating_mul(2).saturating_add(CROP_MARGIN);
    let parts: Vec<Part> = pieces
        .iter()
        .zip(&alone)
        .map(|(piece, views)| Part::new(piece, views, width))
        .collect();
    let mut scan = SplitScan::new(refs, credentials, &alone);
    let edges = (prefilter && pieces.len() > MAX_PERMUTED_PIECES).then(|| EdgeFilter::new(&scan));
    let mut views = Vec::new();
    let mut check = |order: &[usize]| {
        views.clear();
        join_views(pieces, &parts, order, &mut views);
        scan.scan(&views);
    };
    for order in orderings(pieces.len()) {
        check(&order);
    }
    if pieces.len() > MAX_PERMUTED_PIECES {
        for i in 0..pieces.len() {
            for j in 0..pieces.len() {
                let skip = edges
                    .as_ref()
                    .is_some_and(|e| !e.may_cross(&parts[i], &parts[j]));
                if i != j && !skip {
                    check(&[i, j]);
                }
            }
        }
    }
    (scan.credential, scan.level)
}

/// Extra bytes kept on each side of a cropped piece, beyond twice the longest value looked for (room for
/// character boundaries and lowercase expansion).
const CROP_MARGIN: usize = 16;

/// Stands in for the text cut out of a long piece; no value is looked for across it.
const CUT: char = '\u{FFFF}';

/// The four readings of one piece of text, each cut down to its first and last `width` bytes.
struct Forms {
    text: String,
    compact: String,
    compact_lower: String,
    norm: String,
}

impl Forms {
    fn new(view: &View, width: usize) -> Forms {
        Forms {
            text: crop(&view.text, width),
            compact: crop(&view.compact, width),
            compact_lower: crop(&view.compact_lower, width),
            norm: crop(&view.norm, width),
        }
    }
}

/// `text` as it is when short, else its first and last `width` bytes (cut at character boundaries) around [`CUT`].
fn crop(text: &str, width: usize) -> String {
    if text.len() <= width.saturating_mul(2).saturating_add(8) {
        return text.to_owned();
    }
    let mut head = width;
    while !text.is_char_boundary(head) {
        head -= 1;
    }
    let mut tail = text.len() - width;
    while !text.is_char_boundary(tail) {
        tail += 1;
    }
    format!("{}{CUT}{}", &text[..head], &text[tail..])
}

/// One piece of content text, prepared for joining.
struct Part {
    raw: Forms,
    /// The percent-decoded reading, when the text has one that differs from the text.
    decoded: Option<Forms>,
    /// True when the text has a `%` or `+`, so it may read differently inside a join.
    marked: bool,
    /// True when decoding the piece alone could differ from decoding it inside a join: it ends in half an escape
    /// (`%`, `%4`) or its decoded bytes are not valid UTF-8 (a character may continue in the next piece).
    risky: bool,
}

impl Part {
    fn new(piece: &str, views: &[View], width: usize) -> Part {
        let decoded = views.get(1);
        let marked = piece.contains(['%', '+']);
        let risky = marked && {
            let bytes = piece.as_bytes();
            let n = bytes.len();
            let half_escape = bytes.last() == Some(&b'%')
                || (n >= 2 && bytes[n - 2] == b'%' && hex_digit(bytes[n - 1]).is_some());
            half_escape || std::str::from_utf8(&percent_decode_bytes(piece)).is_err()
        };
        Part {
            raw: Forms::new(&views[0], width),
            decoded: decoded.map(|v| Forms::new(v, width)),
            marked,
            risky,
        }
    }
}

/// Adds the views of the pieces joined in `order`: with no separator and with a single space, raw and (when any
/// piece has one) percent-decoded. Only the plain text differs between the two joins, so the space join carries
/// just that. When a piece is risky to decode alone, the decoded readings come from decoding the whole join.
fn join_views(pieces: &[&str], parts: &[Part], order: &[usize], out: &mut Vec<View>) {
    push_joined(
        out,
        &order.iter().map(|&i| &parts[i].raw).collect::<Vec<_>>(),
    );
    if !order.iter().any(|&i| parts[i].marked) {
        return;
    }
    if order.iter().any(|&i| parts[i].risky) {
        let ordered: Vec<&str> = order.iter().map(|&i| pieces[i]).collect();
        out.extend(views_of(&ordered.concat()).into_iter().skip(1));
        out.extend(views_of(&ordered.join(" ")).into_iter().skip(1));
        return;
    }
    let forms: Vec<&Forms> = order
        .iter()
        .map(|&i| parts[i].decoded.as_ref().unwrap_or(&parts[i].raw))
        .collect();
    push_joined(out, &forms);
}

/// Pushes the no-separator join of `forms` (all four readings) and the single-space join (plain text only).
fn push_joined(out: &mut Vec<View>, forms: &[&Forms]) {
    let cat = |field: fn(&Forms) -> &String| -> String {
        forms.iter().map(|f| field(f).as_str()).collect()
    };
    out.push(View {
        text: cat(|f| &f.text),
        compact: cat(|f| &f.compact),
        compact_lower: cat(|f| &f.compact_lower),
        norm: cat(|f| &f.norm),
    });
    out.push(View {
        text: forms
            .iter()
            .map(|f| f.text.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        compact: String::new(),
        compact_lower: String::new(),
        norm: String::new(),
    });
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
    raw_destination_counts(text)
        .iter()
        .fold(0u32, |sum, (_, count)| sum.saturating_add(*count))
}

/// Extracts each raw destination token from `text` in order of appearance. A token that holds several
/// `scheme://` URLs (`x://x://x://...`) is listed once, not once per URL.
pub(crate) fn raw_destination_tokens(text: &str) -> Vec<String> {
    raw_destination_counts(text)
        .into_iter()
        .map(|(token, _)| token)
        .collect()
}

/// Like [`raw_destination_tokens`], each token with how many destinations it counts as (always 1, except for a
/// run of `scheme://` URLs glued into one token, which counts once per `://`). Memory stays linear in the text:
/// the repeated token is stored once and the count carries the rest.
pub(crate) fn raw_destination_counts(text: &str) -> Vec<(String, u32)> {
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
fn tokens_in_token(token: &str, out: &mut Vec<(String, u32)>) {
    // Any `scheme://` with something after it: the token counts once per `://` and is stored once; stop, the
    // URL covers what follows.
    let urls = token
        .match_indices("://")
        .filter(|(at, _)| at + 3 < token.len())
        .count();
    if urls > 0 {
        let trimmed = token.trim_end_matches(['.', ':', '!', '?']);
        out.push((trimmed.to_owned(), u32::try_from(urls).unwrap_or(u32::MAX)));
        return;
    }
    let bytes = token.as_bytes();
    // Byte ranges already counted as part of an email address. Their starts and ends only grow (each address
    // ends before the next `@`), so a cursor finds the one that could cover a position.
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
            out.push((trim_host(&token[start..end]).to_owned(), 1));
            consumed.push((start, end));
        }
    }
    let mut cursor = 0;
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
        while cursor < consumed.len() && consumed[cursor].1 <= start {
            cursor += 1;
        }
        if consumed.get(cursor).is_some_and(|&(s, _)| s <= start) {
            continue;
        }
        let run = &token[start..i];
        let host = trim_host(run);
        if host.is_empty() {
            continue;
        }
        let host_end = start + run.find(host).unwrap_or(0) + host.len();
        if is_bare_host(host, &token[host_end..]) {
            out.push((host.to_owned(), 1));
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
                if matches!(role, ArgRole::Destination | ArgRole::Selector) {
                    // Traced against the delivered scalars; nothing delivered 5, so it is one untraced value.
                    let want = ArgFacts {
                        values: vec![Traced::untraced()],
                        ..ArgFacts::default()
                    };
                    assert_eq!(facts, want, "{scalar:?} {role:?}");
                } else {
                    assert_eq!(facts, default, "{scalar:?} {role:?}");
                }
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

    // ---- percent decoding ----

    #[test]
    fn percent_decode_handles_pairs_plus_and_junk() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("a+b+c"), "a b c");
        assert_eq!(percent_decode("%41%62%7a%7A"), "Abzz");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
        assert_eq!(percent_decode("%2B"), "+");
        assert_eq!(percent_decode("caf%C3%A9 \u{4f60}"), "caf\u{e9} \u{4f60}");
        assert_eq!(percent_decode("%FF"), "\u{fffd}");
        assert_eq!(percent_decode(""), "");
    }

    #[test]
    fn percent_decode_is_not_recursive() {
        assert_eq!(percent_decode("%2541"), "%41");
        assert_eq!(percent_decode("%252B"), "%2B");
    }

    // ---- review 2: Unicode white space and the split check ----

    #[test]
    fn unicode_white_space_does_not_hide_a_known_value() {
        let refs = table("alice-salary-185000", Confidential::Secret);
        for gap in ['\u{a0}', '\u{2003}', '\u{3000}', '\u{2009}', '\u{1680}'] {
            let spaced: String = "alice-salary-185000"
                .chars()
                .flat_map(|c| [c, gap])
                .collect();
            let facts = text_facts(&format!("see {spaced} ok"), &refs, &[]);
            assert_eq!(facts.confidential, Confidential::Secret, "{gap:?}");
        }
        assert_eq!(normalize("A\u{a0}b\u{3000}C\u{2003}"), "abc");
    }

    #[test]
    fn oversize_requests_are_raised_to_secret_and_marked() {
        let refs = RefTable::new();
        let specs: BTreeMap<String, ArgSpec> = ["a", "b"]
            .into_iter()
            .map(|n| (n.to_owned(), spec(Scalar::Text, false, ArgRole::Content)))
            .collect();
        let pad = "z".repeat(MAX_SPLIT_CHECK_BYTES / 2 + 1);
        let args = BTreeMap::from([
            ("a".to_owned(), json!(pad.clone())),
            ("b".to_owned(), json!(pad)),
        ]);
        let facts = trace_request(&specs, &args, &refs, &[]);
        assert!(facts.values().all(|f| f.split_unchecked));
        assert!(
            facts
                .values()
                .all(|f| f.confidential == Confidential::Secret)
        );
    }

    /// A tiny deterministic generator, so the comparison below is repeatable.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self, n: usize) -> usize {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            usize::try_from(self.0 >> 33).unwrap() % n
        }
    }

    #[test]
    fn the_pair_prefilter_never_changes_what_the_split_check_finds() {
        let value = "Alice-Salary 185000-x";
        let cred = cred("sk-live-ABCDEFGHIJ");
        let mut refs = RefTable::new();
        refs.issue(
            value,
            Scalar::Text,
            step(1, "v"),
            label(20, Confidential::Secret),
        );
        refs.issue(
            "other\u{a0}private value",
            Scalar::Text,
            step(2, "v"),
            label(20, Confidential::Private),
        );
        // Fragments of the values in several shapes: plain, split anywhere, spaced, lower case, percent
        // escapes, white space, hidden characters, and filler.
        let mut fragments: Vec<String> = Vec::new();
        for v in [value, "sk-live-ABCDEFGHIJ", "other\u{a0}private value"] {
            for at in 1..v.len() {
                if v.is_char_boundary(at) {
                    fragments.push(v[..at].to_owned());
                    fragments.push(v[at..].to_owned());
                    fragments.push(v[..at].to_lowercase());
                    fragments.push(format!("{}\u{200b}", &v[..at]));
                    fragments.push(format!(" {}", &v[at..]));
                    fragments.push(v[..at].replace('-', "%2D").replace(' ', "+"));
                    fragments.push(v[at..].replace('-', "%2D").replace(' ', "+"));
                    fragments.push(format!("{}%", &v[..at]));
                }
            }
        }
        fragments.extend(["filler text", "", " ", "%", "%2", "+", "\n", "zz"].map(String::from));
        let mut rng = Lcg(7);
        let (mut hits, mut cases) = (0, 0);
        for _ in 0..400 {
            let n = 5 + rng.next(8);
            let pieces: Vec<String> = (0..n)
                .map(|_| fragments[rng.next(fragments.len())].clone())
                .collect();
            let refs_to_pieces: Vec<&str> = pieces
                .iter()
                .map(String::as_str)
                .filter(|p| !p.is_empty())
                .collect();
            if refs_to_pieces.len() < 5 {
                continue;
            }
            cases += 1;
            let with = split_hits(&refs_to_pieces, &refs, &[&cred], true);
            let without = split_hits(&refs_to_pieces, &refs, &[&cred], false);
            assert_eq!(with, without, "{refs_to_pieces:?}");
            if with.0 || with.1.is_some() {
                hits += 1;
            }
        }
        assert!(cases > 300, "{cases}");
        assert!(hits > 20, "the comparison should include real hits: {hits}");
    }

    // ---- DLP encodings ----

    fn percent_encode_all(s: &str) -> String {
        s.bytes().map(|b| format!("%{b:02X}")).collect()
    }

    fn table(value: &str, level: Confidential) -> RefTable {
        let mut refs = RefTable::new();
        refs.issue(value, Scalar::Text, step(1, "v"), label(20, level));
        refs
    }

    fn text_facts(text: &str, refs: &RefTable, creds: &[&Credential]) -> ArgFacts {
        trace_arg(
            &spec(Scalar::Text, false, ArgRole::Content),
            &json!(text),
            refs,
            creds,
        )
    }

    #[test]
    fn url_encoded_credential_is_found() {
        assert!(content_has_credential(
            &format!("key={}", percent_encode_all(SECRET)),
            &[SECRET]
        ));
        assert!(content_has_credential(
            &format!("key={}", percent_encode_all(SECRET).to_ascii_lowercase()),
            &[SECRET]
        ));
        // Only the odd characters encoded, as a URL encoder would.
        assert!(content_has_credential(
            "tok=pass%20word+123%21",
            &["pass word 123!"]
        ));
        assert!(!content_has_credential(
            "tok=pass%20word",
            &["pass word 123!"]
        ));
    }

    #[test]
    fn a_doubly_url_encoded_credential_is_decoded_only_once() {
        // Decoded once only: a doubly encoded credential is not found.
        let twice = percent_encode_all(&percent_encode_all(SECRET));
        assert!(!content_has_credential(&twice, &[SECRET]));
    }

    #[test]
    fn url_encoded_private_store_value_raises_confidentiality() {
        let refs = table("alice salary 185000", Confidential::Private);
        let facts = text_facts("note=alice%20salary%20185000", &refs, &[]);
        assert_eq!(facts.confidential, Confidential::Private);
        let facts = text_facts("note=alice+salary+185000", &refs, &[]);
        assert_eq!(facts.confidential, Confidential::Private);
        let facts = text_facts(&percent_encode_all("alice salary 185000"), &refs, &[]);
        assert_eq!(facts.confidential, Confidential::Private);
        let refs = table("alice salary 185000", Confidential::Secret);
        let facts = text_facts("alice%20salary%20185000", &refs, &[]);
        assert_eq!(facts.confidential, Confidential::Secret);
    }

    #[test]
    fn harmless_url_encoded_text_raises_nothing() {
        let refs = table("alice salary 185000", Confidential::Secret);
        let c = cred(SECRET);
        let facts = text_facts("hello%20world and a+b", &refs, &[&c]);
        assert_eq!(facts.confidential, Confidential::Public);
        assert!(!facts.contains_credential);
        assert!(facts.embedded.is_empty());
        assert_eq!(facts.raw_destinations, 0);
    }

    #[test]
    fn base64_and_hex_of_private_and_secret_values_are_found() {
        let value = "alice-salary-185000";
        for level in [Confidential::Private, Confidential::Secret] {
            let refs = table(value, level);
            let encoded = [
                STANDARD_NO_PAD.encode(value),
                URL_SAFE_NO_PAD.encode(value),
                base64::engine::general_purpose::STANDARD.encode(value),
                hex::encode(value),
                hex::encode(value).to_ascii_uppercase(),
                STANDARD_NO_PAD.encode(format!("xx{value} and more")),
            ];
            for enc in encoded {
                let facts = text_facts(&format!("blob: {enc}"), &refs, &[]);
                assert_eq!(facts.confidential, level, "{enc}");
            }
        }
    }

    #[test]
    fn base64_of_a_url_encoded_private_value_is_found_after_decoding() {
        let value = "alice-salary-185000";
        let refs = table(value, Confidential::Private);
        // The base64 text itself arrives percent-encoded (`=` as %3D, `+` as %2B).
        let enc = STANDARD_NO_PAD.encode(format!("zz{value}"));
        let facts = text_facts(&percent_encode_all(&enc), &refs, &[]);
        assert_eq!(facts.confidential, Confidential::Private);
    }

    #[test]
    fn encoded_forms_only_apply_to_private_and_secret_values() {
        let value = "alice-salary-185000";
        for level in [Confidential::Public, Confidential::Internal] {
            let refs = table(value, level);
            let facts = text_facts(&STANDARD_NO_PAD.encode(value), &refs, &[]);
            assert_eq!(facts.confidential, Confidential::Public, "{level:?}");
            let facts = text_facts(&hex::encode(value), &refs, &[]);
            assert_eq!(facts.confidential, Confidential::Public, "{level:?}");
        }
    }

    #[test]
    fn short_private_values_are_not_matched_encoded() {
        // Seven characters: found plainly, never encoded.
        let refs = table("pin1234", Confidential::Secret);
        assert_eq!(
            text_facts("pin1234", &refs, &[]).confidential,
            Confidential::Secret
        );
        assert_eq!(
            text_facts(&STANDARD_NO_PAD.encode("pin1234"), &refs, &[]).confidential,
            Confidential::Public
        );
        assert_eq!(
            text_facts(&hex::encode("pin1234"), &refs, &[]).confidential,
            Confidential::Public
        );
        // Eight characters get the encoded checks.
        let refs = table("pin12345", Confidential::Secret);
        assert_eq!(
            text_facts(&hex::encode("pin12345"), &refs, &[]).confidential,
            Confidential::Secret
        );
    }

    // ---- values split across content arguments ----

    fn email_specs() -> BTreeMap<String, ArgSpec> {
        let mut specs = BTreeMap::new();
        specs.insert(
            "to".to_owned(),
            spec(Scalar::Email, true, ArgRole::Destination),
        );
        specs.insert(
            "subject".to_owned(),
            spec(Scalar::Text, false, ArgRole::Content),
        );
        specs.insert(
            "body".to_owned(),
            spec(Scalar::Text, false, ArgRole::Content),
        );
        specs.insert(
            "attachments".to_owned(),
            spec(Scalar::Ref, true, ArgRole::Content),
        );
        specs
    }

    fn request_args(subject: &str, body: &str) -> BTreeMap<String, Value> {
        [
            ("to", json!(["bob@a.test"])),
            ("subject", json!(subject)),
            ("body", json!(body)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect()
    }

    #[test]
    fn a_secret_split_across_subject_and_body_raises_both() {
        let refs = table("alice-salary-185000", Confidential::Secret);
        let facts = trace_request(
            &email_specs(),
            &request_args("alice-salary-", "185000 for the year"),
            &refs,
            &[],
        );
        assert_eq!(facts["subject"].confidential, Confidential::Secret);
        assert_eq!(facts["body"].confidential, Confidential::Secret);
        // The destination is untouched.
        assert_eq!(facts["to"].confidential, Confidential::Public);
        // Order does not matter: the body is the first half, the subject the second.
        let facts = trace_request(
            &email_specs(),
            &request_args("185000", "alice-salary-"),
            &refs,
            &[],
        );
        assert_eq!(facts["subject"].confidential, Confidential::Secret);
        assert_eq!(facts["body"].confidential, Confidential::Secret);
        // A first half alone, or two unrelated pieces, raise nothing.
        let facts = trace_request(&email_specs(), &request_args("alice-sal", "x"), &refs, &[]);
        assert_eq!(facts["subject"].confidential, Confidential::Public);
        assert_eq!(facts["body"].confidential, Confidential::Public);
    }

    #[test]
    fn orderings_cover_small_sets_and_fall_back_for_large_ones() {
        assert_eq!(orderings(0), vec![Vec::<usize>::new()]);
        assert_eq!(orderings(2), vec![vec![0, 1], vec![1, 0]]);
        assert_eq!(orderings(4).len(), 24);
        assert_eq!(
            orderings(6),
            vec![vec![0, 1, 2, 3, 4, 5], vec![5, 4, 3, 2, 1, 0]]
        );
    }

    #[test]
    fn a_value_wholly_inside_one_argument_does_not_raise_the_others() {
        let refs = table("alice-salary-185000", Confidential::Private);
        let facts = trace_request(
            &email_specs(),
            &request_args("Weekly summary", "the figure is alice-salary-185000"),
            &refs,
            &[],
        );
        assert_eq!(facts["body"].confidential, Confidential::Private);
        assert_eq!(facts["subject"].confidential, Confidential::Public);
        // Same for an encoded copy and for a credential.
        let enc = hex::encode("alice-salary-185000");
        let facts = trace_request(&email_specs(), &request_args("Hi", &enc), &refs, &[]);
        assert_eq!(facts["body"].confidential, Confidential::Private);
        assert_eq!(facts["subject"].confidential, Confidential::Public);
        let c = cred(SECRET);
        let facts = trace_request(
            &email_specs(),
            &request_args("Hi", SECRET),
            &RefTable::new(),
            &[&c],
        );
        assert!(facts["body"].contains_credential);
        assert!(!facts["subject"].contains_credential);
    }

    #[test]
    fn a_split_joined_by_a_space_is_found() {
        let refs = table("alice salary 185000", Confidential::Private);
        let facts = trace_request(
            &email_specs(),
            &request_args("alice salary", "185000"),
            &refs,
            &[],
        );
        assert_eq!(facts["subject"].confidential, Confidential::Private);
        assert_eq!(facts["body"].confidential, Confidential::Private);
    }

    #[test]
    fn a_credential_split_across_arguments_flags_every_content_argument() {
        let c = cred(SECRET);
        let (a, b) = SECRET.split_at(10);
        let facts = trace_request(&email_specs(), &request_args(a, b), &RefTable::new(), &[&c]);
        assert!(facts["subject"].contains_credential);
        assert!(facts["body"].contains_credential);
        assert!(!facts["to"].contains_credential);
    }

    #[test]
    fn an_encoded_split_value_is_found() {
        let refs = table("alice-salary-185000", Confidential::Secret);
        let enc = hex::encode("alice-salary-185000");
        let (a, b) = enc.split_at(14);
        let facts = trace_request(&email_specs(), &request_args(a, b), &refs, &[]);
        assert_eq!(facts["subject"].confidential, Confidential::Secret);
        assert_eq!(facts["body"].confidential, Confidential::Secret);
    }

    #[test]
    fn a_split_inside_a_list_argument_is_found() {
        let mut specs = email_specs();
        specs.insert(
            "notes".to_owned(),
            spec(Scalar::Text, true, ArgRole::Content),
        );
        let refs = table("alice-salary-185000", Confidential::Secret);
        let mut args = request_args("hi", "there");
        args.insert("notes".to_owned(), json!(["alice-sal", "ary-185000"]));
        let facts = trace_request(&specs, &args, &refs, &[]);
        assert_eq!(facts["subject"].confidential, Confidential::Secret);
        assert_eq!(facts["body"].confidential, Confidential::Secret);
        assert_eq!(facts["notes"].confidential, Confidential::Secret);
    }

    #[test]
    fn short_values_are_not_split_matched() {
        // Seven characters: found whole in one argument, never across two.
        let refs = table("pin1234", Confidential::Secret);
        let facts = trace_request(&email_specs(), &request_args("pin1", "234"), &refs, &[]);
        assert_eq!(facts["subject"].confidential, Confidential::Public);
        assert_eq!(facts["body"].confidential, Confidential::Public);
        let c = cred("hunter2");
        let facts = trace_request(
            &email_specs(),
            &request_args("hunt", "er2"),
            &RefTable::new(),
            &[&c],
        );
        assert!(!facts["subject"].contains_credential);
        assert!(!facts["body"].contains_credential);
        // Eight characters are split-matched.
        let refs = table("pin12345", Confidential::Secret);
        let facts = trace_request(&email_specs(), &request_args("pin1", "2345"), &refs, &[]);
        assert_eq!(facts["body"].confidential, Confidential::Secret);
    }

    #[test]
    fn split_matching_ignores_public_and_internal_values() {
        for level in [Confidential::Public, Confidential::Internal] {
            let refs = table("alice-salary-185000", level);
            let facts = trace_request(
                &email_specs(),
                &request_args("alice-salary-", "185000"),
                &refs,
                &[],
            );
            assert_eq!(facts["subject"].confidential, Confidential::Public);
            assert_eq!(facts["body"].confidential, Confidential::Public);
        }
    }

    #[test]
    fn unrelated_content_arguments_stay_clean() {
        let refs = table("alice-salary-185000", Confidential::Secret);
        let c = cred(SECRET);
        let facts = trace_request(
            &email_specs(),
            &request_args("Weekly summary", "hello%20world, nothing to see"),
            &refs,
            &[&c],
        );
        for name in ["subject", "body", "to"] {
            assert_eq!(facts[name].confidential, Confidential::Public, "{name}");
            assert!(!facts[name].contains_credential, "{name}");
        }
        assert!(facts["subject"].embedded.is_empty() && facts["body"].embedded.is_empty());
    }

    #[test]
    fn trace_request_matches_trace_arg_per_argument() {
        let refs = table("alice-salary-185000", Confidential::Secret);
        let specs = email_specs();
        let args = request_args("a link evil.test", "plain body");
        let facts = trace_request(&specs, &args, &refs, &[]);
        for (name, value) in &args {
            assert_eq!(facts[name], trace_arg(&specs[name], value, &refs, &[]));
        }
        // Arguments without a spec are skipped.
        let mut extra = args.clone();
        extra.insert("unknown".to_owned(), json!("x"));
        assert_eq!(trace_request(&specs, &extra, &refs, &[]).len(), 3);
    }
}
