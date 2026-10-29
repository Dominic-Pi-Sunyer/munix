//! The per-task ref table: values the Gate holds and hands to the agent as `ref:` ids.
//!
//! Destinations travel as refs, so the agent can name a link or an address without the Gate having to trust
//! the string the agent typed. Each entry keeps the origin and label of the place the value came from.

use std::collections::{BTreeMap, BTreeSet};

use munix_core::ids::RefId;
use munix_core::label::{Confidential, Label, Source};
use munix_core::validate::{Scalar, is_valid};
use serde_json::Value;

use crate::facts::{Match, Origin};

/// One value the Gate issued a ref for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEntry {
    pub value: String,
    pub scalar: Scalar,
    pub origin: Origin,
    pub label: Label,
}

impl RefEntry {
    pub fn to_match(&self, id: RefId) -> Match {
        Match {
            id: Some(id),
            origin: self.origin.clone(),
            trust: self.label.trust,
            confidential: self.label.confidential,
            web_domain: match self.label.source {
                Source::Web { domain } => Some(domain),
                _ => None,
            },
            third_party: self.label.region.is_third_party(),
            region: Some(self.label.region),
        }
    }
}

/// Refs for one task. Never shared between tasks.
#[derive(Debug, Default)]
pub struct RefTable {
    entries: BTreeMap<RefId, RefEntry>,
    next: u32,
    /// Non-string scalar values (int, number, bool, enum) the Gate delivered from tool outputs, by canonical JSON
    /// text. They get no ref (the agent types the value itself), so this is how a selector such as a schedule id
    /// is traced back to the step that delivered it.
    scalars: BTreeMap<String, Vec<ScalarSite>>,
    /// Whole whitespace-separated tokens of the signed prompt, with the label prompt values carry. Consulted only
    /// by [`RefTable::find_prompt_token`] (for `id` and `text` destinations and selectors). They are not entries:
    /// no ref is issued, and content scanning, DLP and `find_value` never see them.
    prompt_tokens: BTreeSet<String>,
    prompt_label: Option<Label>,
    /// Every delivered number (int or number output) by its canonical decimal text (`1200`, `0.5`; see
    /// [`canonical_number`]), so an amount is compared by numeric value, not by JSON spelling (`1200` and
    /// `1200.0` are the same amount). Consulted only by [`RefTable::find_control`].
    numbers: BTreeMap<String, Vec<ScalarSite>>,
    /// The numbers (canonical decimal text) and ISO dates the user wrote in the signed prompt. Consulted only by
    /// [`RefTable::find_control`]. See [`prompt_scalars`] for what counts as a number there.
    prompt_numbers: BTreeSet<String>,
    prompt_dates: BTreeSet<String>,
    /// Text the agent receives whole (no ref) but that is `private` or `secret`, or a stored secret the plan
    /// never named: the copy check looks for these in content text exactly like for table entries. Value to the
    /// most confidential level it was seen at. Never issued to the agent.
    known: BTreeMap<String, Confidential>,
    /// Set when a value could not be registered because [`MAX_KNOWN_VALUES`] was reached; the Gate reads and
    /// clears it ([`RefTable::take_known_capped`]) to write a ledger entry.
    known_capped: bool,
}

/// The most free-text values (whole values and fragments together) a task registers for the copy check.
pub const MAX_KNOWN_VALUES: usize = 1024;

/// Where one non-string scalar value was delivered: the origin (step and field) and the field's label.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScalarSite {
    origin: Origin,
    label: Label,
}

impl ScalarSite {
    fn to_match(&self) -> Match {
        Match {
            id: None,
            origin: self.origin.clone(),
            trust: self.label.trust,
            confidential: self.label.confidential,
            web_domain: match self.label.source {
                Source::Web { domain } => Some(domain),
                _ => None,
            },
            third_party: false,
            region: Some(self.label.region),
        }
    }
}

/// True for an output field named like `amount_cents`: its integer holds hundredths of the unit.
fn is_cents_field(origin: &Origin) -> bool {
    matches!(origin, Origin::Step { field, .. } if field.ends_with("_cents"))
}

/// A number as plain decimal text with no exponent, no leading zeros and no trailing fraction zeros (`1200`,
/// `0.5`, `-3`), so equal values have equal text whatever their spelling. `None` for a value that is not finite.
fn canonical_number(n: &serde_json::Number) -> Option<String> {
    let raw = if let Some(i) = n.as_i64() {
        i.to_string()
    } else if let Some(u) = n.as_u64() {
        u.to_string()
    } else {
        let f = n.as_f64().filter(|f| f.is_finite())?;
        // Rust prints the shortest text that reads back as the same f64, and never uses an exponent.
        format!("{f}")
    };
    normalize_decimal(&raw)
}

/// `[-]digits[.digits]` without leading zeros in the integer part or trailing zeros in the fraction. `None` for
/// anything else.
fn normalize_decimal(text: &str) -> Option<String> {
    let (negative, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (int, frac) = match body.split_once('.') {
        Some((i, f)) => (i, f),
        None => (body, ""),
    };
    if int.is_empty()
        || !int.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let int = int.trim_start_matches('0');
    let int = if int.is_empty() { "0" } else { int };
    let frac = frac.trim_end_matches('0');
    let zero = int == "0" && frac.is_empty();
    let mut out = String::new();
    if negative && !zero {
        out.push('-');
    }
    out.push_str(int);
    if !frac.is_empty() {
        out.push('.');
        out.push_str(frac);
    }
    Some(out)
}

/// An amount in units (canonical decimal text) as whole hundredths, also as canonical text: `1200` gives
/// `120000`, `12.5` gives `1250`. `None` when it is negative or has more than two decimals.
fn units_to_cents(units: &str) -> Option<String> {
    if units.starts_with('-') {
        return None;
    }
    let (int, frac) = units.split_once('.').unwrap_or((units, ""));
    if frac.len() > 2 {
        return None;
    }
    normalize_decimal(&format!("{int}{frac:0<2}"))
}

const CURRENCY_SIGNS: [char; 4] = ['$', '\u{20ac}', '\u{a3}', '\u{a5}'];

/// The numbers (canonical decimal text) and dates (`YYYY-MM-DD`) written as whole words of the prompt.
///
/// A word counts only as a whole: the text between white space with surrounding brackets and quotes and trailing
/// `.,;:!?` taken off. So `GB29NWBK60161331926819` or `+15550100` give nothing, and `2022-04-01` is a date, not
/// the number 2022. A number is digits with an optional fraction, written either plain (`1200`, `1200.50`) or with
/// commas in groups of three (`1,200`, `1,200.50`), with one optional currency sign (`$ euro pound yen` signs)
/// before or after it. Anything else (`1.200,50`, `12,34`, `1e3`, `-5`, `50eur`) is not a number. This reads
/// the user's own signed prompt, never attacker text.
fn prompt_scalars(prompt: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut numbers = BTreeSet::new();
    let mut dates = BTreeSet::new();
    for word in prompt.split_whitespace() {
        let word = word.trim_matches(|c| "()[]<>\"'".contains(c));
        let word = word.trim_end_matches(['.', ',', ';', ':', '!', '?']);
        if is_valid(Scalar::Date, word) {
            dates.insert(word.to_owned());
        } else if let Some(n) = parse_prompt_number(word) {
            numbers.insert(n);
        }
    }
    (numbers, dates)
}

fn parse_prompt_number(word: &str) -> Option<String> {
    let body = match (
        word.strip_prefix(CURRENCY_SIGNS),
        word.strip_suffix(CURRENCY_SIGNS),
    ) {
        (Some(rest), None) | (None, Some(rest)) => rest,
        (None, None) => word,
        (Some(_), Some(_)) => return None,
    };
    let (int, frac) = match body.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (body, None),
    };
    if frac.is_some_and(|f| f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    let digits: String = if int.contains(',') {
        let groups: Vec<&str> = int.split(',').collect();
        let first_ok = groups.first().is_some_and(|g| (1..=3).contains(&g.len()));
        if !first_ok
            || !groups.iter().skip(1).all(|g| g.len() == 3)
            || !groups.iter().all(|g| g.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        groups.concat()
    } else if !int.is_empty() && int.bytes().all(|b| b.is_ascii_digit()) {
        int.to_owned()
    } else {
        return None;
    };
    normalize_decimal(&match frac {
        Some(f) => format!("{digits}.{f}"),
        None => digits,
    })
}

/// The key a scalar value is stored and looked up under: its canonical JSON text. `None` for anything that is not
/// a bool, number or string (those are never recorded and never match).
fn scalar_key(value: &Value) -> Option<String> {
    match value {
        Value::Bool(_) | Value::Number(_) | Value::String(_) => serde_json::to_string(value).ok(),
        _ => None,
    }
}

impl RefTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues a ref for `value`. The same value from the same origin gets the same ref back; the same value from
    /// another origin gets a new ref, so each ref keeps exactly one origin and label.
    ///
    /// Ids are `ref:` plus a one-letter kind (`u` url, `e` email, `p` phone, `v` anything else) and a counter
    /// that runs across all kinds: `ref:u1`, `ref:e2`, ...
    pub fn issue(&mut self, value: &str, scalar: Scalar, origin: Origin, label: Label) -> RefId {
        if let Some((id, _)) = self
            .entries
            .iter()
            .find(|(_, e)| e.value == value && e.origin == origin)
        {
            return id.clone();
        }
        let kind = match scalar {
            Scalar::Url => 'u',
            Scalar::Email => 'e',
            Scalar::Phone => 'p',
            Scalar::Iban => 'i',
            _ => 'v',
        };
        self.next = self.next.saturating_add(1);
        let id = match format!("ref:{kind}{}", self.next).parse::<RefId>() {
            Ok(id) => id,
            // "ref:" + one letter + at most ten digits is always a valid ref id (1-32 of [a-z0-9_]).
            Err(_) => unreachable!("generated ref ids are always valid"),
        };
        self.entries.insert(
            id.clone(),
            RefEntry {
                value: value.to_owned(),
                scalar,
                origin,
                label,
            },
        );
        id
    }

    /// Remembers that `value` (a bool, number, or enum string; anything else is ignored) was delivered from
    /// `origin` under `label`. The same value from the same origin is kept once.
    pub fn record_scalar(&mut self, value: &Value, origin: Origin, label: Label) {
        let Some(key) = scalar_key(value) else {
            return;
        };
        let site = ScalarSite { origin, label };
        if let Value::Number(n) = value
            && let Some(text) = canonical_number(n)
        {
            let sites = self.numbers.entry(text).or_default();
            if !sites.contains(&site) {
                sites.push(site.clone());
            }
        }
        let sites = self.scalars.entry(key).or_default();
        if !sites.contains(&site) {
            sites.push(site);
        }
    }

    /// Every place a value equal to `value` (exact canonical JSON equality) was delivered, in delivery order.
    /// Empty when no tool output carried it, which counts as untraced.
    pub fn find_scalar(&self, value: &Value) -> Vec<Match> {
        let Some(key) = scalar_key(value) else {
            return Vec::new();
        };
        self.scalars
            .get(&key)
            .map(|sites| sites.iter().map(ScalarSite::to_match).collect())
            .unwrap_or_default()
    }

    /// Remembers the numbers and ISO dates the user wrote in the prompt, for [`RefTable::find_control`]. Uses the
    /// label given to [`RefTable::record_prompt_tokens`] (call that first) for what a match carries.
    pub fn record_prompt_scalars(&mut self, prompt: &str) {
        let (numbers, dates) = prompt_scalars(prompt);
        self.prompt_numbers.extend(numbers);
        self.prompt_dates.extend(dates);
    }

    /// Where a value of a traced control argument (`ArgSpec::trace`: an int, number, date or bool) came from.
    /// Every place that carried an equal value, in this order: the prompt (a number or ISO date the user wrote;
    /// never a bool), then tool outputs, each as one match with the output field's origin and label.
    ///
    /// - **Numbers** are equal by numeric value: `1200`, `1200.0` and the prompt's `$1,200.00` are one amount.
    /// - **Unit rule:** an output field whose name ends in `_cents` holds hundredths. A number `v` equals such a
    ///   field when `v * 100` is a whole number equal to it (`amount_cents: 120000` is the amount `1200`, never
    ///   `120000`). Every other field is compared as it is, and a `_cents` field is never compared with an amount
    ///   in units. An argument whose own name ends in `_cents` is compared with `_cents` fields as is.
    /// - **Dates** are equal as `YYYY-MM-DD` text, **bools** as `true`/`false`.
    ///
    /// Empty when nothing carried the value (untraced).
    pub fn find_control(&self, scalar: Scalar, value: &Value, arg: &str) -> Vec<Match> {
        let mut out = Vec::new();
        match (scalar, value) {
            (Scalar::Int | Scalar::Number, Value::Number(n)) => {
                let Some(text) = canonical_number(n) else {
                    return out;
                };
                if self.prompt_numbers.contains(&text) {
                    out.extend(self.prompt_scalar_match());
                }
                let in_cents = |site: &&ScalarSite| is_cents_field(&site.origin);
                let sites_of = |key: &str| self.numbers.get(key).into_iter().flatten();
                if arg.ends_with("_cents") {
                    out.extend(sites_of(&text).filter(in_cents).map(ScalarSite::to_match));
                } else {
                    out.extend(
                        sites_of(&text)
                            .filter(|s| !is_cents_field(&s.origin))
                            .map(ScalarSite::to_match),
                    );
                    if let Some(cents) = units_to_cents(&text) {
                        out.extend(sites_of(&cents).filter(in_cents).map(ScalarSite::to_match));
                    }
                }
            }
            (Scalar::Date, Value::String(date)) => {
                if self.prompt_dates.contains(date) {
                    out.extend(self.prompt_scalar_match());
                }
                out.extend(self.find_scalar(value));
            }
            (Scalar::Bool, Value::Bool(_)) => out.extend(self.find_scalar(value)),
            _ => {}
        }
        out
    }

    fn prompt_scalar_match(&self) -> Option<Match> {
        let label = self.prompt_label.as_ref()?;
        Some(Match {
            id: None,
            origin: Origin::Prompt,
            trust: label.trust,
            confidential: label.confidential,
            web_domain: None,
            third_party: false,
            region: None,
        })
    }

    /// Registers `value` as free text the copy check must look for in content (it gets no ref and is not
    /// delivered differently). The most confidential level seen is kept. Returns false, and sets the flag read by
    /// [`RefTable::take_known_capped`], when the table is full.
    pub fn record_known(&mut self, value: &str, level: Confidential) -> bool {
        if value.is_empty() {
            return true;
        }
        if let Some(seen) = self.known.get_mut(value) {
            *seen = (*seen).max(level);
            return true;
        }
        if self.known.len() >= MAX_KNOWN_VALUES {
            self.known_capped = true;
            return false;
        }
        self.known.insert(value.to_owned(), level);
        true
    }

    /// Records that something could not be registered for the copy check (see [`RefTable::take_known_capped`]).
    pub fn note_known_capped(&mut self) {
        self.known_capped = true;
    }

    /// The free-text values registered for the copy check, with their levels.
    pub fn known_values(&self) -> impl Iterator<Item = (&str, Confidential)> {
        self.known.iter().map(|(v, l)| (v.as_str(), *l))
    }

    /// True once if a value was refused since the last call (and clears it).
    pub fn take_known_capped(&mut self) -> bool {
        std::mem::take(&mut self.known_capped)
    }

    /// Remembers the whole tokens of the prompt (see `Gate::start_task`) and the label a match on one carries.
    pub fn record_prompt_tokens<I: IntoIterator<Item = String>>(
        &mut self,
        tokens: I,
        label: Label,
    ) {
        self.prompt_tokens.extend(tokens);
        self.prompt_label = Some(label);
    }

    /// A match with origin `Origin::Prompt` when `raw` is exactly (case-sensitive) a whole prompt token, or is
    /// `http://` or `https://` (any case) followed by exactly a prompt token, with at most one trailing `/`: an agent
    /// writing the user's bare `www.example.com` as `https://www.example.com/` names the same place, and nothing
    /// may be added after it. The match has no ref id. `None` for anything else, including before any token was
    /// recorded.
    pub fn find_prompt_token(&self, raw: &str) -> Option<Match> {
        let label = self.prompt_label.as_ref()?;
        let bare = ["https://", "http://"].iter().find_map(|scheme| {
            raw.get(..scheme.len())
                .filter(|p| p.eq_ignore_ascii_case(scheme))
                .map(|_| &raw[scheme.len()..])
        });
        let found = self.prompt_tokens.contains(raw)
            || bare.is_some_and(|rest| {
                let rest = rest.strip_suffix('/').unwrap_or(rest);
                !rest.is_empty() && self.prompt_tokens.contains(rest)
            });
        found.then_some(Match {
            id: None,
            origin: Origin::Prompt,
            trust: label.trust,
            confidential: label.confidential,
            web_domain: None,
            third_party: false,
            region: None,
        })
    }

    pub fn get(&self, id: &RefId) -> Option<&RefEntry> {
        self.entries.get(id)
    }

    /// Every entry whose value is exactly `raw`, in id order. This is how a raw string the agent typed is traced.
    pub fn find_value(&self, raw: &str) -> Vec<(&RefId, &RefEntry)> {
        self.entries
            .iter()
            .filter(|(_, e)| e.value == raw)
            .collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&RefId, &RefEntry)> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use munix_core::label::{Author, Capacity, Confidential, RegionType, Source, Trust};

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

    fn step(n: u32, field: &str) -> Origin {
        Origin::Step {
            step: n,
            field: field.to_owned(),
        }
    }

    #[test]
    fn new_table_is_empty() {
        let t = RefTable::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert_eq!(t.iter().count(), 0);
        assert!(t.find_value("x").is_empty());
    }

    #[test]
    fn ids_use_kind_letters_and_a_shared_counter_from_one() {
        let mut t = RefTable::new();
        let l = label(80, Confidential::Public);
        let a = t.issue("https://a.test/", Scalar::Url, Origin::Prompt, l.clone());
        let b = t.issue("bob@a.test", Scalar::Email, Origin::Prompt, l.clone());
        let c = t.issue("+15550100", Scalar::Phone, Origin::Prompt, l.clone());
        let d = t.issue("hello", Scalar::Text, Origin::Prompt, l.clone());
        let e = t.issue("https://b.test/", Scalar::Url, Origin::Prompt, l.clone());
        let f = t.issue("abc-123", Scalar::Id, Origin::Prompt, l);
        let ids: Vec<&str> = [&a, &b, &c, &d, &e, &f]
            .iter()
            .map(|i| i.as_str())
            .collect();
        assert_eq!(
            ids,
            ["ref:u1", "ref:e2", "ref:p3", "ref:v4", "ref:u5", "ref:v6"]
        );
        assert_eq!(t.len(), 6);
        assert!(!t.is_empty());
    }

    #[test]
    fn same_value_and_origin_returns_the_same_ref() {
        let mut t = RefTable::new();
        let l = label(80, Confidential::Public);
        let a = t.issue("https://a.test/", Scalar::Url, Origin::Prompt, l.clone());
        let again = t.issue("https://a.test/", Scalar::Url, Origin::Prompt, l);
        assert_eq!(a, again);
        assert_eq!(t.len(), 1);
        // The counter did not advance for the duplicate.
        let next = t.issue(
            "other",
            Scalar::Text,
            Origin::Prompt,
            label(1, Confidential::Public),
        );
        assert_eq!(next.as_str(), "ref:v2");
    }

    #[test]
    fn dedupe_uses_value_and_origin_only() {
        let mut t = RefTable::new();
        let first = t.issue(
            "x@y.test",
            Scalar::Email,
            Origin::Prompt,
            label(90, Confidential::Public),
        );
        // Same value and origin but a different label and scalar: still the same ref, first label kept.
        let second = t.issue(
            "x@y.test",
            Scalar::Text,
            Origin::Prompt,
            label(5, Confidential::Secret),
        );
        assert_eq!(first, second);
        let entry = t.get(&first).unwrap();
        assert_eq!(entry.label.trust, Trust::new(90));
        assert_eq!(entry.scalar, Scalar::Email);
    }

    #[test]
    fn same_value_from_another_origin_gets_a_new_ref() {
        let mut t = RefTable::new();
        let a = t.issue(
            "x@y.test",
            Scalar::Email,
            Origin::Prompt,
            label(90, Confidential::Public),
        );
        let b = t.issue(
            "x@y.test",
            Scalar::Email,
            step(1, "from"),
            label(10, Confidential::Private),
        );
        let c = t.issue(
            "x@y.test",
            Scalar::Email,
            step(2, "from"),
            label(10, Confidential::Private),
        );
        let d = t.issue(
            "x@y.test",
            Scalar::Email,
            step(1, "other"),
            label(10, Confidential::Private),
        );
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(b, d);
        assert_eq!(t.len(), 4);
        assert_eq!(t.get(&a).unwrap().origin, Origin::Prompt);
        assert_eq!(t.get(&b).unwrap().origin, step(1, "from"));
        // Repeating an earlier pair finds the earlier ref.
        let b_again = t.issue(
            "x@y.test",
            Scalar::Email,
            step(1, "from"),
            label(10, Confidential::Private),
        );
        assert_eq!(b, b_again);
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn issued_ids_are_valid_ref_ids() {
        let mut t = RefTable::new();
        let id = t.issue(
            "v",
            Scalar::Text,
            Origin::UserData,
            label(50, Confidential::Public),
        );
        assert!(id.as_str().parse::<RefId>().is_ok());
        assert_eq!(munix_core::ids::find_embedded(id.as_str()).len(), 1);
    }

    #[test]
    fn get_returns_the_entry_or_none() {
        let mut t = RefTable::new();
        let id = t.issue(
            "https://a.test/",
            Scalar::Url,
            Origin::UserData,
            label(70, Confidential::Internal),
        );
        let entry = t.get(&id).unwrap();
        assert_eq!(entry.value, "https://a.test/");
        assert_eq!(entry.scalar, Scalar::Url);
        assert_eq!(entry.origin, Origin::UserData);
        let missing: RefId = "ref:u99".parse().unwrap();
        assert!(t.get(&missing).is_none());
    }

    #[test]
    fn to_match_carries_origin_trust_and_confidentiality() {
        let mut t = RefTable::new();
        let id = t.issue(
            "p",
            Scalar::Text,
            step(3, "body"),
            label(42, Confidential::Private),
        );
        let m = t.get(&id).unwrap().to_match(id.clone());
        assert_eq!(m.id, Some(id));
        assert_eq!(m.origin, step(3, "body"));
        assert_eq!(m.trust, Trust::new(42));
        assert_eq!(m.confidential, Confidential::Private);
    }

    #[test]
    fn find_value_is_exact_and_in_id_order() {
        let mut t = RefTable::new();
        let l = label(50, Confidential::Public);
        let a = t.issue("a@b.test", Scalar::Email, Origin::Prompt, l.clone());
        t.issue("A@b.test", Scalar::Email, Origin::Prompt, l.clone());
        let c = t.issue("a@b.test", Scalar::Email, step(1, "x"), l.clone());
        t.issue("a@b.test ", Scalar::Email, Origin::UserData, l);
        let hits = t.find_value("a@b.test");
        let ids: Vec<&RefId> = hits.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![&a, &c]);
        assert!(hits.iter().all(|(_, e)| e.value == "a@b.test"));
        assert!(t.find_value("a@b").is_empty());
        assert!(t.find_value("").is_empty());
    }

    #[test]
    fn iter_walks_entries_in_id_order() {
        let mut t = RefTable::new();
        let l = label(50, Confidential::Public);
        let a = t.issue("1", Scalar::Text, Origin::Prompt, l.clone());
        let b = t.issue("2", Scalar::Text, Origin::Prompt, l);
        let walked: Vec<&RefId> = t.iter().map(|(id, _)| id).collect();
        assert_eq!(walked, vec![&a, &b]);
    }

    #[test]
    fn tables_are_independent() {
        let mut one = RefTable::new();
        let two = RefTable::new();
        let id = one.issue(
            "v",
            Scalar::Text,
            Origin::Prompt,
            label(50, Confidential::Public),
        );
        assert!(two.get(&id).is_none());
        assert!(two.is_empty());
    }

    #[test]
    fn scalars_are_found_by_exact_canonical_json() {
        let mut t = RefTable::new();
        t.record_scalar(
            &serde_json::json!(7),
            step(1, "ids"),
            label(80, Confidential::Public),
        );
        t.record_scalar(
            &serde_json::json!(7),
            step(1, "ids"),
            label(80, Confidential::Public),
        );
        t.record_scalar(
            &serde_json::json!(7),
            step(2, "other"),
            label(20, Confidential::Public),
        );
        t.record_scalar(
            &serde_json::json!("weekly"),
            step(1, "mode"),
            label(80, Confidential::Public),
        );
        t.record_scalar(
            &serde_json::json!(true),
            step(1, "flag"),
            label(80, Confidential::Public),
        );
        // Not scalars: ignored.
        t.record_scalar(
            &serde_json::json!(null),
            step(1, "x"),
            label(80, Confidential::Public),
        );
        t.record_scalar(
            &serde_json::json!([7]),
            step(1, "x"),
            label(80, Confidential::Public),
        );
        let found = t.find_scalar(&serde_json::json!(7));
        assert_eq!(found.len(), 2, "same origin is kept once");
        assert!(found.iter().all(|m| m.id.is_none()));
        assert_eq!(found[0].origin, step(1, "ids"));
        assert_eq!(found[1].trust.value(), 20);
        assert_eq!(t.find_scalar(&serde_json::json!("weekly")).len(), 1);
        assert_eq!(t.find_scalar(&serde_json::json!(true)).len(), 1);
        // A string "7", a float 7.0 and a different number are other values.
        assert!(t.find_scalar(&serde_json::json!("7")).is_empty());
        assert!(t.find_scalar(&serde_json::json!(7.5)).is_empty());
        assert!(t.find_scalar(&serde_json::json!(8)).is_empty());
        assert!(t.find_scalar(&serde_json::json!(null)).is_empty());
        assert!(t.is_empty(), "scalars issue no refs");
    }

    fn sc(numbers: &[&str]) -> BTreeSet<String> {
        numbers.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn prompt_numbers_and_dates_are_read_exactly() {
        let (n, d) = prompt_scalars(
            "Pay 1200, 1,200.50, $1,200.50 or \u{20ac}50 (also 3.5; 7.) on 2026-11-01. GB29NWBK60161331926819 +15550100",
        );
        assert_eq!(n, sc(&["1200", "1200.5", "50", "3.5", "7"]));
        assert_eq!(d, sc(&["2026-11-01"]));
        // Not numbers: wrong groupings, European style, exponents, signs, glued letters, identifiers.
        for bad in [
            "1,20", "12,34", "1.200,50", "1e3", "-5", "50eur", "1,2000", "..5", "$", "5.", "a1",
        ] {
            let (n, _) = prompt_scalars(bad);
            assert!(n.is_empty() || bad == "5.", "{bad}: {n:?}");
        }
        assert_eq!(prompt_scalars("5.").0, sc(&["5"]));
        // A date is a date, not the number 2026.
        assert!(prompt_scalars("2026-11-01").0.is_empty());
        assert!(prompt_scalars("2026-13-01").1.is_empty());
    }

    #[test]
    fn find_control_compares_numbers_by_value_and_applies_the_cents_rule() {
        let mut t = RefTable::new();
        t.record_prompt_tokens(Vec::new(), label(100, Confidential::Public));
        t.record_prompt_scalars("Send $1,200.00 on 2026-11-01");
        t.record_scalar(
            &serde_json::json!(120000),
            step(1, "amount_cents"),
            label(10, Confidential::Private),
        );
        t.record_scalar(
            &serde_json::json!(75.5),
            step(2, "fee"),
            label(80, Confidential::Public),
        );
        t.record_scalar(
            &serde_json::json!("2026-12-24"),
            step(2, "due"),
            label(80, Confidential::Public),
        );
        t.record_scalar(
            &serde_json::json!(true),
            step(3, "flag"),
            label(80, Confidential::Public),
        );
        let f = |v: serde_json::Value, sc: Scalar| t.find_control(sc, &v, "amount");
        // Prompt: 1200, 1200.0 both match; so does the cents field (unit rule), 120000 in units does not.
        for v in [serde_json::json!(1200), serde_json::json!(1200.0)] {
            let m = f(v, Scalar::Number);
            assert_eq!(m.len(), 2);
            assert_eq!(m[0].origin, Origin::Prompt);
            assert_eq!(m[1].origin, step(1, "amount_cents"));
        }
        assert!(f(serde_json::json!(120000), Scalar::Number).is_empty());
        assert!(f(serde_json::json!(1200.01), Scalar::Number).is_empty());
        assert!(f(serde_json::json!(1200.001), Scalar::Number).is_empty());
        assert_eq!(f(serde_json::json!(75.5), Scalar::Number).len(), 1);
        assert_eq!(f(serde_json::json!(75.50), Scalar::Number).len(), 1);
        // An argument named like a cents field compares with cents fields as is.
        assert_eq!(
            t.find_control(Scalar::Int, &serde_json::json!(120000), "amount_cents")
                .len(),
            1
        );
        assert_eq!(f(serde_json::json!("2026-11-01"), Scalar::Date).len(), 1);
        assert_eq!(f(serde_json::json!("2026-12-24"), Scalar::Date).len(), 1);
        assert!(f(serde_json::json!("2026-12-25"), Scalar::Date).is_empty());
        // A bool never traces to the prompt, only to an output.
        let b = f(serde_json::json!(true), Scalar::Bool);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].origin, step(3, "flag"));
        assert!(f(serde_json::json!(false), Scalar::Bool).is_empty());
    }

    #[test]
    fn known_values_are_capped_and_deduplicated() {
        let mut t = RefTable::new();
        assert!(t.record_known("same text", Confidential::Private));
        assert!(t.record_known("same text", Confidential::Secret));
        assert_eq!(
            t.known_values().collect::<Vec<_>>(),
            vec![("same text", Confidential::Secret)]
        );
        for i in 0..MAX_KNOWN_VALUES {
            t.record_known(&format!("value number {i}"), Confidential::Private);
        }
        assert!(t.take_known_capped());
        assert!(!t.take_known_capped());
        assert!(t.is_empty(), "known values are not refs");
    }
}
