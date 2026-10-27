//! The per-task ref table: values the Gate holds and hands to the agent as `ref:` ids.
//!
//! Destinations travel as refs, so the agent can name a link or an address without the Gate having to trust
//! the string the agent typed. Each entry keeps the origin and label of the place the value came from.

use std::collections::BTreeMap;

use munix_core::ids::RefId;
use munix_core::label::Label;
use munix_core::validate::Scalar;
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
}

/// Where one non-string scalar value was delivered: the origin (step and field) and the field's label.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScalarSite {
    origin: Origin,
    label: Label,
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
        let sites = self.scalars.entry(key).or_default();
        let site = ScalarSite { origin, label };
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
            .map(|sites| {
                sites
                    .iter()
                    .map(|s| Match {
                        id: None,
                        origin: s.origin.clone(),
                        trust: s.label.trust,
                        confidential: s.label.confidential,
                    })
                    .collect()
            })
            .unwrap_or_default()
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
}
