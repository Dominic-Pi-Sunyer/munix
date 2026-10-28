//! Plan memory (`docs/plan-memory.md`): reuse a stored plan when a prompt repeats, exactly or with its values
//! swapped, instead of calling the planner again.
//!
//! A plan holds no values: its rules name sources (`prompt`, `store.contacts.boss`, `step.1`), never a recipient or an
//! amount. The planner sees only the prompt, the catalog and the store key names, never what the agent read
//! (invariant 3), so a plan depends on nothing else. Reusing one for an equivalent prompt gives the Gate the same
//! rules a fresh planner call would, and the Gate enforces them in code either way.
//!
//! - **Matching is deterministic.** A prompt's *shape* masks the tokens core's validators recognize as typed values
//!   (URL, email, IBAN, phone number, date, number), lowercases the rest and collapses whitespace. A template is
//!   keyed by the shape, the catalog's digest, the store keys and the planner's version, so it dies when any of
//!   them changes. An exact repeat is a shape match whose prompt hash the template has seen before.
//! - **Nothing personal is stored.** A template keeps the plan without its per-task fields, the hashes of the
//!   prompts it served, and a summary of tools and sources. Never the prompt text.
//! - **Writes happen between tasks.** [`PlanMemory::remember`] and [`PlanMemory::record_use`] are for after a task
//!   ends; the directory is sealed while a task runs (invariant 11).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use munix_core::crypto::Digest;
use munix_core::ids::{PlanId, TaskId};
use munix_core::label::RegionType;
use munix_core::manifest::Catalog;
use munix_core::plan::{Amendments, Plan, Step};
use munix_core::validate::{is_date, is_email, is_iban, is_phone, is_url};
use serde::{Deserialize, Serialize};

/// The template file format's version.
pub const FORMAT: u32 = 1;
/// The most prompt hashes a template keeps for telling exact repeats from shape matches.
pub const MAX_EXACT: usize = 32;

/// How a stored plan matched a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// The same prompt (after normalizing whitespace and case) was seen before.
    Exact,
    /// The same prompt with its typed values swapped.
    Shape,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Exact => "exact",
            Level::Shape => "shape",
        }
    }
}

/// A stored plan, without its per-task fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub format: u32,
    /// The digest of (shape, catalog, store keys, planner version): the template's id and file name.
    pub key: Digest,
    pub catalog: Digest,
    pub planner_version: String,
    pub reads: BTreeSet<RegionType>,
    pub steps: Vec<Step>,
    pub amendments: Amendments,
    /// Tools and argument sources only, for review (`munix plans`).
    pub summary: String,
    /// Seconds since the Unix epoch.
    pub created: u64,
    pub uses: u64,
    /// Hashes of the normalized prompts this template served (at most [`MAX_EXACT`]).
    pub exact: Vec<Digest>,
}

/// Why plan memory could not do something. Lookups never fail: an unreadable template is a miss.
#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    #[error("plan memory: {0}")]
    Io(String),
}

/// The plan memory in one directory, for one catalog and one planner version.
#[derive(Debug, Clone)]
pub struct PlanMemory {
    dir: PathBuf,
    catalog: Digest,
    planner_version: String,
}

/// The digest of a catalog: every manifest's digest, in tool-name order.
pub fn catalog_digest(catalog: &Catalog) -> Digest {
    let mut text = String::new();
    for (name, manifest) in catalog.iter() {
        let digest = manifest
            .digest()
            .map_or_else(|_| "unhashable".to_owned(), |d| d.as_str().to_owned());
        let _ = writeln!(text, "{name} {digest}");
    }
    Digest::of_bytes(text.as_bytes())
}

/// Whitespace collapsed and lowercased: what "the same prompt" means.
fn normalized(text: &str) -> String {
    text.split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

/// A number as a person writes one: digits with an optional sign, decimals, thousands commas, a leading currency sign
/// or a trailing percent.
fn is_number(s: &str) -> bool {
    let s = s.trim_start_matches(['$', '€', '£']).trim_end_matches('%');
    let s = s.strip_prefix('-').unwrap_or(s);
    let plain: String = s.chars().filter(|c| *c != ',').collect();
    !plain.is_empty()
        && plain.chars().any(|c| c.is_ascii_digit())
        && plain.chars().all(|c| c.is_ascii_digit() || c == '.')
        && plain.matches('.').count() <= 1
}

/// The kind of typed value a token is, by core's validators, or `None` for a word.
fn value_kind(token: &str) -> Option<&'static str> {
    if is_date(token) {
        Some("date")
    } else if is_iban(token) {
        Some("iban")
    } else if is_email(token) {
        Some("email")
    } else if is_url(token) {
        Some("url")
    } else if is_number(token) {
        Some("number")
    } else if is_phone(token) {
        Some("phone")
    } else {
        None
    }
}

/// The prompt with every typed value masked (`<iban>`, `<email>`, `<url>`, `<phone>`, `<date>`, `<number>`), then
/// normalized. Punctuation around a value stays; words are never masked.
pub fn prompt_shape(text: &str) -> String {
    let edge = |c: char| {
        matches!(
            c,
            '.' | ',' | ';' | ':' | '!' | '?' | '(' | ')' | '[' | ']' | '"' | '\''
        )
    };
    let masked: Vec<String> = text
        .split_whitespace()
        .map(|token| {
            let core = token.trim_matches(edge);
            if core.is_empty() {
                return token.to_lowercase();
            }
            let start = token.find(core).unwrap_or(0);
            let (head, rest) = token.split_at(start);
            let tail = &rest[core.len()..];
            match value_kind(core) {
                // Checked before lowercasing: an IBAN is uppercase by definition.
                Some(kind) => format!("{}<{kind}>{}", head.to_lowercase(), tail.to_lowercase()),
                None => token.to_lowercase(),
            }
        })
        .collect();
    masked.join(" ")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Tools and argument sources, one step per clause: `email.send: to from store.contacts.boss, cc forbidden`.
fn summarize(steps: &[Step]) -> String {
    steps
        .iter()
        .map(|step| {
            let rules: Vec<String> = step
                .args
                .iter()
                .filter_map(|(name, rule)| {
                    if rule.is_forbidden() {
                        Some(format!("{name} forbidden"))
                    } else {
                        rule.from.as_ref().map(|from| {
                            let sources: Vec<String> =
                                from.iter().map(ToString::to_string).collect();
                            format!("{name} from {}", sources.join("|"))
                        })
                    }
                })
                .collect();
            if rules.is_empty() {
                step.tool.as_str().to_owned()
            } else {
                format!("{}: {}", step.tool.as_str(), rules.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

impl PlanMemory {
    /// The memory in `dir` for this catalog and planner version. `planner_version` names the planner's model, effort
    /// and prompt (see `planner::version`); a change makes every older template a miss. The directory is created on
    /// the first `remember`.
    pub fn open(dir: impl Into<PathBuf>, catalog: &Catalog, planner_version: &str) -> PlanMemory {
        PlanMemory {
            dir: dir.into(),
            catalog: catalog_digest(catalog),
            planner_version: planner_version.to_owned(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The template key for a prompt and the store keys the task holds.
    pub fn key(&self, prompt_text: &str, stores: &BTreeMap<String, Vec<String>>) -> Digest {
        let mut text = format!(
            "munix plan memory {FORMAT}\nshape {}\ncatalog {}\nplanner {}\n",
            prompt_shape(prompt_text),
            self.catalog.as_str(),
            self.planner_version
        );
        for (name, keys) in stores {
            let mut keys = keys.clone();
            keys.sort();
            let _ = writeln!(text, "store {name}: {}", keys.join(","));
        }
        Digest::of_bytes(text.as_bytes())
    }

    fn exact_hash(prompt_text: &str) -> Digest {
        Digest::of_bytes(normalized(prompt_text).as_bytes())
    }

    fn path_of(&self, key: &Digest) -> PathBuf {
        let hex = key.as_str().strip_prefix("sha256:").unwrap_or(key.as_str());
        self.dir.join(format!("{hex}.json"))
    }

    fn read(path: &Path) -> Option<Template> {
        let text = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn write(&self, template: &Template) -> Result<(), MemoryError> {
        std::fs::create_dir_all(&self.dir).map_err(|e| MemoryError::Io(e.to_string()))?;
        let path = self.path_of(&template.key);
        let tmp = path.with_extension("json.tmp");
        let text =
            serde_json::to_string_pretty(template).map_err(|e| MemoryError::Io(e.to_string()))?;
        std::fs::write(&tmp, text).map_err(|e| MemoryError::Io(e.to_string()))?;
        std::fs::rename(&tmp, &path).map_err(|e| MemoryError::Io(e.to_string()))
    }

    /// The stored template for this prompt, if one matches, and how. A template is used only when its file is
    /// well-formed, it was stored under this exact key, and its catalog and planner version are the current ones.
    pub fn lookup(
        &self,
        prompt_text: &str,
        stores: &BTreeMap<String, Vec<String>>,
    ) -> Option<(Template, Level)> {
        let key = self.key(prompt_text, stores);
        let template = Self::read(&self.path_of(&key))?;
        if template.format != FORMAT
            || template.key != key
            || template.catalog != self.catalog
            || template.planner_version != self.planner_version
        {
            return None;
        }
        let level = if template.exact.contains(&Self::exact_hash(prompt_text)) {
            Level::Exact
        } else {
            Level::Shape
        };
        Some((template, level))
    }

    /// The plan for a new task from a template: the template's rules with this task's ids and prompt hash. The caller
    /// validates it against the catalog and signs it, as it would a given plan.
    pub fn instantiate(
        template: &Template,
        task: TaskId,
        plan: PlanId,
        prompt_hash: Digest,
    ) -> Plan {
        Plan {
            plan,
            task,
            prompt_hash,
            reads: template.reads.clone(),
            steps: template.steps.clone(),
            amendments: template.amendments,
        }
    }

    /// Stores the planner's plan for this prompt. Call it only after the task ended cleanly (no takeover, no off-plan
    /// denial), and only for a plan the planner wrote. An existing template for the same key is kept.
    pub fn remember(
        &self,
        plan: &Plan,
        prompt_text: &str,
        stores: &BTreeMap<String, Vec<String>>,
    ) -> Result<Template, MemoryError> {
        let key = self.key(prompt_text, stores);
        if let Some(existing) = Self::read(&self.path_of(&key)) {
            return Ok(existing);
        }
        let template = Template {
            format: FORMAT,
            key,
            catalog: self.catalog.clone(),
            planner_version: self.planner_version.clone(),
            reads: plan.reads.clone(),
            steps: plan.steps.clone(),
            amendments: plan.amendments,
            summary: summarize(&plan.steps),
            created: now(),
            uses: 0,
            exact: vec![Self::exact_hash(prompt_text)],
        };
        self.write(&template)?;
        Ok(template)
    }

    /// Counts a reuse of the template that served this prompt, and remembers the prompt's hash for exact matches.
    /// After the task, like `remember`.
    pub fn record_use(
        &self,
        prompt_text: &str,
        stores: &BTreeMap<String, Vec<String>>,
    ) -> Result<(), MemoryError> {
        let key = self.key(prompt_text, stores);
        let Some(mut template) = Self::read(&self.path_of(&key)) else {
            return Ok(());
        };
        template.uses = template.uses.saturating_add(1);
        let hash = Self::exact_hash(prompt_text);
        if !template.exact.contains(&hash) && template.exact.len() < MAX_EXACT {
            template.exact.push(hash);
        }
        self.write(&template)
    }

    /// Every readable template in `dir`, whatever its catalog or planner version, oldest first.
    pub fn list(dir: &Path) -> Vec<Template> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut out: Vec<Template> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .filter_map(|p| Self::read(&p))
            .collect();
        out.sort_by_key(|t| t.created);
        out
    }

    /// Deletes the templates whose key starts with `id` (with or without `sha256:`). Returns how many.
    pub fn forget(dir: &Path, id: &str) -> Result<usize, MemoryError> {
        let id = id.strip_prefix("sha256:").unwrap_or(id);
        if id.len() < 6 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(MemoryError::Io(
                "give at least 6 hex characters of a template id".to_owned(),
            ));
        }
        let mut removed = 0;
        for template in Self::list(dir) {
            let hex = template
                .key
                .as_str()
                .strip_prefix("sha256:")
                .unwrap_or(template.key.as_str());
            if hex.starts_with(id) {
                std::fs::remove_file(dir.join(format!("{hex}.json")))
                    .map_err(|e| MemoryError::Io(e.to_string()))?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use munix_core::manifest::ToolManifest;

    const SEND: &str = "
tool: banking.send_money
description: Send money.
tier: 3
egress: true
args:
  recipient: {type: iban, role: destination}
  amount:    {type: number, role: control}
  subject:   {type: text, role: content, max_len: 200, single_line: true}
output:
  message: {type: text, region: operator_content}
";

    fn catalog(description: &str) -> Catalog {
        Catalog::from_manifests([ToolManifest::from_yaml(
            &SEND.replace("Send money.", description),
        )
        .unwrap()])
        .unwrap()
    }

    fn plan() -> Plan {
        Plan::from_yaml(
            "
plan: P-one
task: T-one
prompt_hash: \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"
reads: [operator_content, user_content]
steps:
  - id: 1
    tool: banking.send_money
    args:
      recipient: {from: [prompt]}
      subject:   {dlp: no_secret}
    budget: 1
amendments: {auto_max_tier: 1}
",
        )
        .unwrap()
    }

    fn dir() -> PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("munix-plan-memory-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn stores() -> BTreeMap<String, Vec<String>> {
        BTreeMap::from([("contacts".to_owned(), vec!["boss".to_owned()])])
    }

    #[test]
    fn shapes_mask_typed_values_and_keep_words() {
        assert_eq!(
            prompt_shape("Pay  US133000000121212121212 $50.00 for rent on 2022-04-01, thanks!"),
            "pay <iban> <number> for rent on <date>, thanks!"
        );
        assert_eq!(
            prompt_shape(
                "Email bob@corp.example the summary of https://pixelmart.test:8080/reviews."
            ),
            "email <email> the summary of <url>."
        );
        assert_eq!(prompt_shape("Call +14155550100 now"), "call <phone> now");
        // Words are never masked: different names are different shapes.
        assert_ne!(prompt_shape("Write to Bob"), prompt_shape("Write to Alice"));
        // An IBAN is recognized before lowercasing.
        assert_eq!(prompt_shape("GB29NWBK60161331926819"), "<iban>");
    }

    #[test]
    fn a_plan_is_reused_for_the_same_prompt_and_for_swapped_values() {
        let d = dir();
        let memory = PlanMemory::open(&d, &catalog("Send money."), "meta:muse-spark-1.3@low|p1");
        let first = "Send US133000000121212121212 50 for the dinner";
        assert!(memory.lookup(first, &stores()).is_none());
        let template = memory.remember(&plan(), first, &stores()).unwrap();
        assert_eq!(
            template.summary,
            "banking.send_money: recipient from prompt"
        );

        let (hit, level) = memory.lookup(first, &stores()).unwrap();
        assert_eq!(
            (hit.key.clone(), level),
            (template.key.clone(), Level::Exact)
        );
        let (_, level) = memory
            .lookup("Send GB29NWBK60161331926819 12.5 for the dinner", &stores())
            .unwrap();
        assert_eq!(level, Level::Shape);
        // Different words, a different count of values, or other stores: a miss.
        assert!(
            memory
                .lookup("Send US133000000121212121212 50 for the rent", &stores())
                .is_none()
        );
        assert!(
            memory
                .lookup(
                    "Send US133000000121212121212 50 and 60 for the dinner",
                    &stores()
                )
                .is_none()
        );
        assert!(memory.lookup(first, &BTreeMap::new()).is_none());

        // The reused plan is the planner's, with this task's ids and prompt hash.
        let reused = PlanMemory::instantiate(
            &hit,
            "T-two".parse().unwrap(),
            "P-two".parse().unwrap(),
            Digest::of_bytes(b"new prompt"),
        );
        let original = plan();
        assert_eq!(
            (reused.reads, reused.steps, reused.amendments),
            (original.reads, original.steps, original.amendments)
        );
        assert_eq!(reused.task.as_str(), "T-two");
        assert_eq!(reused.prompt_hash, Digest::of_bytes(b"new prompt"));
    }

    #[test]
    fn a_new_catalog_or_planner_version_makes_old_templates_misses() {
        let d = dir();
        let prompt = "Send US133000000121212121212 50";
        PlanMemory::open(&d, &catalog("Send money."), "v1")
            .remember(&plan(), prompt, &stores())
            .unwrap();
        assert!(
            PlanMemory::open(&d, &catalog("Send money."), "v1")
                .lookup(prompt, &stores())
                .is_some()
        );
        assert!(
            PlanMemory::open(&d, &catalog("Send money now."), "v1")
                .lookup(prompt, &stores())
                .is_none()
        );
        assert!(
            PlanMemory::open(&d, &catalog("Send money."), "v2")
                .lookup(prompt, &stores())
                .is_none()
        );
    }

    #[test]
    fn no_prompt_text_is_stored_and_a_broken_or_moved_file_is_a_miss() {
        let d = dir();
        let memory = PlanMemory::open(&d, &catalog("Send money."), "v1");
        let prompt = "Send US133000000121212121212 50 for the secret birthday gift";
        let template = memory.remember(&plan(), prompt, &stores()).unwrap();
        let path = memory.path_of(&template.key);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("birthday") && !text.contains("US1330"),
            "{text}"
        );

        // A template copied under another key does not match it.
        let other = memory.key(
            "Send US133000000121212121212 50 for something else",
            &stores(),
        );
        std::fs::copy(&path, memory.path_of(&other)).unwrap();
        assert!(
            memory
                .lookup(
                    "Send US133000000121212121212 50 for something else",
                    &stores()
                )
                .is_none()
        );
        // A broken file is a miss, not an error.
        std::fs::write(&path, "{not json").unwrap();
        assert!(memory.lookup(prompt, &stores()).is_none());
    }

    #[test]
    fn uses_and_exact_hashes_are_recorded_and_templates_can_be_listed_and_forgotten() {
        let d = dir();
        let memory = PlanMemory::open(&d, &catalog("Send money."), "v1");
        let template = memory
            .remember(&plan(), "Send US133000000121212121212 50", &stores())
            .unwrap();
        let swapped = "Send GB29NWBK60161331926819 70";
        assert_eq!(memory.lookup(swapped, &stores()).unwrap().1, Level::Shape);
        memory.record_use(swapped, &stores()).unwrap();
        let (again, level) = memory.lookup(swapped, &stores()).unwrap();
        assert_eq!((again.uses, level), (1, Level::Exact));
        // Remembering the same key again keeps the first template.
        let kept = memory.remember(&plan(), swapped, &stores()).unwrap();
        assert_eq!(kept.created, template.created);

        let listed = PlanMemory::list(&d);
        assert_eq!(listed.len(), 1);
        assert!(PlanMemory::forget(&d, "ab").is_err());
        let hex = template.key.as_str().strip_prefix("sha256:").unwrap();
        assert_eq!(PlanMemory::forget(&d, &hex[..8]).unwrap(), 1);
        assert!(PlanMemory::list(&d).is_empty());
    }
}
