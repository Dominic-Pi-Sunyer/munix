//! What the Gate knows about where a value came from. The tracer produces these facts and the policy engine
//! rules on them, so the two never depend on each other.

use munix_core::ids::RefId;
use munix_core::label::{Confidential, Trust};
use munix_core::plan::SourcePath;

/// Where a value entered the task.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// Written by the user in the signed prompt.
    Prompt,
    /// Attached or pasted by the user (labelled apart from the instructions).
    UserData,
    /// A value from an operator store, such as `contacts.boss`.
    Store { name: String, key: String },
    /// An output field of an executed plan step.
    Step { step: u32, field: String },
}

impl Origin {
    /// True when the plan's source path allows this origin. A path without a key or field allows any key or
    /// field under it.
    pub fn matches(&self, path: &SourcePath) -> bool {
        match (self, path) {
            (Origin::Prompt, SourcePath::Prompt) | (Origin::UserData, SourcePath::UserData) => true,
            (
                Origin::Store { name, key },
                SourcePath::Store {
                    name: want,
                    key: want_key,
                },
            ) => name == want && want_key.as_ref().is_none_or(|k| k == key),
            (
                Origin::Step { step, field },
                SourcePath::Step {
                    step: want,
                    field: want_field,
                },
            ) => step == want && want_field.as_ref().is_none_or(|f| f == field),
            _ => false,
        }
    }

    /// True for values the user or operator supplied before anything was read (the plan's own destinations).
    pub fn is_clean_side(&self) -> bool {
        !matches!(self, Origin::Step { .. })
    }
}

/// One place a value was found, with the label that place carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// The ref the match came from (`None` when a test builds a `Match` without a ref).
    pub id: Option<RefId>,
    pub origin: Origin,
    pub trust: Trust,
    pub confidential: Confidential,
}

/// Everything the tracer found for one value. No matches means the value is untraced, which counts as trust 0
/// (invariant 5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Traced {
    pub matches: Vec<Match>,
}

impl Traced {
    pub fn untraced() -> Traced {
        Traced::default()
    }

    /// True when some match comes from an allowed source with at least `min_trust`.
    pub fn satisfies(&self, from: &[SourcePath], min_trust: Option<Trust>) -> bool {
        self.matches.iter().any(|m| {
            from.iter().any(|p| m.origin.matches(p)) && min_trust.is_none_or(|t| m.trust >= t)
        })
    }

    /// The highest trust among the matches; 0 when untraced.
    pub fn best_trust(&self) -> Trust {
        self.matches
            .iter()
            .map(|m| m.trust)
            .max()
            .unwrap_or(Trust::ZERO)
    }
}

/// What the tracer found in one request argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgFacts {
    /// For string-shaped destination and selector arguments: one entry per value (each list element).
    pub values: Vec<Traced>,
    /// For content text: the refs embedded in it, resolved.
    pub embedded: Vec<Traced>,
    /// `ref:` tokens (as whole values or embedded) that the Gate never issued for this task.
    pub unknown_refs: u32,
    /// Raw links or addresses written straight into content text instead of embedded as refs.
    pub raw_destinations: u32,
    /// The most confidential data found in the argument, from embedded refs and from known values copied in.
    pub confidential: Confidential,
    /// True when the text contains a Vault credential, plain or encoded.
    pub contains_credential: bool,
}

impl Default for ArgFacts {
    fn default() -> Self {
        ArgFacts {
            values: Vec::new(),
            embedded: Vec::new(),
            unknown_refs: 0,
            raw_destinations: 0,
            confidential: Confidential::Public,
            contains_credential: false,
        }
    }
}
