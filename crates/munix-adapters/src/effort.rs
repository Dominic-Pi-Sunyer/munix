//! Reasoning effort: how hard the model thinks before it answers. It costs tokens and time, never safety.

use std::fmt;
use std::str::FromStr;

use crate::AdapterError;

/// The values Meta's API accepts for `reasoning_effort`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ReasoningEffort {
    Minimal,
    #[default]
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

impl ReasoningEffort {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
            Self::Max => "max",
        }
    }
}

impl fmt::Display for ReasoningEffort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ReasoningEffort {
    type Err = AdapterError;

    /// Surrounding whitespace and letter case are ignored. The error never echoes the input.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "minimal" => Ok(Self::Minimal),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "xhigh" => Ok(Self::Xhigh),
            "max" => Ok(Self::Max),
            _ => Err(AdapterError::Config(
                "unknown reasoning effort (expected minimal, low, medium, high, xhigh or max)"
                    .to_string(),
            )),
        }
    }
}

/// Which part of Munix is calling the model. Each role has its own effort setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Planner,
    Reviewer,
    Reader,
    Worker,
}

impl Role {
    /// The environment variable that sets this role's effort.
    pub fn env_var(self) -> &'static str {
        match self {
            Self::Planner => "MUNIX_PLANNER_EFFORT",
            Self::Reviewer => "MUNIX_REVIEWER_EFFORT",
            Self::Reader => "MUNIX_READER_EFFORT",
            Self::Worker => "MUNIX_WORKER_EFFORT",
        }
    }
}

/// The effort for a role, read from its environment variable. Unset or empty means `low`; any other
/// unknown value is a config error, never silently ignored.
pub fn effort_for(role: Role) -> Result<ReasoningEffort, AdapterError> {
    effort_from_value(role, std::env::var(role.env_var()).ok().as_deref())
}

pub(crate) fn effort_from_value(
    role: Role,
    raw: Option<&str>,
) -> Result<ReasoningEffort, AdapterError> {
    match raw.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(ReasoningEffort::default()),
        Some(v) => v.parse().map_err(|_| {
            AdapterError::Config(format!(
                "{} is not a valid reasoning effort (expected minimal, low, medium, high, xhigh or max)",
                role.env_var()
            ))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [ReasoningEffort; 6] = [
        ReasoningEffort::Minimal,
        ReasoningEffort::Low,
        ReasoningEffort::Medium,
        ReasoningEffort::High,
        ReasoningEffort::Xhigh,
        ReasoningEffort::Max,
    ];

    #[test]
    fn wire_names_round_trip() {
        let names = ["minimal", "low", "medium", "high", "xhigh", "max"];
        for (effort, name) in ALL.into_iter().zip(names) {
            assert_eq!(effort.as_str(), name);
            assert_eq!(effort.to_string(), name);
            assert_eq!(name.parse::<ReasoningEffort>().unwrap(), effort);
        }
    }

    #[test]
    fn default_is_low() {
        assert_eq!(ReasoningEffort::default(), ReasoningEffort::Low);
    }

    #[test]
    fn parsing_trims_and_ignores_case_but_rejects_unknown_values() {
        assert_eq!(
            " High\n".parse::<ReasoningEffort>().unwrap(),
            ReasoningEffort::High
        );
        for bad in ["", "ultra", "lo", "none", "1", "low high", "SECRET-VALUE"] {
            let err = bad.parse::<ReasoningEffort>().unwrap_err();
            assert!(matches!(err, AdapterError::Config(_)), "{bad:?}");
            assert!(!err.to_string().contains("SECRET"));
        }
    }

    #[test]
    fn env_var_names_are_per_role() {
        assert_eq!(Role::Planner.env_var(), "MUNIX_PLANNER_EFFORT");
        assert_eq!(Role::Reviewer.env_var(), "MUNIX_REVIEWER_EFFORT");
        assert_eq!(Role::Reader.env_var(), "MUNIX_READER_EFFORT");
        assert_eq!(Role::Worker.env_var(), "MUNIX_WORKER_EFFORT");
    }

    #[test]
    fn unset_or_empty_means_low() {
        for raw in [None, Some(""), Some("   ")] {
            assert_eq!(
                effort_from_value(Role::Planner, raw).unwrap(),
                ReasoningEffort::Low
            );
        }
    }

    #[test]
    fn set_values_are_used_and_unknown_ones_are_config_errors() {
        assert_eq!(
            effort_from_value(Role::Reviewer, Some("xhigh")).unwrap(),
            ReasoningEffort::Xhigh
        );
        let err = effort_from_value(Role::Reader, Some("turbo")).unwrap_err();
        let AdapterError::Config(msg) = err else {
            panic!("{err:?}")
        };
        assert!(msg.contains("MUNIX_READER_EFFORT"), "{msg}");
        assert!(!msg.contains("turbo"), "{msg}");
    }
}
