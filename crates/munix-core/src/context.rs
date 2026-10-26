//! The agent's context trust and the strictness band it selects.
//!
//! Trust only goes down within one agent instance. The only way to get a context at 100 is
//! [`ContextState::fresh`], which belongs to a new instance.

use crate::label::Trust;
use serde::{Deserialize, Serialize};

/// Strictness band from the context trust (design spec 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Band {
    #[serde(rename = "80-100")]
    Clean,
    #[serde(rename = "50-79")]
    Elevated,
    #[serde(rename = "20-49")]
    Restricted,
    #[serde(rename = "0-19")]
    Lockdown,
}

impl Band {
    /// The band for a trust score.
    pub fn of(trust: Trust) -> Band {
        match trust.value() {
            80..=100 => Band::Clean,
            50..=79 => Band::Elevated,
            20..=49 => Band::Restricted,
            _ => Band::Lockdown,
        }
    }
}

/// Context trust for one agent instance. There is deliberately no way to raise it, copy it or rebuild it:
///
/// ```compile_fail
/// let ctx = munix_core::context::ContextState::fresh();
/// let _copy = ctx.clone();
/// ```
///
/// ```compile_fail
/// let _ctx = munix_core::context::ContextState::default();
/// ```
///
/// ```compile_fail
/// let _ctx: munix_core::context::ContextState = serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail
/// let mut ctx = munix_core::context::ContextState::fresh();
/// ctx.raise_to(munix_core::label::Trust::FULL);
/// ```
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ContextState {
    trust: Trust,
}

impl ContextState {
    /// A new instance's context, at trust 100.
    pub fn fresh() -> ContextState {
        ContextState { trust: Trust::FULL }
    }

    pub fn trust(&self) -> Trust {
        self.trust
    }

    pub fn band(&self) -> Band {
        Band::of(self.trust)
    }

    /// Lowers trust to `t` if that is lower. A higher value is ignored. Returns whether trust changed.
    pub fn lower_to(&mut self, t: Trust) -> bool {
        if t < self.trust {
            self.trust = t;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bands_at_the_boundaries() {
        let cases = [
            (100, Band::Clean),
            (80, Band::Clean),
            (79, Band::Elevated),
            (50, Band::Elevated),
            (49, Band::Restricted),
            (20, Band::Restricted),
            (19, Band::Lockdown),
            (0, Band::Lockdown),
        ];
        for (t, band) in cases {
            assert_eq!(Band::of(Trust::new(t)), band, "{t}");
        }
        assert!(Band::Clean < Band::Lockdown);
    }

    #[test]
    fn band_wire_names() {
        for (band, name) in [
            (Band::Clean, "80-100"),
            (Band::Elevated, "50-79"),
            (Band::Restricted, "20-49"),
            (Band::Lockdown, "0-19"),
        ] {
            assert_eq!(serde_json::to_value(band).unwrap(), serde_json::json!(name));
            assert_eq!(
                serde_json::from_value::<Band>(serde_json::json!(name)).unwrap(),
                band
            );
        }
        assert!(serde_json::from_value::<Band>(serde_json::json!("clean")).is_err());
    }

    #[test]
    fn fresh_starts_at_100() {
        let ctx = ContextState::fresh();
        assert_eq!(ctx.trust(), Trust::FULL);
        assert_eq!(ctx.band(), Band::Clean);
    }

    #[test]
    fn lower_to_only_lowers() {
        let mut ctx = ContextState::fresh();
        assert!(ctx.lower_to(Trust::new(60)));
        assert_eq!(ctx.trust().value(), 60);
        assert_eq!(ctx.band(), Band::Elevated);
        // Raising is ignored, equal is a no-op, lowering again works.
        assert!(!ctx.lower_to(Trust::new(90)));
        assert!(!ctx.lower_to(Trust::FULL));
        assert!(!ctx.lower_to(Trust::new(60)));
        assert_eq!(ctx.trust().value(), 60);
        assert!(ctx.lower_to(Trust::new(34)));
        assert_eq!(ctx.band(), Band::Restricted);
        assert!(ctx.lower_to(Trust::ZERO));
        assert_eq!(ctx.band(), Band::Lockdown);
        assert!(!ctx.lower_to(Trust::FULL));
        assert_eq!(ctx.trust(), Trust::ZERO);
    }
}
