//! Token usage, its price, and an adapter wrapper that totals both across calls.

use std::ops::{Add, AddAssign};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::{AdapterError, ModelAdapter, ModelReply, ModelRequest};

/// Tokens used by one call, or by many added together.
///
/// `reasoning_tokens` is already included in `completion_tokens`; never add the two when pricing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub reasoning_tokens: u64,
}

impl Add for Usage {
    type Output = Usage;

    fn add(self, rhs: Usage) -> Usage {
        Usage {
            prompt_tokens: self.prompt_tokens.saturating_add(rhs.prompt_tokens),
            completion_tokens: self.completion_tokens.saturating_add(rhs.completion_tokens),
            reasoning_tokens: self.reasoning_tokens.saturating_add(rhs.reasoning_tokens),
        }
    }
}

impl AddAssign for Usage {
    fn add_assign(&mut self, rhs: Usage) {
        *self = *self + rhs;
    }
}

const DEFAULT_INPUT_PER_M: f64 = 1.25;
const DEFAULT_OUTPUT_PER_M: f64 = 4.25;

/// Dollars per million tokens.
///
/// The defaults are the published Muse Spark 1.1 rates, so the result is an estimate for other models.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pricing {
    pub input_per_m: f64,
    pub output_per_m: f64,
}

impl Default for Pricing {
    fn default() -> Self {
        Self {
            input_per_m: DEFAULT_INPUT_PER_M,
            output_per_m: DEFAULT_OUTPUT_PER_M,
        }
    }
}

impl Pricing {
    /// Reads `MUNIX_PRICE_INPUT_PER_M` (default 1.25) and `MUNIX_PRICE_OUTPUT_PER_M` (default 4.25).
    /// A negative, NaN, infinite or unparsable value is a config error.
    pub fn from_env() -> Result<Self, AdapterError> {
        Self::from_vars(
            std::env::var("MUNIX_PRICE_INPUT_PER_M").ok().as_deref(),
            std::env::var("MUNIX_PRICE_OUTPUT_PER_M").ok().as_deref(),
        )
    }

    pub(crate) fn from_vars(
        input: Option<&str>,
        output: Option<&str>,
    ) -> Result<Self, AdapterError> {
        Ok(Self {
            input_per_m: parse_price("MUNIX_PRICE_INPUT_PER_M", input, DEFAULT_INPUT_PER_M)?,
            output_per_m: parse_price("MUNIX_PRICE_OUTPUT_PER_M", output, DEFAULT_OUTPUT_PER_M)?,
        })
    }

    /// Prompt tokens at the input rate plus completion tokens at the output rate. Reasoning tokens are part of
    /// the completion tokens, so they are not added again.
    pub fn cost_usd(&self, usage: &Usage) -> f64 {
        (usage.prompt_tokens as f64 * self.input_per_m
            + usage.completion_tokens as f64 * self.output_per_m)
            / 1_000_000.0
    }
}

fn parse_price(var: &str, raw: Option<&str>, default: f64) -> Result<f64, AdapterError> {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(default);
    };
    match raw.parse::<f64>() {
        Ok(v) if v.is_finite() && v >= 0.0 => Ok(v),
        _ => Err(AdapterError::Config(format!(
            "{var} must be a non-negative number"
        ))),
    }
}

#[derive(Debug, Default)]
struct Totals {
    calls: u64,
    usage: Usage,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Wraps an adapter and adds up the usage of every reply. Clones share the same totals.
#[derive(Clone)]
pub struct Metered {
    inner: Arc<dyn ModelAdapter>,
    totals: Arc<Mutex<Totals>>,
}

impl Metered {
    pub fn new(inner: Arc<dyn ModelAdapter>) -> Self {
        Self {
            inner,
            totals: Arc::new(Mutex::new(Totals::default())),
        }
    }

    /// Calls made so far (failed calls included) and the usage of the successful ones.
    pub fn total(&self) -> (u64, Usage) {
        let totals = lock(&self.totals);
        (totals.calls, totals.usage)
    }
}

impl std::fmt::Debug for Metered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metered")
            .field("inner", &self.inner.name())
            .finish_non_exhaustive()
    }
}

impl ModelAdapter for Metered {
    fn name(&self) -> String {
        self.inner.name()
    }

    fn complete_json(&self, req: &ModelRequest) -> Result<ModelReply, AdapterError> {
        let result = self.inner.complete_json(req);
        let mut totals = lock(&self.totals);
        totals.calls = totals.calls.saturating_add(1);
        if let Ok(reply) = &result {
            totals.usage += reply.usage;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(p: u64, c: u64, r: u64) -> Usage {
        Usage {
            prompt_tokens: p,
            completion_tokens: c,
            reasoning_tokens: r,
        }
    }

    #[test]
    fn usage_adds_and_saturates() {
        let mut u = usage(1, 2, 1);
        u += usage(10, 20, 5);
        assert_eq!(u, usage(11, 22, 6));
        assert_eq!(
            usage(u64::MAX, 0, 0) + usage(1, 0, 0),
            usage(u64::MAX, 0, 0)
        );
        assert_eq!(Usage::default(), usage(0, 0, 0));
    }

    #[test]
    fn defaults_are_the_published_rates() {
        let p = Pricing::from_vars(None, None).unwrap();
        assert_eq!(p, Pricing::default());
        assert_eq!((p.input_per_m, p.output_per_m), (1.25, 4.25));
        assert_eq!(Pricing::from_vars(Some(""), Some("  ")).unwrap(), p);
    }

    #[test]
    fn prices_come_from_values() {
        let p = Pricing::from_vars(Some(" 2.5 "), Some("10")).unwrap();
        assert_eq!((p.input_per_m, p.output_per_m), (2.5, 10.0));
        let free = Pricing::from_vars(Some("0"), None).unwrap();
        assert_eq!(free.input_per_m, 0.0);
    }

    #[test]
    fn bad_prices_are_config_errors() {
        for bad in ["-1", "NaN", "nan", "inf", "-inf", "abc", "1,5", "$2"] {
            for (i, o) in [(Some(bad), None), (None, Some(bad))] {
                let err = Pricing::from_vars(i, o).unwrap_err();
                assert!(matches!(err, AdapterError::Config(_)), "{bad}");
                assert!(!err.to_string().contains(bad) || bad.is_empty());
            }
        }
    }

    #[test]
    fn cost_is_prompt_times_input_plus_completion_times_output() {
        let p = Pricing::default();
        assert_eq!(p.cost_usd(&Usage::default()), 0.0);
        let cost = p.cost_usd(&usage(1_000_000, 1_000_000, 0));
        assert!((cost - 5.5).abs() < 1e-9, "{cost}");
        let cost = p.cost_usd(&usage(2_000, 500, 0));
        assert!((cost - (2_000.0 * 1.25 + 500.0 * 4.25) / 1e6).abs() < 1e-12);
        // Reasoning tokens are inside the completion tokens and cost nothing extra.
        assert_eq!(
            p.cost_usd(&usage(10, 100, 80)),
            p.cost_usd(&usage(10, 100, 0))
        );
    }
}
