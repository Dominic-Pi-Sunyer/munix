//! Injection detectors (invariant 7: detectors only lower trust).
//!
//! A detector is a classifier, such as Meta's Llama Prompt Guard 2, that scores text for injected instructions. It
//! returns only numbers, so nothing it says can carry an attacker's words onward. Munix uses a score in one direction
//! only: at or above the threshold, the scored value's trust drops to [`DETECTOR_FLAGGED`]; below it, nothing
//! changes. A detector that fails or answers badly counts as a flag (invariant 5: unknown means untrusted), so
//! turning a detector off or breaking it can never raise trust, only cost utility.

use crate::label::Trust;

/// The trust of a value a detector flagged: below an ad (10), above hidden (0).
pub const DETECTOR_FLAGGED: Trust = Trust::new(5);

/// The default flag threshold on a detector's injection probability.
pub const DEFAULT_THRESHOLD: f32 = 0.5;

/// Why a detector gave no usable scores. Every variant is treated as a flag.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectError {
    /// The detector could not be reached or timed out.
    #[error("detector unavailable")]
    Unavailable,
    /// The reply was malformed: wrong count, or a score outside 0..=1 or not finite.
    #[error("detector reply malformed")]
    BadReply,
}

/// Scores texts for injected instructions.
pub trait Detector: Send + Sync {
    /// A short name for the ledger, such as `Llama-Prompt-Guard-2-22M`. Fixed by Munix's config, never taken from
    /// the detector's reply.
    fn name(&self) -> &str;

    /// One injection probability in `0.0..=1.0` per text, in order. An empty input returns an empty vector
    /// without calling out.
    fn score(&self, texts: &[&str]) -> Result<Vec<f32>, DetectError>;
}

/// A detector and the threshold at which its score flags a value.
#[derive(Clone)]
pub struct DetectorConfig {
    pub detector: std::sync::Arc<dyn Detector>,
    /// Flag at `score >= threshold`. Must be finite and in `0.0..=1.0`; [`DetectorConfig::new`] checks it.
    pub threshold: f32,
}

impl DetectorConfig {
    /// `None` when the threshold is not finite or outside `0.0..=1.0`.
    pub fn new(detector: std::sync::Arc<dyn Detector>, threshold: f32) -> Option<DetectorConfig> {
        (threshold.is_finite() && (0.0..=1.0).contains(&threshold)).then_some(DetectorConfig {
            detector,
            threshold,
        })
    }

    /// Scores `texts` and returns, per text, whether it is flagged, and the highest score seen (`None` when the
    /// detector failed). A failure flags every text (fail closed). A score that is not finite or is outside
    /// `0.0..=1.0`, or a reply of the wrong length, is a failure too.
    pub fn flags(&self, texts: &[&str]) -> (Vec<bool>, Option<f32>) {
        if texts.is_empty() {
            return (Vec::new(), None);
        }
        match self.detector.score(texts) {
            Ok(scores)
                if scores.len() == texts.len()
                    && scores
                        .iter()
                        .all(|s| s.is_finite() && (0.0..=1.0).contains(s)) =>
            {
                let max = scores.iter().copied().fold(0.0f32, f32::max);
                (
                    scores.iter().map(|s| *s >= self.threshold).collect(),
                    Some(max),
                )
            }
            _ => (vec![true; texts.len()], None),
        }
    }
}

impl std::fmt::Debug for DetectorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetectorConfig")
            .field("detector", &self.detector.name())
            .field("threshold", &self.threshold)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    struct Fixed(Result<Vec<f32>, DetectError>);

    impl Detector for Fixed {
        fn name(&self) -> &str {
            "fixed"
        }
        fn score(&self, _texts: &[&str]) -> Result<Vec<f32>, DetectError> {
            self.0.clone()
        }
    }

    fn config(reply: Result<Vec<f32>, DetectError>) -> DetectorConfig {
        DetectorConfig::new(Arc::new(Fixed(reply)), 0.5).unwrap()
    }

    #[test]
    fn flags_at_or_above_threshold() {
        let (flags, max) = config(Ok(vec![0.1, 0.5, 0.9])).flags(&["a", "b", "c"]);
        assert_eq!(flags, vec![false, true, true]);
        assert_eq!(max, Some(0.9));
    }

    #[test]
    fn failures_flag_everything() {
        for reply in [
            Err(DetectError::Unavailable),
            Ok(vec![0.1]),
            Ok(vec![0.1, f32::NAN]),
            Ok(vec![0.1, 1.5]),
            Ok(vec![-0.1, 0.1]),
        ] {
            let (flags, max) = config(reply).flags(&["a", "b"]);
            assert_eq!(flags, vec![true, true]);
            assert_eq!(max, None);
        }
    }

    #[test]
    fn empty_input_calls_nothing() {
        let (flags, max) = config(Err(DetectError::Unavailable)).flags(&[]);
        assert!(flags.is_empty());
        assert_eq!(max, None);
    }

    #[test]
    fn rejects_bad_thresholds() {
        let d: Arc<dyn Detector> = Arc::new(Fixed(Ok(vec![])));
        assert!(DetectorConfig::new(d.clone(), f32::NAN).is_none());
        assert!(DetectorConfig::new(d.clone(), 1.1).is_none());
        assert!(DetectorConfig::new(d, 0.0).is_some());
    }
}
