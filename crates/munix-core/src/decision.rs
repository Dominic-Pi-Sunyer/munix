//! The Supervisor's decision on one request (design spec 4.6). The Gate runs only signed decisions whose
//! `request_hash` matches the request exactly.

use crate::context::Band;
use crate::crypto::Digest;
use crate::ids::{PlanId, TaskId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Approve,
    Deny,
    ConfirmUser,
    RequireAmendment,
}

/// Which stage produced the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Deterministic,
    LlmReview,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub verdict: Verdict,
    /// Digest of the request this decision is for.
    pub request_hash: Digest,
    pub task: TaskId,
    pub plan: PlanId,
    pub band: Band,
    pub stage: Stage,
    pub reasons: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Purpose, Signed, SigningKey};
    use serde_json::json;

    fn wire() -> serde_json::Value {
        json!({
            "verdict": "approve",
            "request_hash": format!("sha256:{}", "ab".repeat(32)),
            "task": "T-91c2",
            "plan": "P-8f3a",
            "band": "20-49",
            "stage": "llm_review",
            "reasons": ["plan.step3", "to.source=contacts"]
        })
    }

    #[test]
    fn spec_example_round_trips() {
        let d: Decision = serde_json::from_value(wire()).unwrap();
        assert_eq!(d.verdict, Verdict::Approve);
        assert_eq!(d.band, Band::Restricted);
        assert_eq!(d.stage, Stage::LlmReview);
        assert_eq!(d.reasons.len(), 2);
        assert_eq!(serde_json::to_value(&d).unwrap(), wire());
    }

    #[test]
    fn verdict_and_stage_names() {
        for (v, name) in [
            (Verdict::Approve, "approve"),
            (Verdict::Deny, "deny"),
            (Verdict::ConfirmUser, "confirm_user"),
            (Verdict::RequireAmendment, "require_amendment"),
        ] {
            assert_eq!(serde_json::to_value(v).unwrap(), json!(name));
        }
        for (s, name) in [
            (Stage::Deterministic, "deterministic"),
            (Stage::LlmReview, "llm_review"),
            (Stage::User, "user"),
        ] {
            assert_eq!(serde_json::to_value(s).unwrap(), json!(name));
        }
        assert!(serde_json::from_value::<Verdict>(json!("allow")).is_err());
    }

    #[test]
    fn rejects_unknown_and_invalid_fields() {
        let mut extra = wire();
        extra["override"] = json!(true);
        assert!(serde_json::from_value::<Decision>(extra).is_err());
        let mut bad_hash = wire();
        bad_hash["request_hash"] = json!("sha256:short");
        assert!(serde_json::from_value::<Decision>(bad_hash).is_err());
        let mut bad_band = wire();
        bad_band["band"] = json!("0-100");
        assert!(serde_json::from_value::<Decision>(bad_band).is_err());
        let mut bad_task = wire();
        bad_task["task"] = json!("T 1");
        assert!(serde_json::from_value::<Decision>(bad_task).is_err());
    }

    #[test]
    fn signed_decision_binds_to_decision_purpose() {
        let key = SigningKey::from_bytes(&[9; 32]).unwrap();
        let d: Decision = serde_json::from_value(wire()).unwrap();
        let signed = Signed::sign(&key, Purpose::Decision, d.clone()).unwrap();
        assert_eq!(signed.verify(&key, Purpose::Decision).unwrap(), &d);
        assert!(signed.verify(&key, Purpose::Plan).is_err());
        let mut flipped = signed.clone();
        flipped.body.verdict = Verdict::Deny;
        assert!(flipped.verify(&key, Purpose::Decision).is_err());
        let text = serde_json::to_string(&signed).unwrap();
        let back: Signed<Decision> = serde_json::from_str(&text).unwrap();
        assert!(back.verify(&key, Purpose::Decision).is_ok());
    }
}
