//! The user's prompt as the runtime receives it. The Supervisor signs a plan bound to this envelope's digest.

use crate::crypto::{self, Digest};
use crate::error::{Result, invalid};
use crate::ids::{SessionId, TaskId};
use crate::validate::is_clean_text;
use serde::{Deserialize, Serialize};

/// A file or blob the user attached. The content itself is held by the Gate; only its digest travels here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub name: String,
    pub content_digest: Digest,
    pub len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptEnvelope {
    pub task: TaskId,
    pub session: SessionId,
    /// A fresh random value per prompt, so a signed envelope cannot be replayed as another.
    pub nonce: String,
    pub text: String,
    pub data: Vec<Attachment>,
}

impl PromptEnvelope {
    /// Checks the nonce (8-128 printable ASCII characters, no spaces) and the attachment names (1-128 clean,
    /// single-line characters).
    pub fn validate(&self) -> Result<()> {
        let nonce_ok = (8..=128).contains(&self.nonce.len())
            && self.nonce.bytes().all(|b| (0x21..=0x7e).contains(&b));
        if !nonce_ok {
            return Err(invalid("nonce must be 8-128 printable ASCII characters"));
        }
        for a in &self.data {
            if a.name.is_empty() || a.name.chars().count() > 128 || !is_clean_text(&a.name, true) {
                return Err(invalid(
                    "attachment name must be 1-128 clean single-line characters",
                ));
            }
        }
        Ok(())
    }

    /// The digest a plan's `prompt_hash` must equal.
    pub fn digest(&self) -> Result<Digest> {
        crypto::digest(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Purpose, Signed, SigningKey};

    fn envelope() -> PromptEnvelope {
        PromptEnvelope {
            task: "T-1".parse().unwrap(),
            session: "S-1".parse().unwrap(),
            nonce: "0123456789abcdef".into(),
            text: "Read the reviews and email my boss a summary".into(),
            data: vec![Attachment {
                name: "notes.txt".into(),
                content_digest: Digest::of_bytes(b"hello"),
                len: 5,
            }],
        }
    }

    #[test]
    fn valid_envelope() {
        envelope().validate().unwrap();
    }

    #[test]
    fn nonce_rules() {
        for (nonce, ok) in [
            ("1234567", false),
            ("12345678", true),
            ("has space1", false),
            ("tab\t12345", false),
            ("", false),
        ] {
            let mut e = envelope();
            e.nonce = nonce.into();
            assert_eq!(e.validate().is_ok(), ok, "{nonce:?}");
        }
        let mut e = envelope();
        e.nonce = "a".repeat(129);
        assert!(e.validate().is_err());
        e.nonce = "a".repeat(128);
        assert!(e.validate().is_ok());
    }

    #[test]
    fn attachment_name_rules() {
        for (name, ok) in [
            ("a.txt", true),
            ("", false),
            ("a\nb", false),
            ("a\u{202e}txt.exe", false),
            ("x\u{200b}y", false),
        ] {
            let mut e = envelope();
            e.data[0].name = name.into();
            assert_eq!(e.validate().is_ok(), ok, "{name:?}");
        }
    }

    #[test]
    fn digest_changes_with_any_field() {
        let base = envelope().digest().unwrap();
        assert_eq!(base, envelope().digest().unwrap());
        let mut e = envelope();
        e.text.push('!');
        assert_ne!(e.digest().unwrap(), base);
        let mut e = envelope();
        e.nonce = "fedcba9876543210".into();
        assert_ne!(e.digest().unwrap(), base);
        let mut e = envelope();
        e.data.clear();
        assert_ne!(e.digest().unwrap(), base);
    }

    #[test]
    fn serde_denies_unknown_fields_and_signs_for_prompt_only() {
        let text = serde_json::to_string(&envelope()).unwrap();
        assert_eq!(
            serde_json::from_str::<PromptEnvelope>(&text).unwrap(),
            envelope()
        );
        assert!(
            serde_json::from_str::<PromptEnvelope>(
                &text.replace("\"nonce\"", "\"admin\":true,\"nonce\"")
            )
            .is_err()
        );
        let key = SigningKey::from_bytes(&[3; 32]).unwrap();
        let signed = Signed::sign(&key, Purpose::Prompt, envelope()).unwrap();
        assert!(signed.verify(&key, Purpose::Prompt).is_ok());
        assert!(signed.verify(&key, Purpose::Plan).is_err());
    }
}
