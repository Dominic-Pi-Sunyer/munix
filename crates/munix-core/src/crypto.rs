//! Digests, canonical JSON and purpose-bound HMAC signatures.

use crate::error::{Error, Result, invalid};
use crate::ids::string_id;
use hmac::{Hmac, Mac};
use serde::ser;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::fmt;

string_id!(
    /// `sha256:` followed by 64 lowercase hex characters.
    Digest, "digest", |s| s
        .strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
);

impl Digest {
    /// The SHA-256 digest of raw bytes.
    pub fn of_bytes(bytes: &[u8]) -> Digest {
        Digest(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }

    /// The all-zero placeholder digest (for examples and tests, never a real hash).
    pub fn zero() -> Digest {
        Digest(format!("sha256:{}", "0".repeat(64)))
    }
}

/// Errors on NaN or infinite floats anywhere in a value, which `serde_json` would silently turn into `null`.
struct Probe;
struct Walk;

macro_rules! accept {
    ($($f:ident($t:ty)),* $(,)?) => { $(fn $f(self, _v: $t) -> std::result::Result<(), serde_json::Error> { Ok(()) })* };
}

impl ser::Serializer for Probe {
    type Ok = ();
    type Error = serde_json::Error;
    type SerializeSeq = Walk;
    type SerializeTuple = Walk;
    type SerializeTupleStruct = Walk;
    type SerializeTupleVariant = Walk;
    type SerializeMap = Walk;
    type SerializeStruct = Walk;
    type SerializeStructVariant = Walk;

    accept!(
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_char(char),
        serialize_str(&str),
        serialize_bytes(&[u8]),
    );

    fn serialize_f32(self, v: f32) -> std::result::Result<(), serde_json::Error> {
        if v.is_finite() {
            Ok(())
        } else {
            Err(ser::Error::custom("non-finite float"))
        }
    }
    fn serialize_f64(self, v: f64) -> std::result::Result<(), serde_json::Error> {
        if v.is_finite() {
            Ok(())
        } else {
            Err(ser::Error::custom("non-finite float"))
        }
    }
    fn serialize_none(self) -> std::result::Result<(), serde_json::Error> {
        Ok(())
    }
    fn serialize_some<T: ?Sized + Serialize>(
        self,
        v: &T,
    ) -> std::result::Result<(), serde_json::Error> {
        v.serialize(Probe)
    }
    fn serialize_unit(self) -> std::result::Result<(), serde_json::Error> {
        Ok(())
    }
    fn serialize_unit_struct(self, _: &'static str) -> std::result::Result<(), serde_json::Error> {
        Ok(())
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> std::result::Result<(), serde_json::Error> {
        Ok(())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        v: &T,
    ) -> std::result::Result<(), serde_json::Error> {
        v.serialize(Probe)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        v: &T,
    ) -> std::result::Result<(), serde_json::Error> {
        v.serialize(Probe)
    }
    fn serialize_seq(self, _: Option<usize>) -> std::result::Result<Walk, serde_json::Error> {
        Ok(Walk)
    }
    fn serialize_tuple(self, _: usize) -> std::result::Result<Walk, serde_json::Error> {
        Ok(Walk)
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> std::result::Result<Walk, serde_json::Error> {
        Ok(Walk)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> std::result::Result<Walk, serde_json::Error> {
        Ok(Walk)
    }
    fn serialize_map(self, _: Option<usize>) -> std::result::Result<Walk, serde_json::Error> {
        Ok(Walk)
    }
    fn serialize_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> std::result::Result<Walk, serde_json::Error> {
        Ok(Walk)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> std::result::Result<Walk, serde_json::Error> {
        Ok(Walk)
    }
}

impl ser::SerializeSeq for Walk {
    type Ok = ();
    type Error = serde_json::Error;
    fn serialize_element<T: ?Sized + Serialize>(
        &mut self,
        v: &T,
    ) -> std::result::Result<(), serde_json::Error> {
        v.serialize(Probe)
    }
    fn end(self) -> std::result::Result<(), serde_json::Error> {
        Ok(())
    }
}
impl ser::SerializeTuple for Walk {
    type Ok = ();
    type Error = serde_json::Error;
    fn serialize_element<T: ?Sized + Serialize>(
        &mut self,
        v: &T,
    ) -> std::result::Result<(), serde_json::Error> {
        v.serialize(Probe)
    }
    fn end(self) -> std::result::Result<(), serde_json::Error> {
        Ok(())
    }
}
impl ser::SerializeTupleStruct for Walk {
    type Ok = ();
    type Error = serde_json::Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        v: &T,
    ) -> std::result::Result<(), serde_json::Error> {
        v.serialize(Probe)
    }
    fn end(self) -> std::result::Result<(), serde_json::Error> {
        Ok(())
    }
}
impl ser::SerializeTupleVariant for Walk {
    type Ok = ();
    type Error = serde_json::Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        v: &T,
    ) -> std::result::Result<(), serde_json::Error> {
        v.serialize(Probe)
    }
    fn end(self) -> std::result::Result<(), serde_json::Error> {
        Ok(())
    }
}
impl ser::SerializeMap for Walk {
    type Ok = ();
    type Error = serde_json::Error;
    fn serialize_key<T: ?Sized + Serialize>(
        &mut self,
        k: &T,
    ) -> std::result::Result<(), serde_json::Error> {
        k.serialize(Probe)
    }
    fn serialize_value<T: ?Sized + Serialize>(
        &mut self,
        v: &T,
    ) -> std::result::Result<(), serde_json::Error> {
        v.serialize(Probe)
    }
    fn end(self) -> std::result::Result<(), serde_json::Error> {
        Ok(())
    }
}
impl ser::SerializeStruct for Walk {
    type Ok = ();
    type Error = serde_json::Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _: &'static str,
        v: &T,
    ) -> std::result::Result<(), serde_json::Error> {
        v.serialize(Probe)
    }
    fn end(self) -> std::result::Result<(), serde_json::Error> {
        Ok(())
    }
}
impl ser::SerializeStructVariant for Walk {
    type Ok = ();
    type Error = serde_json::Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _: &'static str,
        v: &T,
    ) -> std::result::Result<(), serde_json::Error> {
        v.serialize(Probe)
    }
    fn end(self) -> std::result::Result<(), serde_json::Error> {
        Ok(())
    }
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) -> Result<()> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => serde_json::to_writer(&mut *out, s)?,
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push(b'{');
            for (i, (k, val)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, k)?;
                out.push(b':');
                write_canonical(val, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Canonical JSON: object keys sorted at every level, no whitespace. Errors on NaN or infinite floats.
pub fn canonical_json<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    v.serialize(Probe)
        .map_err(|e| invalid(format!("not canonicalizable: {e}")))?;
    let value = serde_json::to_value(v)?;
    let mut out = Vec::new();
    write_canonical(&value, &mut out)?;
    Ok(out)
}

/// The SHA-256 digest of the canonical JSON of a value.
pub fn digest<T: Serialize>(v: &T) -> Result<Digest> {
    Ok(Digest::of_bytes(&canonical_json(v)?))
}

/// A secret HMAC key of at least 32 bytes. Never printed.
#[derive(Clone)]
pub struct SigningKey(Vec<u8>);

impl SigningKey {
    /// Builds a key from at least 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 32 {
            return Err(invalid("signing key must be at least 32 bytes"));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Builds a key from hex text (at least 32 decoded bytes).
    pub fn from_hex(text: &str) -> Result<Self> {
        let bytes = hex::decode(text.trim()).map_err(|_| invalid("signing key is not hex"))?;
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

/// What a signature is for. A signature made for one purpose never verifies for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Prompt,
    Plan,
    Decision,
    UserConfirmation,
    Checkpoint,
}

impl Purpose {
    fn tag(self) -> &'static str {
        match self {
            Purpose::Prompt => "munix/v1/prompt",
            Purpose::Plan => "munix/v1/plan",
            Purpose::Decision => "munix/v1/decision",
            Purpose::UserConfirmation => "munix/v1/user-confirmation",
            Purpose::Checkpoint => "munix/v1/checkpoint",
        }
    }
}

const SIG_PREFIX: &str = "hmac-sha256:";

fn mac_for<T: Serialize>(key: &SigningKey, purpose: Purpose, body: &T) -> Result<Hmac<Sha256>> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key.0)
        .map_err(|_| invalid("signing key rejected"))?;
    mac.update(purpose.tag().as_bytes());
    mac.update(&[0]);
    mac.update(&canonical_json(body)?);
    Ok(mac)
}

/// A body plus its HMAC signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub body: T,
    pub sig: String,
}

impl<T: Serialize> Signed<T> {
    /// Signs `body` for `purpose`: HMAC-SHA256 over the purpose tag and the canonical body.
    pub fn sign(key: &SigningKey, purpose: Purpose, body: T) -> Result<Signed<T>> {
        let tag = mac_for(key, purpose, &body)?.finalize().into_bytes();
        Ok(Signed {
            body,
            sig: format!("{SIG_PREFIX}{}", hex::encode(tag)),
        })
    }

    /// Checks the signature in constant time and returns the body only when it matches the key and purpose.
    pub fn verify(&self, key: &SigningKey, purpose: Purpose) -> Result<&T> {
        let sig = self
            .sig
            .strip_prefix(SIG_PREFIX)
            .ok_or(Error::BadSignature)?;
        let sig = hex::decode(sig).map_err(|_| Error::BadSignature)?;
        mac_for(key, purpose, &self.body)?
            .verify_slice(&sig)
            .map_err(|_| Error::BadSignature)?;
        Ok(&self.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::{BTreeMap, HashMap};

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32]).unwrap()
    }

    #[test]
    fn digest_format() {
        let d = Digest::of_bytes(b"abc");
        assert_eq!(
            d.as_str(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(d.as_str().parse::<Digest>().is_ok());
        assert_eq!(Digest::zero().as_str().len(), 7 + 64);
        for bad in [
            "",
            "sha256:",
            "sha256:ABC",
            &format!("sha256:{}", "A".repeat(64)),
            &format!("sha256:{}", "0".repeat(63)),
            &format!("sha256:{}", "0".repeat(65)),
            &format!("sha1:{}", "0".repeat(64)),
            &format!("sha256:{}g", "0".repeat(63)),
        ] {
            assert!(bad.parse::<Digest>().is_err(), "{bad}");
        }
        assert!(serde_json::from_str::<Digest>("\"nope\"").is_err());
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_level() {
        let a = json!({"b": 1, "a": {"z": [1, {"y": 2, "x": 3}], "c": null}});
        assert_eq!(
            String::from_utf8(canonical_json(&a).unwrap()).unwrap(),
            r#"{"a":{"c":null,"z":[1,{"x":3,"y":2}]},"b":1}"#
        );
    }

    #[test]
    fn canonical_json_ignores_insertion_order() {
        let mut one = HashMap::new();
        let mut two = HashMap::new();
        for (i, k) in ["delta", "alpha", "charlie", "bravo", "echo"]
            .iter()
            .enumerate()
        {
            one.insert(k.to_string(), i);
        }
        for (i, k) in ["delta", "alpha", "charlie", "bravo", "echo"]
            .iter()
            .enumerate()
            .rev()
        {
            two.insert(k.to_string(), i);
        }
        assert_eq!(canonical_json(&one).unwrap(), canonical_json(&two).unwrap());
        let sorted: BTreeMap<_, _> = one.iter().collect();
        assert_eq!(
            canonical_json(&one).unwrap(),
            canonical_json(&sorted).unwrap()
        );
        assert_eq!(digest(&one).unwrap(), digest(&two).unwrap());
    }

    #[test]
    fn canonical_json_escapes_strings_and_has_no_whitespace() {
        let out =
            String::from_utf8(canonical_json(&json!({"k\"ey": "a\nb\u{1}"})).unwrap()).unwrap();
        assert_eq!(out, r#"{"k\"ey":"a\nb\u0001"}"#);
    }

    #[test]
    fn canonical_json_rejects_non_finite_floats() {
        assert!(canonical_json(&f64::NAN).is_err());
        assert!(canonical_json(&f64::INFINITY).is_err());
        assert!(canonical_json(&f32::NEG_INFINITY).is_err());
        assert!(canonical_json(&vec![1.0, f64::NAN]).is_err());
        let mut nested = BTreeMap::new();
        nested.insert("a", Some((1, f64::INFINITY)));
        assert!(canonical_json(&nested).is_err());
        assert!(digest(&f64::NAN).is_err());
        assert!(canonical_json(&1.5f64).is_ok());
    }

    #[test]
    fn signing_key_validation_and_debug() {
        assert!(SigningKey::from_bytes(&[1; 31]).is_err());
        assert!(SigningKey::from_bytes(&[1; 32]).is_ok());
        assert!(SigningKey::from_hex(&"ab".repeat(32)).is_ok());
        assert!(SigningKey::from_hex(&"ab".repeat(31)).is_err());
        assert!(SigningKey::from_hex("zz").is_err());
        let shown = format!("{:?}", key(7));
        assert_eq!(shown, "SigningKey(<redacted>)");
    }

    #[test]
    fn sign_and_verify() {
        let body = json!({"plan": "P-1", "n": 3});
        let signed = Signed::sign(&key(1), Purpose::Plan, body.clone()).unwrap();
        assert!(signed.sig.starts_with("hmac-sha256:"));
        assert_eq!(signed.sig.len(), "hmac-sha256:".len() + 64);
        assert_eq!(signed.verify(&key(1), Purpose::Plan).unwrap(), &body);
    }

    #[test]
    fn signature_fails_across_purposes() {
        let purposes = [
            Purpose::Prompt,
            Purpose::Plan,
            Purpose::Decision,
            Purpose::UserConfirmation,
            Purpose::Checkpoint,
        ];
        for signed_for in purposes {
            let signed = Signed::sign(&key(1), signed_for, json!({"a": 1})).unwrap();
            for verify_for in purposes {
                assert_eq!(
                    signed.verify(&key(1), verify_for).is_ok(),
                    signed_for == verify_for,
                    "{signed_for:?} vs {verify_for:?}"
                );
            }
        }
    }

    #[test]
    fn signature_fails_with_wrong_key() {
        let signed = Signed::sign(&key(1), Purpose::Decision, json!({"a": 1})).unwrap();
        assert!(matches!(
            signed.verify(&key(2), Purpose::Decision),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn signature_fails_after_any_body_change() {
        let signed = Signed::sign(
            &key(1),
            Purpose::Decision,
            json!({"verdict": "deny", "reasons": ["a"], "n": 1}),
        )
        .unwrap();
        for changed in [
            json!({"verdict": "approve", "reasons": ["a"], "n": 1}),
            json!({"verdict": "deny", "reasons": ["a", "b"], "n": 1}),
            json!({"verdict": "deny", "reasons": ["a"], "n": 2}),
            json!({"verdict": "deny", "reasons": ["a"], "n": 1, "extra": null}),
            json!({"verdict": "deny", "reasons": ["a"]}),
        ] {
            let tampered = Signed {
                body: changed,
                sig: signed.sig.clone(),
            };
            assert!(tampered.verify(&key(1), Purpose::Decision).is_err());
        }
    }

    #[test]
    fn signature_survives_key_reordering_but_not_malformed_sig() {
        let signed = Signed::sign(&key(1), Purpose::Plan, json!({"a": 1, "b": 2})).unwrap();
        let reordered = Signed {
            body: json!({"b": 2, "a": 1}),
            sig: signed.sig.clone(),
        };
        assert!(reordered.verify(&key(1), Purpose::Plan).is_ok());
        for sig in [
            "",
            "hmac-sha256:",
            "hmac-sha256:zz",
            "sha256:00",
            &signed.sig.to_uppercase(),
            &signed.sig[..signed.sig.len() - 2],
        ] {
            let bad = Signed {
                body: json!({"a": 1, "b": 2}),
                sig: sig.to_string(),
            };
            assert!(bad.verify(&key(1), Purpose::Plan).is_err(), "{sig}");
        }
    }

    #[test]
    fn signed_serde_denies_unknown_fields() {
        let signed = Signed::sign(&key(1), Purpose::Plan, json!({"a": 1})).unwrap();
        let text = serde_json::to_string(&signed).unwrap();
        let back: Signed<Value> = serde_json::from_str(&text).unwrap();
        assert_eq!(back, signed);
        assert!(
            serde_json::from_str::<Signed<Value>>(
                &text.replace("{\"body\"", "{\"extra\":1,\"body\"")
            )
            .is_err()
        );
    }
}
