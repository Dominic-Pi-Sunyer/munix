//! Validated identifier newtypes. Deserializing an invalid one fails, so a bad id never enters the system.

/// Defines a string newtype checked by `$check` on every construction path (parse, serde).
macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident, $what:literal, $check:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, ::serde::Serialize, ::serde::Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// The validated string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::error::Error;
            fn from_str(s: &str) -> $crate::error::Result<Self> {
                let check: fn(&str) -> bool = $check;
                if check(s) { Ok(Self(s.to_owned())) } else { Err($crate::error::invalid(concat!("invalid ", $what))) }
            }
        }

        impl TryFrom<String> for $name {
            type Error = $crate::error::Error;
            fn try_from(s: String) -> $crate::error::Result<Self> {
                s.parse()
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}
pub(crate) use string_id;

fn all_bytes(s: &str, min: usize, max: usize, ok: impl Fn(u8) -> bool) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(ok)
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_ref_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
}

string_id!(
    /// A task id: 1-64 of `[A-Za-z0-9_-]`.
    TaskId, "task id", |s| all_bytes(s, 1, 64, is_name_byte)
);
string_id!(
    /// A plan id: 1-64 of `[A-Za-z0-9_-]`.
    PlanId, "plan id", |s| all_bytes(s, 1, 64, is_name_byte)
);
string_id!(
    /// A session id: 1-64 of `[A-Za-z0-9_-]`.
    SessionId, "session id", |s| all_bytes(s, 1, 64, is_name_byte)
);
string_id!(
    /// A lowercase dotted tool name such as `web.open`: 1-64 of `[a-z0-9_.]`, no leading, trailing or double dot.
    ToolName, "tool name", |s| {
        all_bytes(s, 1, 64, |b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
            && !s.starts_with('.')
            && !s.ends_with('.')
            && !s.contains("..")
    }
);
string_id!(
    /// A Gate-held reference: `ref:` plus 1-32 of `[a-z0-9_]`.
    RefId, "ref id", |s| s.strip_prefix("ref:").is_some_and(|rest| all_bytes(rest, 1, 32, is_ref_byte))
);
string_id!(
    /// A path into the Vault: `vault://` plus `[a-z0-9_/.-]` segments (no empty, `.` or `..` segments).
    VaultRef, "vault ref", |s| {
        s.strip_prefix("vault://").is_some_and(|path| {
            all_bytes(path, 1, 128, |b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'/' | b'.' | b'-'))
                && path.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        })
    }
);

/// Finds ref tokens in free text as `(start, end, ref)` byte ranges.
///
/// A token must not be glued to a preceding `[a-z0-9_]` byte. A run of `[a-z0-9_]` after `ref:` that is longer
/// than 32 bytes is not a ref and is skipped.
pub fn find_embedded(text: &str) -> Vec<(usize, usize, RefId)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(off) = text[from..].find("ref:") {
        let start = from + off;
        from = start + 4;
        if start > 0 && is_ref_byte(bytes[start - 1]) {
            continue;
        }
        let run = bytes[start + 4..]
            .iter()
            .take_while(|b| is_ref_byte(**b))
            .count();
        if (1..=32).contains(&run) {
            let end = start + 4 + run;
            if let Ok(id) = text[start..end].parse::<RefId>() {
                found.push((start, end, id));
            }
            from = end;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_ids_accept_and_reject() {
        for ok in ["T-91c2", "a", "A_b-9", &"x".repeat(64)] {
            assert!(ok.parse::<TaskId>().is_ok(), "{ok}");
            assert!(ok.parse::<PlanId>().is_ok());
            assert!(ok.parse::<SessionId>().is_ok());
        }
        for bad in [
            "",
            " ",
            "a b",
            "a/b",
            "a.b",
            "a:b",
            "é",
            &"x".repeat(65),
            "a\n",
        ] {
            assert!(bad.parse::<TaskId>().is_err(), "{bad:?}");
            assert!(bad.parse::<PlanId>().is_err());
            assert!(bad.parse::<SessionId>().is_err());
        }
    }

    #[test]
    fn tool_names() {
        for ok in [
            "web.open",
            "email.send",
            "github.get_issue",
            "a",
            "fs.read_file2",
        ] {
            assert!(ok.parse::<ToolName>().is_ok(), "{ok}");
        }
        for bad in [
            "",
            ".a",
            "a.",
            "a..b",
            "Web.open",
            "web-open",
            "web open",
            "web/open",
            &"a".repeat(65),
        ] {
            assert!(bad.parse::<ToolName>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ref_ids() {
        assert!("ref:c1".parse::<RefId>().is_ok());
        assert!("ref:u_4".parse::<RefId>().is_ok());
        assert!(format!("ref:{}", "a".repeat(32)).parse::<RefId>().is_ok());
        for bad in [
            "ref:",
            "ref",
            "ref:A",
            "ref:a-b",
            "ref:a b",
            "Ref:a",
            " ref:a",
            "xref:a",
            &format!("ref:{}", "a".repeat(33)),
        ] {
            assert!(bad.parse::<RefId>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn vault_refs() {
        for ok in [
            "vault://mail/demo",
            "vault://gmail/oauth",
            "vault://a.b-c_d/e",
        ] {
            assert!(ok.parse::<VaultRef>().is_ok(), "{ok}");
        }
        for bad in [
            "vault://",
            "vault:/mail",
            "mail/demo",
            "vault://Mail",
            "vault://a//b",
            "vault://../x",
            "vault://a/./b",
            "vault://a b",
            "vault://a/",
        ] {
            assert!(bad.parse::<VaultRef>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn serde_validates() {
        let id: TaskId = serde_json::from_str("\"T-1\"").unwrap();
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"T-1\"");
        assert!(serde_json::from_str::<TaskId>("\"bad id\"").is_err());
        assert!(serde_json::from_str::<RefId>("\"ref:BAD\"").is_err());
        assert!(serde_json::from_str::<ToolName>("\"a..b\"").is_err());
        assert!(serde_json::from_str::<TaskId>("5").is_err());
        assert_eq!(id.to_string(), "T-1");
    }

    #[test]
    fn find_embedded_finds_tokens() {
        let text = "Top pick: ref:u4 (4.6 stars) and ref:c_1, ref:x.";
        let hits = find_embedded(text);
        let ids: Vec<&str> = hits.iter().map(|(_, _, r)| r.as_str()).collect();
        assert_eq!(ids, ["ref:u4", "ref:c_1", "ref:x"]);
        for (s, e, r) in &hits {
            assert_eq!(&text[*s..*e], r.as_str());
        }
    }

    #[test]
    fn find_embedded_skips_glued_and_overlong() {
        assert!(find_embedded("xref:a").is_empty());
        assert!(find_embedded("a_ref:a 9ref:b").is_empty());
        assert!(find_embedded("ref:").is_empty());
        assert!(find_embedded("ref: a").is_empty());
        assert!(find_embedded(&format!("ref:{}", "a".repeat(33))).is_empty());
        assert_eq!(find_embedded(&format!("ref:{}", "a".repeat(32))).len(), 1);
        // Not glued: uppercase, punctuation or start of text precede the token.
        assert_eq!(find_embedded("Xref:a").len(), 1);
        assert_eq!(find_embedded("(ref:a)").len(), 1);
        assert_eq!(find_embedded("ref:a ref:b").len(), 2);
    }

    #[test]
    fn find_embedded_handles_multibyte_text() {
        let text = "héllo ref:a1 – ünï ref:b2";
        let hits = find_embedded(text);
        assert_eq!(hits.len(), 2);
        assert_eq!(&text[hits[1].0..hits[1].1], "ref:b2");
    }
}
