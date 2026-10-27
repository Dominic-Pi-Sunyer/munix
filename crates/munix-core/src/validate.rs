//! The only validators for values that cross a trust boundary. Other crates call these; none keeps its own copy.
//!
//! Machine values (email, url, id, phone, iban, date, ref) are printable ASCII only, so there are no homoglyphs.
//! Free text may carry non-ASCII letters but never control, bidi, zero-width, tag or other invisible characters.

use crate::error::{Error, invalid};
use crate::ids::RefId;
use std::fmt;
use std::str::FromStr;

/// The string-shaped and primitive value types a tool argument can have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scalar {
    Text,
    Email,
    Url,
    Phone,
    Iban,
    Id,
    Ref,
    Bool,
    Int,
    Number,
    Date,
    Enum,
}

impl Scalar {
    /// The lowercase name used in manifests.
    pub fn name(self) -> &'static str {
        match self {
            Scalar::Text => "text",
            Scalar::Email => "email",
            Scalar::Url => "url",
            Scalar::Phone => "phone",
            Scalar::Iban => "iban",
            Scalar::Id => "id",
            Scalar::Ref => "ref",
            Scalar::Bool => "bool",
            Scalar::Int => "int",
            Scalar::Number => "number",
            Scalar::Date => "date",
            Scalar::Enum => "enum",
        }
    }

    /// True for types carried as JSON strings (a Gate-held ref can stand in for these).
    pub fn is_string_shaped(self) -> bool {
        !matches!(
            self,
            Scalar::Bool | Scalar::Int | Scalar::Number | Scalar::Enum
        )
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Scalar {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match s {
            "text" => Scalar::Text,
            "email" => Scalar::Email,
            "url" => Scalar::Url,
            "phone" => Scalar::Phone,
            "iban" => Scalar::Iban,
            "id" => Scalar::Id,
            "ref" => Scalar::Ref,
            "bool" => Scalar::Bool,
            "int" => Scalar::Int,
            "number" => Scalar::Number,
            "date" => Scalar::Date,
            "enum" => Scalar::Enum,
            _ => return Err(invalid("unknown scalar type")),
        })
    }
}

/// Validates a string-shaped scalar. Always false for `Bool`, `Int`, `Number` and `Enum`.
pub fn is_valid(scalar: Scalar, s: &str) -> bool {
    match scalar {
        Scalar::Text => is_clean_text(s, false),
        Scalar::Email => is_email(s),
        Scalar::Url => is_url(s),
        Scalar::Phone => is_phone(s),
        Scalar::Iban => is_iban(s),
        Scalar::Id => is_id(s),
        Scalar::Ref => s.parse::<RefId>().is_ok(),
        Scalar::Date => is_date(s),
        Scalar::Bool | Scalar::Int | Scalar::Number | Scalar::Enum => false,
    }
}

/// Characters that are invisible or that reorder or hide text, which free text must never contain.
fn is_hidden_format_char(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD                  // soft hyphen
        | 0x061C                // Arabic letter mark
        | 0x180E                // Mongolian vowel separator
        | 0x200B..=0x200F       // zero-width space/joiners, LRM, RLM
        | 0x2028..=0x202E       // line/paragraph separators, bidi embeddings and overrides
        | 0x2060..=0x206F       // word joiner, invisible operators, bidi isolates, deprecated format controls
        | 0xFE00..=0xFE0F       // variation selectors
        | 0xFEFF                // zero-width no-break space / BOM
        | 0xFFF9..=0xFFFB       // interlinear annotation
        | 0x1D173..=0x1D17A     // musical format controls
        | 0xE0000..=0xE007F     // tag block
        | 0xE0100..=0xE01EF     // variation selectors supplement
    )
}

/// Free text with no control characters (except `\n` and `\t`) and no invisible or bidi characters.
/// With `single_line`, `\n` is rejected as well.
pub fn is_clean_text(s: &str, single_line: bool) -> bool {
    s.chars().all(|c| {
        if c == '\n' {
            !single_line
        } else if c == '\t' {
            true
        } else {
            !c.is_control() && !is_hidden_format_char(c)
        }
    })
}

/// Non-empty printable ASCII with no spaces.
fn is_machine(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

const INTERNAL_TLDS: &[&str] = &[
    "internal",
    "local",
    "localhost",
    "lan",
    "intranet",
    "home",
    "arpa",
    "corp",
    "private",
    "invalid",
    "onion",
];

/// Services whose subdomains resolve to whatever address is spelled in the name (DNS rebinding helpers).
const REBINDING_DOMAINS: &[&str] = &[
    "nip.io",
    "sslip.io",
    "xip.io",
    "localtest.me",
    "lvh.me",
    "traefik.me",
];

/// A public-looking DNS name: at least two labels, letters/digits/hyphens, an alphabetic (or `xn--`) top-level
/// label. Rejects IP literals of any form, `localhost`, internal TLDs and DNS-rebinding services.
/// `.test` and `.example` are fine.
pub fn is_hostname(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    let lower = h.to_ascii_lowercase();
    let labels: Vec<&str> = lower.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if !labels.iter().all(|l| label_ok(l)) {
        return false;
    }
    let tld = labels[labels.len() - 1];
    let tld_ok =
        tld.bytes().all(|b| b.is_ascii_lowercase()) || (tld.starts_with("xn--") && tld.len() > 4);
    if !tld_ok || INTERNAL_TLDS.contains(&tld) {
        return false;
    }
    !REBINDING_DOMAINS
        .iter()
        .any(|d| lower == *d || lower.ends_with(&format!(".{d}")))
}

fn is_port(p: &str) -> bool {
    (1..=5).contains(&p.len())
        && p.bytes().all(|b| b.is_ascii_digit())
        && !p.starts_with('0')
        && p.parse::<u32>().is_ok_and(|n| n <= 65535)
}

/// `http://` or `https://`, a valid hostname, an optional port, no userinfo, no backslash, at most 2048 chars.
pub fn is_url(s: &str) -> bool {
    if s.len() > 2048 || !is_machine(s) || s.contains('\\') {
        return false;
    }
    let rest = match (s.get(..7), s.get(..8)) {
        (_, Some(p)) if p.eq_ignore_ascii_case("https://") => &s[8..],
        (Some(p), _) if p.eq_ignore_ascii_case("http://") => &s[7..],
        _ => return false,
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.contains('@') {
        return false;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    port.is_none_or(is_port) && is_hostname(host)
}

/// `local@host`: local part 1-64 of `[A-Za-z0-9._+-]` (not starting with `.` or `-`, no `..`, not ending with `.`),
/// a valid hostname, at most 254 chars.
pub fn is_email(s: &str) -> bool {
    if s.len() > 254 || !is_machine(s) {
        return false;
    }
    let Some((local, host)) = s.rsplit_once('@') else {
        return false;
    };
    (1..=64).contains(&local.len())
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
        && !local.starts_with(['.', '-'])
        && !local.ends_with('.')
        && !local.contains("..")
        && is_hostname(host)
}

/// 1-128 of `[A-Za-z0-9._:-]`. No path syntax.
pub fn is_id(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Optional `+`, then 4-20 digits.
pub fn is_phone(s: &str) -> bool {
    let digits = s.strip_prefix('+').unwrap_or(s);
    (4..=20).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit())
}

/// An International Bank Account Number by shape only: two uppercase ASCII letters, two ASCII digits, then 10-30
/// uppercase ASCII letters or digits (14-34 characters in all), with no spaces.
///
/// There is deliberately no mod-97 checksum and no country-code list: AgentDojo's test data uses synthetic numbers
/// and a non-ISO country code ("UK"), which a checksum would reject. Lowercase is invalid; callers must not
/// normalize silently, because a changed destination would no longer match what the user wrote.
pub fn is_iban(s: &str) -> bool {
    let b = s.as_bytes();
    (14..=34).contains(&b.len())
        && b[..2].iter().all(u8::is_ascii_uppercase)
        && b[2..4].iter().all(u8::is_ascii_digit)
        && b[4..]
            .iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// `YYYY-MM-DD` that is a real calendar date (year 0001 or later).
pub fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = &s[r];
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (Some(y), Some(m), Some(d)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => 28 + u32::from(leap),
        _ => return false,
    };
    y >= 1 && (1..=days).contains(&d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_names_round_trip() {
        for s in [
            Scalar::Text,
            Scalar::Email,
            Scalar::Url,
            Scalar::Phone,
            Scalar::Iban,
            Scalar::Id,
            Scalar::Ref,
            Scalar::Bool,
            Scalar::Int,
            Scalar::Number,
            Scalar::Date,
            Scalar::Enum,
        ] {
            assert_eq!(s.name().parse::<Scalar>().unwrap(), s);
            assert_eq!(s.to_string(), s.name());
        }
        assert!("Text".parse::<Scalar>().is_err());
        assert!("string".parse::<Scalar>().is_err());
    }

    #[test]
    fn non_string_scalars_never_validate_as_strings() {
        for s in [Scalar::Bool, Scalar::Int, Scalar::Number, Scalar::Enum] {
            assert!(!is_valid(s, "true"));
            assert!(!is_valid(s, "1"));
            assert!(!s.is_string_shaped());
        }
        assert!(Scalar::Text.is_string_shaped());
    }

    #[test]
    fn text_accepts_normal_content() {
        assert!(is_clean_text("", false));
        assert!(is_clean_text(
            "Hello, world! Ünïcödé, 日本語, emoji 🙂",
            false
        ));
        assert!(is_clean_text("line one\nline two\ttabbed", false));
        assert!(is_clean_text("tabs\tare fine on one line", true));
        assert!(is_valid(Scalar::Text, "plain"));
    }

    #[test]
    fn text_rejects_control_characters() {
        for bad in [
            "a\u{0}b",
            "a\u{7}b",
            "a\rb",
            "a\u{1b}[31m",
            "a\u{7f}b",
            "a\u{85}b",
            "a\u{9f}b",
        ] {
            assert!(!is_clean_text(bad, false), "{bad:?}");
        }
    }

    #[test]
    fn single_line_rejects_line_breaks() {
        assert!(!is_clean_text("a\nb", true));
        assert!(!is_clean_text("a\rb", true));
        assert!(!is_clean_text("a\u{2028}b", true));
        assert!(is_clean_text("a\nb", false));
    }

    #[test]
    fn text_rejects_bidi_controls() {
        for c in [
            '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
            '\u{202E}',
        ] {
            assert!(!is_clean_text(&format!("a{c}b"), false), "{:x}", c as u32);
        }
        for c in '\u{2066}'..='\u{2069}' {
            assert!(!is_clean_text(&format!("a{c}b"), false), "{:x}", c as u32);
        }
    }

    #[test]
    fn text_rejects_zero_width_tags_and_invisibles() {
        for c in [
            '\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}',
            '\u{2064}', '\u{FEFF}',
        ] {
            assert!(
                !is_clean_text(&format!("pass{c}word"), false),
                "{:x}",
                c as u32
            );
        }
        // The tag block hides a whole message inside normal-looking text.
        let hidden: String = "ignore previous"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).unwrap())
            .collect();
        assert!(!is_clean_text(&format!("nice review{hidden}"), false));
        assert!(!is_clean_text("x\u{E0001}y", false));
        for c in [
            '\u{00AD}',
            '\u{180E}',
            '\u{FFF9}',
            '\u{FFFA}',
            '\u{FFFB}',
            '\u{FE00}',
            '\u{FE0F}',
            '\u{E0100}',
        ] {
            assert!(!is_clean_text(&format!("a{c}b"), false), "{:x}", c as u32);
        }
    }

    #[test]
    fn hostnames_accept() {
        for ok in [
            "example.com",
            "pixelmart.test",
            "shop.pixelmart.test",
            "a.example",
            "EXAMPLE.COM",
            "my-site.co.uk",
            "xn--bcher-kva.de",
            "site.xn--p1ai",
            "a1.b2.org",
        ] {
            assert!(is_hostname(ok), "{ok}");
        }
    }

    #[test]
    fn hostnames_reject_ip_literals_of_any_form() {
        for bad in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "2130706433",
            "0x7f000001",
            "0x7f.0.0.1",
            "0177.0.0.1",
            "127.1",
            "1.2.3.4.5",
            "[::1]",
            "::1",
            "[2001:db8::1]",
            "999.999.999.999",
            "127.0.0.0x1",
        ] {
            assert!(!is_hostname(bad), "{bad}");
        }
    }

    #[test]
    fn hostnames_reject_internal_and_rebinding() {
        for bad in [
            "localhost",
            "foo.localhost",
            "printer.local",
            "db.internal",
            "router.lan",
            "wiki.intranet",
            "nas.home",
            "x.in-addr.arpa",
            "ad.corp",
            "box.private",
            "a.invalid",
            "hidden.onion",
            "127.0.0.1.nip.io",
            "nip.io",
            "a.sslip.io",
            "a.xip.io",
            "x.localtest.me",
            "localtest.me",
        ] {
            assert!(!is_hostname(bad), "{bad}");
        }
    }

    #[test]
    fn hostnames_reject_malformed() {
        for bad in [
            "",
            "com",
            "example",
            ".com",
            "example.",
            "example.com.",
            "a..com",
            "-a.com",
            "a-.com",
            "a_b.com",
            "a b.com",
            "exam\u{e9}ple.com",
            "example.c0m",
            "example.123",
            "example.xn--",
            "ex ample.com",
        ] {
            assert!(!is_hostname(bad), "{bad:?}");
        }
        assert!(is_hostname(&format!("{}.com", "a".repeat(63))));
        assert!(!is_hostname(&format!("{}.com", "a".repeat(64))));
        assert!(!is_hostname(&format!(
            "{}.com",
            vec!["a".repeat(60); 5].join(".")
        )));
    }

    #[test]
    fn urls_accept() {
        for ok in [
            "https://example.com",
            "http://pixelmart.test:8080/x",
            "https://shop.example.com/path/to?q=1&r=2#frag",
            "HTTPS://Example.com/",
            "http://a.test:1",
            "http://a.test:65535/",
            "https://example.com:443?x=1",
        ] {
            assert!(is_url(ok), "{ok}");
            assert!(is_valid(Scalar::Url, ok));
        }
    }

    #[test]
    fn urls_reject() {
        for bad in [
            "",
            "example.com",
            "ftp://example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "//example.com",
            "https://",
            "http://127.0.0.1/",
            "http://127.0.0.1:8080/",
            "http://localhost/",
            "http://localhost:3000",
            "http://[::1]/",
            "http://printer.local/",
            "http://1.2.3.4.nip.io/",
            "http://user@example.com/",
            "http://user:pw@example.com/",
            "http://example.com@evil.test/",
            "http://example.com\\@evil.test/",
            "http://example.com\\evil.test",
            "https://example.com/a b",
            "https://example.com/\u{202e}",
            "https://exämple.com/",
            "http://example.com:0/",
            "http://example.com:01/",
            "http://example.com:65536/",
            "http://example.com:123456/",
            "http://example.com:/",
            "http://example.com:80a/",
            "https://example.com/\n",
        ] {
            assert!(!is_url(bad), "{bad:?}");
        }
        let long = format!("https://example.com/{}", "a".repeat(2048));
        assert!(!is_url(&long));
        let max = format!(
            "https://example.com/{}",
            "a".repeat(2048 - "https://example.com/".len())
        );
        assert_eq!(max.len(), 2048);
        assert!(is_url(&max));
    }

    #[test]
    fn emails() {
        for ok in [
            "boss@example.com",
            "a.b+tag@pixelmart.test",
            "x_y-z@sub.example.co",
            "1@a.example",
        ] {
            assert!(is_email(ok), "{ok}");
        }
        for bad in [
            "",
            "boss",
            "@example.com",
            "boss@",
            "boss@localhost",
            "boss@127.0.0.1",
            "boss@[::1]",
            "boss@example",
            ".boss@example.com",
            "-boss@example.com",
            "bo..ss@example.com",
            "boss.@example.com",
            "bo ss@example.com",
            "bo@ss@example.com",
            "bo\u{e9}@example.com",
            "boss@exa\u{e9}mple.com",
            "boss@example.com\n",
            "\"quoted\"@example.com",
            "boss@example.com,evil@example.com",
            "boss@example.com;evil@example.com",
            "boss<a@example.com>",
        ] {
            assert!(!is_email(bad), "{bad:?}");
        }
        assert!(is_email(&format!("{}@example.com", "a".repeat(64))));
        assert!(!is_email(&format!("{}@example.com", "a".repeat(65))));
        let long_host = format!("a@{}.com", vec!["b".repeat(60); 4].join("."));
        assert!(long_host.len() <= 254 && is_email(&long_host));
        let too_long = format!("a@{}.com", vec!["b".repeat(60); 5].join("."));
        assert!(too_long.len() > 254 && !is_email(&too_long));
    }

    #[test]
    fn ibans_by_shape_only() {
        for ok in [
            "GB29NWBK60161331926819",
            "UK12345678901234567890",
            "SE3550000000054910000003",
            "US133000000121212121212",
            "AB12ABCDEFGHIJ",
            &format!("DE00{}", "A".repeat(30)),
        ] {
            assert!(is_valid(Scalar::Iban, ok), "{ok}");
        }
        for bad in [
            "",
            "gb29nwbk60161331926819",
            "GB29nwbk60161331926819",
            "GB29NWBK6016",
            "AB12ABCDEFGHI",
            &format!("DE00{}", "A".repeat(31)),
            "GB29 NWBK 6016 1331 9268 19",
            "GB29NWBK60161331926819 ",
            "1B29NWBK60161331926819",
            "GBX9NWBK60161331926819",
            "GB29NWBK-0161331926819",
            "G\u{412}29NWBK60161331926819",
            "GB29NWBK60161331926\u{ff11}19",
            "GB29NWBK60161331926819\n",
        ] {
            assert!(!is_valid(Scalar::Iban, bad), "{bad:?}");
        }
        assert!(Scalar::Iban.is_string_shaped());
    }

    #[test]
    fn ids_phones_dates_refs() {
        for ok in ["abc", "A-1_2.3:4", &"a".repeat(128)] {
            assert!(is_valid(Scalar::Id, ok), "{ok}");
        }
        for bad in ["", "a/b", "../x", "a b", "a\n", "a\u{e9}", &"a".repeat(129)] {
            assert!(!is_valid(Scalar::Id, bad), "{bad:?}");
        }
        for ok in ["+14155550123", "5551234", "1234"] {
            assert!(is_valid(Scalar::Phone, ok), "{ok}");
        }
        for bad in [
            "",
            "+",
            "123",
            "+123",
            "12 34",
            "(415)5550123",
            "++1234",
            "1234567890123456789012",
            "+1234a",
            "+\u{ff11}\u{ff12}\u{ff13}\u{ff14}",
        ] {
            assert!(!is_valid(Scalar::Phone, bad), "{bad:?}");
        }
        for ok in [
            "2026-10-26",
            "2024-02-29",
            "2000-02-29",
            "0001-01-01",
            "2026-12-31",
        ] {
            assert!(is_valid(Scalar::Date, ok), "{ok}");
        }
        for bad in [
            "",
            "2026-13-01",
            "2026-00-10",
            "2026-02-29",
            "1900-02-29",
            "2026-04-31",
            "2026-1-01",
            "26-10-26",
            "2026/10/26",
            "2026-10-26 ",
            "0000-01-01",
            "2026-10-2a",
            "+026-10-26",
        ] {
            assert!(!is_valid(Scalar::Date, bad), "{bad:?}");
        }
        assert!(is_valid(Scalar::Ref, "ref:u4"));
        assert!(!is_valid(Scalar::Ref, "u4"));
        assert!(!is_valid(Scalar::Ref, "ref:U4"));
    }

    #[test]
    fn machine_values_reject_homoglyphs() {
        // Cyrillic 'а' (U+0430) looks like Latin 'a'.
        assert!(!is_email("b\u{430}ss@example.com"));
        assert!(!is_url("https://ex\u{430}mple.com/"));
        assert!(!is_valid(Scalar::Id, "\u{430}bc"));
    }
}
