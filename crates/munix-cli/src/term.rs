//! Text for the operator's terminal. A value that came from a page, a tool or the ledger can hold an ESC sequence
//! (to rewrite the lines above it, retitle the window or hide text) or a line break (to start a fake line such as
//! `munix: ALLOWED ...`). Everything of that kind that is printed goes through [`terminal_safe`] first.

use munix_core::validate::is_hidden_format_char;

/// `s` with every control character, line or paragraph separator and invisible or bidi format character replaced
/// by its visible escape (`\u{1b}` for ESC, `\u{a}` for a newline), so it prints on one line and shows what it was.
pub fn terminal_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() || is_hidden_format_char(c) || c == '\u{2028}' || c == '\u{2029}' {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_separators_and_bidi_are_escaped_and_plain_text_is_kept() {
        assert_eq!(
            terminal_safe("a\u{1b}[2Jb\nc\r\td"),
            "a\\u{1b}[2Jb\\u{a}c\\u{d}\\u{9}d"
        );
        assert_eq!(
            terminal_safe("x\u{2028}y\u{2029}z"),
            "x\\u{2028}y\\u{2029}z"
        );
        assert_eq!(
            terminal_safe("a\u{202e}b\u{200b}c\u{9b}"),
            "a\\u{202e}b\\u{200b}c\\u{9b}"
        );
        assert_eq!(terminal_safe("hello wörld € 1.2.3"), "hello wörld € 1.2.3");
    }
}
