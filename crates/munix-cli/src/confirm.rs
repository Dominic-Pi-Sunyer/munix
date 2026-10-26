//! The Console: the user confirms a parked request, seeing the real values and where each came from.
//!
//! The Console is the user's own screen. Its decisions are signed with `Purpose::UserConfirmation`, never
//! `Purpose::Decision`.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};

use munix_core::context::Band;
use munix_core::decision::Stage;
use munix_gate::gate::PendingView;

/// The longest value shown, in characters. A longer one is cut and says how much was left out.
const MAX_SHOWN: usize = 500;

/// Asks the user about one parked request. `true` approves.
pub trait Confirmer {
    fn confirm(&mut self, view: &PendingView) -> bool;
}

/// Asks on the terminal: prints the request to stderr and reads a `y`/`n` answer from `/dev/tty`, so the agent's
/// own stdio never answers for the user. Anything but `y` or `yes` (case-insensitive), including a read error or
/// no terminal, is a no.
#[derive(Debug, Default)]
pub struct TerminalConfirmer;

impl Confirmer for TerminalConfirmer {
    fn confirm(&mut self, view: &PendingView) -> bool {
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "\n{}\nAllow this? [y/N] ", render(view));
        let _ = stderr.flush();
        let Ok(tty) = std::fs::File::open("/dev/tty") else {
            let _ = writeln!(stderr, "\nno terminal to ask on: denied");
            return false;
        };
        let mut answer = String::new();
        if BufReader::new(tty).read_line(&mut answer).is_err() {
            return false;
        }
        is_yes(&answer)
    }
}

/// The text shown for a parked request: the tool and step, the band, then one block per argument with its value
/// as it will be sent and its sources. Values are shown as they are (this is the user's screen) but each one is
/// cut to 500 characters and stripped of control characters other than newlines, so a value can't redraw the
/// terminal.
pub fn render(view: &PendingView) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Munix needs your confirmation to run {} (plan step {}).",
        clean(view.tool.as_str()),
        view.step
    );
    let who = match view.needs {
        Stage::User => "your confirmation",
        Stage::LlmReview => "a review (asked of you until the Supervisor exists)",
        Stage::Deterministic => "a decision",
    };
    let _ = writeln!(
        out,
        "Needs {who}. Context trust band: {}.",
        band_text(view.band)
    );
    for arg in &view.args {
        let value = clean(&arg.value);
        if value.contains('\n') {
            let _ = writeln!(out, "  {}:", clean(&arg.name));
            for line in value.lines() {
                let _ = writeln!(out, "    {line}");
            }
        } else {
            let _ = writeln!(out, "  {}: {value}", clean(&arg.name));
        }
        if arg.sources.is_empty() {
            let _ = writeln!(out, "      from: nothing traced");
        } else {
            let sources: Vec<String> = arg.sources.iter().map(|s| clean(s)).collect();
            let _ = writeln!(out, "      from: {}", sources.join("; "));
        }
    }
    out
}

fn band_text(band: Band) -> &'static str {
    match band {
        Band::Clean => "80-100 (clean)",
        Band::Elevated => "50-79 (elevated)",
        Band::Restricted => "20-49 (restricted)",
        Band::Lockdown => "0-19 (lockdown)",
    }
}

fn is_yes(answer: &str) -> bool {
    let answer = answer.trim();
    answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes")
}

/// Characters that change what a terminal shows without being visible text: bidirectional controls, zero-width
/// characters, and the byte order mark.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// Strips control and invisible characters (newlines stay) and cuts the text to `MAX_SHOWN` characters.
fn clean(text: &str) -> String {
    let kept: String = text
        .chars()
        .filter(|c| *c == '\n' || !(c.is_control() || is_invisible(*c)))
        .collect();
    let total = kept.chars().count();
    if total <= MAX_SHOWN {
        return kept;
    }
    let mut cut: String = kept.chars().take(MAX_SHOWN).collect();
    let _ = write!(cut, "... [{} more characters not shown]", total - MAX_SHOWN);
    cut
}

#[cfg(test)]
mod tests {
    use munix_gate::gate::PendingArg;

    use super::*;

    fn view(args: Vec<PendingArg>) -> PendingView {
        PendingView {
            tool: "email.send".parse().unwrap(),
            step: 2,
            needs: Stage::User,
            band: Band::Lockdown,
            args,
        }
    }

    fn arg(name: &str, value: &str, sources: &[&str]) -> PendingArg {
        PendingArg {
            name: name.to_owned(),
            value: value.to_owned(),
            sources: sources.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn render_shows_the_tool_band_values_and_sources() {
        let text = render(&view(vec![
            arg(
                "to",
                "boss@corp.example",
                &["store contacts.boss (trust 100)"],
            ),
            arg("subject", "Hi", &[]),
        ]));
        assert!(text.contains("email.send"));
        assert!(text.contains("step 2"));
        assert!(text.contains("0-19 (lockdown)"));
        assert!(text.contains("to: boss@corp.example"));
        assert!(text.contains("from: store contacts.boss (trust 100)"));
        assert!(text.contains("from: nothing traced"));
    }

    #[test]
    fn render_strips_control_characters_but_keeps_newlines() {
        let text = render(&view(vec![arg(
            "body",
            "line one\x1b[2J\x1b[Hline\ttwo\r\nline three\u{202E}evil\u{200B}",
            &["step 1 reviews\x07 (ugc_review, trust 15)"],
        )]));
        assert!(!text.chars().any(|c| c.is_control() && c != '\n'));
        assert!(!text.contains('\u{202E}') && !text.contains('\u{200B}'));
        assert!(text.contains("line three"));
        assert!(text.contains("step 1 reviews (ugc_review, trust 15)"));
    }

    #[test]
    fn render_cuts_long_values() {
        let text = render(&view(vec![arg("body", &"a".repeat(2000), &[])]));
        assert!(text.contains(&"a".repeat(500)));
        assert!(!text.contains(&"a".repeat(501)));
        assert!(text.contains("1500 more characters"));
        // A value at the limit is shown whole.
        let text = render(&view(vec![arg("body", &"b".repeat(500), &[])]));
        assert!(text.contains(&"b".repeat(500)) && !text.contains("more characters"));
    }

    #[test]
    fn only_y_and_yes_approve() {
        for yes in ["y", "Y", "yes", "YES", " Yes \n"] {
            assert!(is_yes(yes), "{yes:?}");
        }
        for no in ["", "n", "no", "yep", "ye", "y es", "\n", "sure"] {
            assert!(!is_yes(no), "{no:?}");
        }
    }
}
