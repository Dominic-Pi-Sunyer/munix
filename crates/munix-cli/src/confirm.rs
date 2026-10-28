//! The Console: the user confirms a parked request, seeing the real values and where each came from.
//!
//! The Console is the user's own screen. Its decisions are signed with `Purpose::UserConfirmation`, never
//! `Purpose::Decision`.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};

use munix_core::context::Band;
use munix_core::decision::Stage;
use munix_core::label::Trust;
use munix_gate::gate::PendingView;

/// The longest value shown, in characters. A longer one is cut and says how much was left out.
const MAX_SHOWN: usize = 500;

/// Asks the user about one parked request. `true` approves.
pub trait Confirmer {
    fn confirm(&mut self, view: &PendingView) -> bool;

    /// The single reason the Console's decision carries in the ledger. Anything that is not a real person at the
    /// user's own screen must override this, so its decisions can be told apart.
    fn label(&self) -> &'static str {
        "console.user"
    }
}

/// The lowest best-match trust at which `SimulatedUser` accepts a destination that does not come from the
/// prompt, the user's data or a store.
pub const SIMULATED_USER_MIN_TRUST: u8 = 80;

/// A deterministic stand-in for the user, for the evaluation bridge only (`munix bridge --simulated-user`).
///
/// It models a careful user who reads the Console's provenance and approves only when every destination and
/// selector argument traces to something they would trust: their own prompt, their stores or data, or a record
/// at trust `SIMULATED_USER_MIN_TRUST` or more. It denies everything else: any value that traces to nothing, any
/// destination read from low-trust content, and any request with no destination or selector argument to judge.
///
/// This exists so an evaluation with no human (AgentDojo) can show how Munix behaves with a person present. It is
/// never a security mechanism and `munix run` never uses it. Its decisions are marked in the ledger by the reason
/// `console.simulated_user`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SimulatedUser;

impl Confirmer for SimulatedUser {
    fn confirm(&mut self, view: &PendingView) -> bool {
        let min = Some(Trust::new(SIMULATED_USER_MIN_TRUST));
        let mut judged = 0usize;
        for trace in view.args.iter().filter_map(|a| a.destination) {
            judged += 1;
            if !(trace.clean_side || trace.best_trust >= min) {
                return false;
            }
        }
        judged > 0
    }

    fn label(&self) -> &'static str {
        "console.simulated_user"
    }
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
    use munix_gate::gate::{DestinationTrace, PendingArg};

    use super::*;

    fn view(args: Vec<PendingArg>) -> PendingView {
        PendingView {
            tool: "email.send".parse().unwrap(),
            step: 2,
            needs: Stage::User,
            band: Band::Lockdown,
            args,
            web_unbound: false,
        }
    }

    fn arg(name: &str, value: &str, sources: &[&str]) -> PendingArg {
        PendingArg {
            name: name.to_owned(),
            value: value.to_owned(),
            sources: sources.iter().map(|s| (*s).to_owned()).collect(),
            destination: None,
        }
    }

    fn dest(name: &str, best_trust: Option<u8>, clean_side: bool) -> PendingArg {
        PendingArg {
            destination: Some(DestinationTrace {
                best_trust: best_trust.map(Trust::new),
                clean_side,
            }),
            ..arg(name, "value", &[])
        }
    }

    #[test]
    fn the_simulated_user_approves_only_traced_destinations() {
        let mut user = SimulatedUser;
        // Traces to a store (clean side).
        assert!(user.confirm(&view(vec![
            dest("to", Some(100), true),
            arg("body", "Hi", &[]),
        ])));
        // A step-sourced value at trust 85 passes, at 30 does not; the boundary is 80.
        assert!(user.confirm(&view(vec![dest("iban", Some(85), false)])));
        assert!(user.confirm(&view(vec![dest("iban", Some(80), false)])));
        assert!(!user.confirm(&view(vec![dest("iban", Some(79), false)])));
        assert!(!user.confirm(&view(vec![dest("iban", Some(30), false)])));
        // Untraced.
        assert!(!user.confirm(&view(vec![dest("iban", None, false)])));
        // One bad destination among good ones.
        assert!(!user.confirm(&view(vec![
            dest("to", Some(100), true),
            dest("cc", Some(30), false),
        ])));
        // Nothing to judge.
        assert!(!user.confirm(&view(vec![arg("body", "Hi", &[])])));
        assert!(!user.confirm(&view(vec![])));
        assert_eq!(user.label(), "console.simulated_user");
        assert_eq!(TerminalConfirmer.label(), "console.user");
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
