//! `munix ledger [<file>]`: print a run's hash-chained ledger, one line per entry, and check the chain.
//!
//! Without a file it reads the newest `runs/*.ledger.jsonl`. Each line shows the entry's sequence number, its
//! event, and the fields an auditor reads first (tool, step, outcome, code, reasons, context trust). The last line
//! says whether every entry's hash links to the one before it. Exit code 0 when the chain verifies, 1 when it
//! doesn't, 2 for bad usage or an unreadable file.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use munix_ledger::verify_bytes;
use serde_json::Value;

const USAGE: &str = "usage: munix ledger [<file.ledger.jsonl>]";

pub fn main(args: Vec<String>) -> ExitCode {
    let path = match args.as_slice() {
        [] => match newest(Path::new("runs")) {
            Some(path) => path,
            None => {
                eprintln!("munix: no runs/*.ledger.jsonl to show");
                return ExitCode::from(2);
            }
        },
        [one] if !one.starts_with('-') => PathBuf::from(one),
        _ => {
            eprintln!("munix: {USAGE}");
            return ExitCode::from(2);
        }
    };
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("munix: cannot read {}", path.display());
        return ExitCode::from(2);
    };
    println!("{}", path.display());
    match verify_bytes(&bytes) {
        Ok(entries) => {
            for entry in &entries {
                println!("{:>4}  {}", entry.seq, summary(&entry.event));
            }
            println!(
                "chain verified: {} entries, each hash links to the one before",
                entries.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            // Show what parses, so the break is visible, but say plainly that the chain does not verify.
            for line in String::from_utf8_lossy(&bytes).lines() {
                if let Ok(entry) = serde_json::from_str::<Value>(line) {
                    let seq = entry.get("seq").and_then(Value::as_u64).unwrap_or(0);
                    println!(
                        "{seq:>4}  {}",
                        summary(entry.get("event").unwrap_or(&Value::Null))
                    );
                }
            }
            println!("CHAIN DOES NOT VERIFY: {e}");
            ExitCode::from(1)
        }
    }
}

/// The newest `*.ledger.jsonl` in `dir` by modification time.
fn newest(dir: &Path) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(".ledger.jsonl"))
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max_by_key(|(modified, _)| *modified)
        .map(|(_, p)| p)
}

/// One entry in a line: the event, then the fields that say what happened. Hashes and ids are left out.
pub fn summary(event: &Value) -> String {
    let field = |k: &str| event.get(k).filter(|v| !v.is_null());
    let text = |v: &Value| match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let mut parts = vec![field("event").map(text).unwrap_or_else(|| "?".to_owned())];
    for key in [
        "tool", "step", "outcome", "code", "stage", "verdict", "reason", "attempt", "from", "to",
        "path",
    ] {
        if let Some(v) = field(key) {
            parts.push(format!("{key}={}", text(v)));
        }
    }
    if let Some(reasons) = field("reasons").and_then(Value::as_array) {
        let reasons: Vec<String> = reasons.iter().map(text).collect();
        parts.push(format!("[{}]", reasons.join(" ")));
    }
    parts.join("  ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_ruling_reads_as_one_line_without_hashes() {
        let line = summary(&json!({
            "event": "ruling", "tool": "email.send", "step": 2, "outcome": "deny",
            "code": "untrusted_destination", "reasons": ["plan.step2", "to.trace_untrusted"],
            "request_hash": "sha256:abc", "task": "T-1"
        }));
        assert_eq!(
            line,
            "ruling  tool=email.send  step=2  outcome=deny  code=untrusted_destination  [plan.step2 to.trace_untrusted]"
        );
        assert!(!line.contains("sha256"));
    }

    #[test]
    fn context_lowered_and_tamper_show_their_numbers_and_path() {
        assert_eq!(
            summary(
                &json!({"event": "context_lowered", "tool": "web.open", "from": 100, "to": 15})
            ),
            "context_lowered  tool=web.open  from=100  to=15"
        );
        assert_eq!(
            summary(
                &json!({"event": "tamper_detected", "path": "manifests/x.yaml", "old": "a", "new": "b"})
            ),
            "tamper_detected  path=manifests/x.yaml"
        );
    }
}
