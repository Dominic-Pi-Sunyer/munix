//! `munix plans [--dir <dir>] [list | forget <id>]`: review plan memory (`docs/plan-memory.md`).
//!
//! `list` (the default) prints one line per stored plan: the first 12 hex characters of its id, how often it was
//! reused, and its summary of tools and argument sources. Templates hold no prompt text, so nothing personal is
//! printed. `forget <id>` deletes the plans whose id starts with `<id>` (6 hex characters at least). The directory
//! is `--dir`, else `MUNIX_PLAN_MEMORY`, else `plan-memory`. Exit code 0 on success, 2 for bad usage.

use std::path::PathBuf;
use std::process::ExitCode;

use crate::term::terminal_safe;
use munix_supervisor::memory::PlanMemory;

const USAGE: &str = "usage: munix plans [--dir <dir>] [list | forget <id>]";
const DEFAULT_DIR: &str = "plan-memory";

pub fn main(args: Vec<String>) -> ExitCode {
    let mut rest = args.as_slice();
    let mut dir = std::env::var("MUNIX_PLAN_MEMORY")
        .ok()
        .filter(|d| !d.is_empty())
        .map_or_else(|| PathBuf::from(DEFAULT_DIR), PathBuf::from);
    if let [flag, value, tail @ ..] = rest
        && flag == "--dir"
    {
        dir = PathBuf::from(value);
        rest = tail;
    }
    match rest {
        [] => list(&dir),
        [cmd] if cmd == "list" => list(&dir),
        [cmd, id] if cmd == "forget" => match PlanMemory::forget(&dir, id) {
            Ok(n) => {
                println!("forgot {n} plan(s)");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("munix: {e}");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!("munix: {USAGE}");
            ExitCode::from(2)
        }
    }
}

fn list(dir: &std::path::Path) -> ExitCode {
    let templates = PlanMemory::list(dir);
    println!("{}: {} stored plan(s)", dir.display(), templates.len());
    for t in templates {
        let hex = t
            .key
            .as_str()
            .strip_prefix("sha256:")
            .unwrap_or(t.key.as_str());
        println!(
            "{}  uses={}  {}",
            hex.get(..12).unwrap_or(hex),
            t.uses,
            terminal_safe(&t.summary)
        );
    }
    ExitCode::SUCCESS
}
