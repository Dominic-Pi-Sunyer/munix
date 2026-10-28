//! `munix run [--plan <file>] --prompt <text> -- <agent command...>`,
//! `munix bridge --manifests <dir> --ledger <file> [--plan <file> [--no-reviewer] | --plan-memory <dir>]
//! [--simulated-user] [--pins <file>] [--detector-url <url> [--detector-name <name>] [--detector-threshold <0-1>]]`, `munix dashboard [--runs <dir>] [--port <n>]`, `munix ledger [<file>]` and
//! `munix plans [--dir <dir>] [list | forget <id>]`; see [`munix_cli::run`], [`munix_cli::bridge`],
//! [`munix_cli::dashboard`], [`munix_cli::ledger`] and [`munix_cli::plans`].

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("dashboard") => munix_cli::dashboard::main(args.into_iter().skip(1).collect()),
        Some("bridge") => munix_cli::bridge::main(args),
        Some("ledger") => munix_cli::ledger::main(args.into_iter().skip(1).collect()),
        Some("plans") => munix_cli::plans::main(args.into_iter().skip(1).collect()),
        _ => munix_cli::run::main(args),
    }
}
