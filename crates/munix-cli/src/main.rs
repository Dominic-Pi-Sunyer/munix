//! `munix run [--plan <file>] --prompt <text> -- <agent command...>`,
//! `munix bridge --manifests <dir> --ledger <file> [--plan <file>]` and
//! `munix dashboard [--runs <dir>] [--port <n>]`; see [`munix_cli::run`], [`munix_cli::bridge`] and
//! [`munix_cli::dashboard`].

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("dashboard") => munix_cli::dashboard::main(args.into_iter().skip(1).collect()),
        Some("bridge") => munix_cli::bridge::main(args),
        _ => munix_cli::run::main(args),
    }
}
