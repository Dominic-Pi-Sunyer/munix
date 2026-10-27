//! `munix run [--plan <file>] --prompt <text> -- <agent command...>` and
//! `munix dashboard [--runs <dir>] [--port <n>]`; see [`munix_cli::run`] and [`munix_cli::dashboard`].

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("dashboard") {
        munix_cli::dashboard::main(args.into_iter().skip(1).collect())
    } else {
        munix_cli::run::main(args)
    }
}
