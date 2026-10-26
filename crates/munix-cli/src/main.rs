//! `munix run --plan <file> --prompt <text> -- <agent command...>`; see `munix_cli::run`.

fn main() -> std::process::ExitCode {
    munix_cli::run::main(std::env::args().skip(1).collect())
}
