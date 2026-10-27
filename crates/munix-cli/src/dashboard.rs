//! `munix dashboard`: read-only live view of the hash-chained ledger files in `runs/`.
//!
//! ```text
//! munix dashboard [--runs <dir>] [--port <n>]
//! ```
//!
//! Binds `127.0.0.1:<port>` only and serves the self-contained dashboard page plus `/api/runs` and
//! `/api/runs/<id>`. It never opens a ledger for writing or modifies anything on disk.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::UNIX_EPOCH;

use munix_core::ids::TaskId;
use munix_ledger::verify_bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tiny_http::{Header, Method, Response, Server, StatusCode};

const USAGE: &str = "usage: munix dashboard [--runs <dir>] [--port <n>]";
const DEFAULT_RUNS: &str = "runs";
const DEFAULT_PORT: u16 = 8090;
const LEDGER_SUFFIX: &str = ".ledger.jsonl";
const PAGE: &str = include_str!("../dashboard/index.html");
const CONTENT_TYPE_HTML: &str = "text/html; charset=utf-8";
const CONTENT_TYPE_JSON: &str = "application/json";
const CSP_VALUE: &str =
    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'";

/// What `munix dashboard` was asked to do.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    runs: PathBuf,
    port: u16,
}

/// Summary of one ledger file returned by `/api/runs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RunSummary {
    task: String,
    entries: usize,
    verified: bool,
    error: Option<String>,
    modified_ms: u64,
    last_event: Option<String>,
}

/// One entry in the `/api/runs/<id>` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EntryView {
    seq: u64,
    ts_ms: u64,
    event: Value,
}

/// Full run view returned by `/api/runs/<id>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RunDetail {
    task: String,
    verified: bool,
    error: Option<String>,
    entries: Vec<EntryView>,
}

/// Loose line shape used when `verify_bytes` fails so intact lines can still be shown.
#[derive(Deserialize)]
struct LooseLine {
    seq: u64,
    ts_ms: u64,
    event: Value,
}

/// Result of reading and verifying one ledger file.
struct LoadedLedger {
    verified: bool,
    error: Option<String>,
    entries: Vec<EntryView>,
}

/// Entrypoint for `munix dashboard`.
pub fn main(args: Vec<String>) -> ExitCode {
    let opts = match parse_args(&args) {
        Ok(opts) => opts,
        Err(msg) => {
            eprintln!("munix: {msg}");
            return ExitCode::from(2);
        }
    };
    let server = match Server::http(("127.0.0.1", opts.port)) {
        Ok(server) => server,
        Err(e) => {
            eprintln!("munix: could not bind 127.0.0.1:{}: {e}", opts.port);
            return ExitCode::from(1);
        }
    };
    eprintln!("munix: dashboard at http://127.0.0.1:{}", opts.port);
    for request in server.incoming_requests() {
        let host = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Host"))
            .map(|h| h.value.as_str().to_owned());
        let (status, content_type, body) = if !host_allowed(host.as_deref(), opts.port) {
            (403, CONTENT_TYPE_JSON, br#"{"error":"forbidden"}"#.to_vec())
        } else if request.method() == &Method::Get {
            route(&opts.runs, request.url())
        } else {
            (
                405,
                CONTENT_TYPE_JSON,
                br#"{"error":"method not allowed"}"#.to_vec(),
            )
        };
        let mut response = Response::from_data(body).with_status_code(StatusCode(status));
        for header in response_headers(content_type) {
            response.add_header(header);
        }
        let _ = request.respond(response);
    }
    ExitCode::SUCCESS
}

/// Only the loopback names for this port, so a web page that rebinds its own domain to 127.0.0.1 can't read the
/// ledger through the visitor's browser.
fn host_allowed(host: Option<&str>, port: u16) -> bool {
    host.is_some_and(|h| h == format!("127.0.0.1:{port}") || h == format!("localhost:{port}"))
}

/// Parses `[--runs <dir>] [--port <n>]`.
fn parse_args(args: &[String]) -> Result<Options, &'static str> {
    let mut runs: Option<PathBuf> = None;
    let mut port: Option<u16> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--runs" => {
                let val = it.next().ok_or(USAGE)?;
                if val.is_empty() {
                    return Err(USAGE);
                }
                runs = Some(PathBuf::from(val));
            }
            "--port" => {
                let val = it.next().ok_or(USAGE)?;
                let parsed: u16 = val.parse().map_err(|_| USAGE)?;
                if parsed == 0 {
                    return Err(USAGE);
                }
                port = Some(parsed);
            }
            _ => return Err(USAGE),
        }
    }
    Ok(Options {
        runs: runs.unwrap_or_else(|| PathBuf::from(DEFAULT_RUNS)),
        port: port.unwrap_or(DEFAULT_PORT),
    })
}

/// Builds the HTTP headers for a dashboard response.
fn response_headers(content_type: &'static str) -> Vec<Header> {
    let mut out = Vec::with_capacity(4);
    if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes()) {
        out.push(h);
    }
    if let Ok(h) = Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]) {
        out.push(h);
    }
    if let Ok(h) = Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]) {
        out.push(h);
    }
    if content_type == CONTENT_TYPE_HTML
        && let Ok(h) = Header::from_bytes(&b"Content-Security-Policy"[..], CSP_VALUE.as_bytes())
    {
        out.push(h);
    }
    out
}

/// Pure routing function for `GET` requests, testable without opening a socket.
fn route(runs: &Path, url: &str) -> (u16, &'static str, Vec<u8>) {
    let path = url.split('?').next().unwrap_or(url);
    if path == "/" {
        return (200, CONTENT_TYPE_HTML, PAGE.as_bytes().to_vec());
    }
    if path == "/api/runs" {
        let list = list_runs(runs);
        let body = serde_json::to_vec(&list).unwrap_or_else(|_| b"[]".to_vec());
        return (200, CONTENT_TYPE_JSON, body);
    }
    if let Some(raw_id) = path.strip_prefix("/api/runs/") {
        let Ok(task_id) = raw_id.parse::<TaskId>() else {
            return not_found();
        };
        let file = ledger_path(runs, &task_id);
        let Ok(bytes) = fs::read(&file) else {
            return not_found();
        };
        let loaded = parse_ledger_bytes(&bytes);
        let detail = RunDetail {
            task: task_id.as_str().to_owned(),
            verified: loaded.verified,
            error: loaded.error,
            entries: loaded.entries,
        };
        let body = serde_json::to_vec(&detail)
            .unwrap_or_else(|_| br#"{"error":"serialization failed"}"#.to_vec());
        return (200, CONTENT_TYPE_JSON, body);
    }
    not_found()
}

fn not_found() -> (u16, &'static str, Vec<u8>) {
    (404, CONTENT_TYPE_JSON, br#"{"error":"not found"}"#.to_vec())
}

/// Builds `<runs>/<task_id>.ledger.jsonl` from an already-validated [`TaskId`].
fn ledger_path(runs: &Path, task_id: &TaskId) -> PathBuf {
    runs.join(format!("{}{LEDGER_SUFFIX}", task_id.as_str()))
}

/// Lists valid `<id>.ledger.jsonl` files directly inside `runs`, newest first by modified time.
fn list_runs(runs: &Path) -> Vec<RunSummary> {
    let Ok(dir) = fs::read_dir(runs) else {
        return Vec::new();
    };
    let mut summaries = Vec::new();
    for entry in dir.flatten() {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if !ft.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(stem) = name.strip_suffix(LEDGER_SUFFIX) else {
            continue;
        };
        let Ok(task_id) = stem.parse::<TaskId>() else {
            continue;
        };
        let path = ledger_path(runs, &task_id);
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let modified_ms = fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let loaded = parse_ledger_bytes(&bytes);
        let last_event = loaded
            .entries
            .last()
            .and_then(|e| e.event.get("event"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        summaries.push(RunSummary {
            task: task_id.as_str().to_owned(),
            entries: loaded.entries.len(),
            verified: loaded.verified,
            error: loaded.error,
            modified_ms,
            last_event,
        });
    }
    summaries.sort_by(|a, b| {
        b.modified_ms
            .cmp(&a.modified_ms)
            .then_with(|| a.task.cmp(&b.task))
    });
    summaries
}

/// Keeps bytes up to and including the last `b'\n'`, verifies the hash chain with [`verify_bytes`], and falls
/// back to line-by-line JSON parsing if verification fails.
fn parse_ledger_bytes(bytes: &[u8]) -> LoadedLedger {
    let trimmed = match bytes.iter().rposition(|&b| b == b'\n') {
        Some(pos) => &bytes[..=pos],
        None => &[][..],
    };
    match verify_bytes(trimmed) {
        Ok(entries) => LoadedLedger {
            verified: true,
            error: None,
            entries: entries
                .into_iter()
                .map(|e| EntryView {
                    seq: e.seq,
                    ts_ms: e.ts_ms,
                    event: e.event,
                })
                .collect(),
        },
        Err(err) => {
            let mut entries = Vec::new();
            for raw in trimmed
                .split(|&b| b == b'\n')
                .filter(|line| !line.is_empty())
            {
                if let Ok(parsed) = serde_json::from_slice::<LooseLine>(raw) {
                    entries.push(EntryView {
                        seq: parsed.seq,
                        ts_ms: parsed.ts_ms,
                        event: parsed.event,
                    });
                }
            }
            LoadedLedger {
                verified: false,
                error: Some(err.to_string()),
                entries,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    use munix_ledger::Ledger;
    use serde_json::json;

    use super::*;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("munix-dashboard-test-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn write_sample_ledger(path: &Path, task: &str) {
        let mut ledger = Ledger::create(path).unwrap();
        ledger
            .append(json!({
                "event": "tool_registered",
                "tool": "web.open",
                "manifest_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            }))
            .unwrap();
        ledger
            .append(json!({
                "event": "task_started",
                "task": task,
                "plan": "P-1",
                "seal": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            }))
            .unwrap();
        ledger
            .append(json!({
                "event": "ruling",
                "task": task,
                "step": 1,
                "tool": "web.open",
                "outcome": "allow",
                "reasons": ["plan.step1"]
            }))
            .unwrap();
    }

    #[test]
    fn root_serves_self_contained_html_without_inner_html() {
        let tmp = TempDir::new();
        let (status, content_type, body) = route(&tmp.path, "/?ignored=1");
        assert_eq!(status, 200);
        assert_eq!(content_type, "text/html; charset=utf-8");
        let html = String::from_utf8(body).unwrap();
        assert!(html.contains("Munix"));
        assert!(!html.contains("innerHTML"));
        assert!(!html.contains("insertAdjacentHTML"));
        let headers = response_headers(content_type);
        assert!(
            headers
                .iter()
                .any(|h| h.field.equiv("Content-Security-Policy"))
        );
        assert!(
            headers
                .iter()
                .any(|h| h.field.equiv("X-Content-Type-Options"))
        );
        assert!(headers.iter().any(|h| h.field.equiv("Cache-Control")));
    }

    #[test]
    fn api_runs_lists_valid_ledgers_and_ignores_other_files() {
        let tmp = TempDir::new();
        write_sample_ledger(&tmp.path.join("T-0a1b2c3d.ledger.jsonl"), "T-0a1b2c3d");
        fs::write(tmp.path.join("notes.txt"), b"hello\n").unwrap();
        fs::write(tmp.path.join("bad..id.ledger.jsonl"), b"{}\n").unwrap();
        fs::write(tmp.path.join("space id.ledger.jsonl"), b"{}\n").unwrap();
        fs::create_dir(tmp.path.join("T-dir.ledger.jsonl")).unwrap();

        assert!("notes.txt".parse::<TaskId>().is_err());
        assert!("../x.ledger.jsonl".parse::<TaskId>().is_err());
        assert!("../x".parse::<TaskId>().is_err());

        let (status, content_type, body) = route(&tmp.path, "/api/runs");
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        let runs: Vec<RunSummary> = serde_json::from_slice(&body).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].task, "T-0a1b2c3d");
        assert_eq!(runs[0].entries, 3);
        assert!(runs[0].verified);
        assert_eq!(runs[0].error, None);
        assert_eq!(runs[0].last_event.as_deref(), Some("ruling"));

        let missing = tmp.path.join("no-such-dir");
        let (status_missing, _, body_missing) = route(&missing, "/api/runs");
        assert_eq!(status_missing, 200);
        let empty: Vec<RunSummary> = serde_json::from_slice(&body_missing).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn api_run_detail_returns_verified_entries() {
        let tmp = TempDir::new();
        write_sample_ledger(&tmp.path.join("T-100.ledger.jsonl"), "T-100");

        let (status, content_type, body) = route(&tmp.path, "/api/runs/T-100");
        assert_eq!(status, 200);
        assert_eq!(content_type, "application/json");
        let detail: RunDetail = serde_json::from_slice(&body).unwrap();
        assert_eq!(detail.task, "T-100");
        assert!(detail.verified);
        assert_eq!(detail.error, None);
        assert_eq!(detail.entries.len(), 3);
        assert_eq!(detail.entries[0].seq, 0);
        assert_eq!(detail.entries[1].event["event"], "task_started");
        assert_eq!(detail.entries[2].event["event"], "ruling");
    }

    #[test]
    fn half_written_trailing_line_still_verifies_complete_entries() {
        let tmp = TempDir::new();
        let file = tmp.path.join("T-live.ledger.jsonl");
        write_sample_ledger(&file, "T-live");
        let mut f = fs::OpenOptions::new().append(true).open(&file).unwrap();
        f.write_all(br#"{"seq":3,"ts_ms":123,"prev":"sha256:00"#)
            .unwrap();
        drop(f);

        let (status, _, body) = route(&tmp.path, "/api/runs/T-live");
        assert_eq!(status, 200);
        let detail: RunDetail = serde_json::from_slice(&body).unwrap();
        assert!(detail.verified);
        assert_eq!(detail.error, None);
        assert_eq!(detail.entries.len(), 3);
    }

    #[test]
    fn tampered_middle_line_reports_unverified_and_keeps_parseable_entries() {
        let tmp = TempDir::new();
        let file = tmp.path.join("T-tamper.ledger.jsonl");
        write_sample_ledger(&file, "T-tamper");
        let text = fs::read_to_string(&file).unwrap();
        let tampered = text.replacen("\"P-1\"", "\"P-9\"", 1);
        assert_ne!(text, tampered);
        fs::write(&file, tampered).unwrap();

        let (status, _, body) = route(&tmp.path, "/api/runs/T-tamper");
        assert_eq!(status, 200);
        let detail: RunDetail = serde_json::from_slice(&body).unwrap();
        assert!(!detail.verified);
        assert!(detail.error.is_some());
        assert_eq!(detail.entries.len(), 3);
        assert_eq!(detail.entries[1].event["plan"], "P-9");
    }

    #[test]
    fn invalid_ids_missing_runs_and_unknown_paths_return_404() {
        let tmp = TempDir::new();
        write_sample_ledger(&tmp.path.join("T-ok.ledger.jsonl"), "T-ok");

        for bad in [
            "/api/runs/..%2Fetc",
            "/api/runs/../etc",
            "/api/runs/not-an-id",
            "/api/runs/bad!id",
            "/api/runs/",
            "/unknown",
            "/api/other",
        ] {
            let (status, _, _) = route(&tmp.path, bad);
            assert_eq!(status, 404, "{bad}");
        }
    }

    #[test]
    fn only_loopback_hosts_are_served() {
        assert!(host_allowed(Some("127.0.0.1:8090"), 8090));
        assert!(host_allowed(Some("localhost:8090"), 8090));
        assert!(!host_allowed(Some("evil.example:8090"), 8090));
        assert!(!host_allowed(Some("127.0.0.1:9999"), 8090));
        assert!(!host_allowed(None, 8090));
    }

    #[test]
    fn flags_parse_with_defaults_and_reject_bad_usage() {
        assert_eq!(
            parse_args(&[]).unwrap(),
            Options {
                runs: PathBuf::from("runs"),
                port: 8090,
            }
        );
        let custom = parse_args(&[
            "--runs".to_owned(),
            "custom/runs".to_owned(),
            "--port".to_owned(),
            "9100".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            custom,
            Options {
                runs: PathBuf::from("custom/runs"),
                port: 9100,
            }
        );
        for bad in [
            &["--runs"][..],
            &["--port"][..],
            &["--port", "0"][..],
            &["--port", "abc"][..],
            &["--wat"][..],
            &["extra"][..],
        ] {
            let v: Vec<String> = bad.iter().map(|s| (*s).to_owned()).collect();
            assert!(parse_args(&v).is_err(), "{bad:?}");
        }
    }
}
