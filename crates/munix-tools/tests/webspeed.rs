//! `web.open` against a fake Web Speed OSS (stdlib Python, offline), plus one ignored live test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use munix_core::validate::Scalar;
use munix_core::validate::is_valid as is_valid_scalar_string;
use munix_gate::tool::{Tool, ToolFailure};
use munix_tools::ToolConfigError;
use munix_tools::webspeed::{WebSpeedConfig, WebSpeedOpen};
use serde_json::{Value, json};

fn python3() -> PathBuf {
    let path = std::env::var_os("PATH").expect("PATH is set");
    std::env::split_paths(&path)
        .map(|dir| dir.join("python3"))
        .find(|candidate| candidate.is_file())
        .expect("python3 on PATH")
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_webspeed.py")
}

fn config(allow_hosts: Option<&str>) -> WebSpeedConfig {
    WebSpeedConfig {
        program: python3(),
        args: vec!["-I".into(), fixture().to_string_lossy().into_owned()],
        cwd: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        allow_hosts: allow_hosts.map(str::to_owned),
        timeout: Duration::from_secs(2),
    }
}

fn tool() -> WebSpeedOpen {
    WebSpeedOpen::new(config(None)).expect("fake config is valid")
}

fn open(tool: &WebSpeedOpen, url: &str) -> Result<BTreeMap<String, Value>, ToolFailure> {
    tool.call(&BTreeMap::from([("url".to_owned(), json!(url))]), None)
}

fn page(out: &BTreeMap<String, Value>) -> &str {
    out["page"].as_str().expect("page is a string")
}

fn links(out: &BTreeMap<String, Value>) -> Vec<&str> {
    out["links"]
        .as_array()
        .expect("links is an array")
        .iter()
        .map(|v| v.as_str().expect("link is a string"))
        .collect()
}

#[test]
fn renders_the_page_as_plain_text() {
    let out = open(&tool(), "http://test.example/ok").unwrap();
    assert_eq!(out.len(), 2);
    let expected = "\
Title: Aurora G27Q review
A bidi test
# Review
## Pros
Sharp panel here
Second
linex
Intro text
Section heading
Section text
Name | Price
Aurora | $299";
    assert_eq!(page(&out), expected);
}

#[test]
fn page_has_no_forbidden_characters_and_passes_the_text_validator() {
    let out = open(&tool(), "http://test.example/ok").unwrap();
    let page = page(&out);
    for c in page.chars() {
        let forbidden = (c.is_control() && c != '\n' && c != '\t')
            || matches!(c, '\u{61c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}' | '\u{2066}'..='\u{2069}' | '\u{feff}' | '\u{e0000}'..='\u{e007f}');
        assert!(!forbidden, "forbidden char {c:?} in page");
    }
    assert!(is_valid_scalar_string(Scalar::Text, page));
}

#[test]
fn links_are_filtered_and_deduplicated_in_order() {
    let out = open(&tool(), "http://test.example/ok").unwrap();
    // The non-ASCII and `javascript:` links are dropped, the repeated one is kept once.
    assert_eq!(
        links(&out),
        [
            "https://shop.example.com/aurora",
            "https://xn--80ak6aa92e.com/",
            "https://shop.example.com/article-link",
        ]
    );
}

#[test]
fn links_are_capped_at_fifty() {
    let out = open(&tool(), "http://test.example/many").unwrap();
    let found = links(&out);
    assert_eq!(found.len(), 50);
    assert_eq!(found[0], "https://shop.example.com/p0");
    assert_eq!(found[49], "https://shop.example.com/p49");
}

#[test]
fn product_and_listing_are_rendered() {
    let out = open(&tool(), "http://test.example/product").unwrap();
    let expected = "\
Title: Widget
Product: Widget Pro
Price: $49.99
Rating: 4.5
Availability: In stock
Weight: 1 kg
- Item A | First | $1
- Item B";
    assert_eq!(page(&out), expected);
    assert_eq!(
        links(&out),
        ["https://shop.example.com/a", "https://shop.example.com/b"]
    );
}

#[test]
fn error_codes_map_to_coarse_failures() {
    let tool = tool();
    assert_eq!(
        open(&tool, "http://test.example/blocked").unwrap_err(),
        ToolFailure::BadInput
    );
    assert_eq!(
        open(&tool, "http://test.example/notfound").unwrap_err(),
        ToolFailure::Unavailable
    );
    assert_eq!(
        open(&tool, "http://test.example/weird").unwrap_err(),
        ToolFailure::Internal
    );
    assert_eq!(
        open(&tool, "http://test.example/toolerror").unwrap_err(),
        ToolFailure::Internal
    );
    // Those were answers, not child failures: the same child still serves.
    assert!(open(&tool, "http://test.example/ok").is_ok());
}

#[test]
fn a_timeout_is_unavailable_and_the_next_call_gets_a_fresh_child() {
    let tool = tool();
    assert_eq!(
        open(&tool, "http://test.example/slow").unwrap_err(),
        ToolFailure::Unavailable
    );
    assert!(open(&tool, "http://test.example/ok").is_ok());
}

#[test]
fn a_crash_is_unavailable_and_the_next_call_recovers() {
    let tool = tool();
    assert!(open(&tool, "http://test.example/ok").is_ok());
    assert_eq!(
        open(&tool, "http://test.example/crash").unwrap_err(),
        ToolFailure::Unavailable
    );
    assert!(open(&tool, "http://test.example/ok").is_ok());
}

#[test]
fn noise_before_the_response_is_skipped() {
    let out = open(&tool(), "http://test.example/noise").unwrap();
    assert_eq!(page(&out), "Title: Unknown path /noise");
}

fn env_flags(allow_hosts: Option<&str>) -> Value {
    let tool = WebSpeedOpen::new(config(allow_hosts)).unwrap();
    let out = open(&tool, "http://test.example/env").unwrap();
    let title = page(&out).strip_prefix("Title: ").expect("title line");
    serde_json::from_str(title).expect("flags are JSON")
}

#[test]
fn the_allowlist_reaches_the_child_and_the_read_flag_is_sent() {
    let flags = env_flags(Some("127.0.0.1:8080"));
    assert_eq!(flags["allow_hosts"], json!("127.0.0.1:8080"));
    assert_eq!(flags["read_flag"], json!(true));
    assert_eq!(env_flags(None)["allow_hosts"], Value::Null);
}

/// Setting a variable in this process needs `unsafe` in edition 2024, so the check runs this
/// test binary again with `MODEL_API_KEY` in its environment.
#[test]
fn a_model_api_key_in_the_parent_does_not_reach_the_child() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "secret_check_inner", "--ignored", "--nocapture"])
        .env("MODEL_API_KEY", "sk-test-secret")
        .env("MUNIX_SECRET_CHECK_INNER", "1")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "run by a_model_api_key_in_the_parent_does_not_reach_the_child"]
fn secret_check_inner() {
    if std::env::var("MUNIX_SECRET_CHECK_INNER").as_deref() != Ok("1") {
        return;
    }
    assert_eq!(
        std::env::var("MODEL_API_KEY").as_deref(),
        Ok("sk-test-secret")
    );
    assert_eq!(
        env_flags(Some("127.0.0.1:8080"))["model_api_key"],
        json!(false)
    );
}

#[test]
fn bad_arguments_are_rejected() {
    let tool = tool();
    let call = |args: &[(&str, Value)]| {
        let args: BTreeMap<String, Value> = args
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        tool.call(&args, None).unwrap_err()
    };
    assert_eq!(call(&[]), ToolFailure::BadInput);
    assert_eq!(call(&[("url", json!(5))]), ToolFailure::BadInput);
    assert_eq!(
        call(&[("url", json!("ftp://x.com/"))]),
        ToolFailure::BadInput
    );
    assert_eq!(
        call(&[("url", json!("https://good.com@evil.com/"))]),
        ToolFailure::BadInput
    );
    assert_eq!(call(&[("url", json!("not a url"))]), ToolFailure::BadInput);
    assert_eq!(
        call(&[
            ("url", json!("http://test.example/ok")),
            ("extra", json!("x"))
        ]),
        ToolFailure::BadInput
    );
    assert_eq!(
        call(&[("link", json!("http://test.example/ok"))]),
        ToolFailure::BadInput
    );
}

#[test]
fn new_rejects_a_missing_program_and_a_zero_timeout() {
    let mut cfg = config(None);
    cfg.program = PathBuf::from("/definitely/not/here/python");
    assert!(matches!(
        WebSpeedOpen::new(cfg),
        Err(ToolConfigError::Invalid(_))
    ));
    let mut cfg = config(None);
    cfg.timeout = Duration::ZERO;
    assert!(matches!(
        WebSpeedOpen::new(cfg),
        Err(ToolConfigError::Invalid(_))
    ));
}

#[test]
fn from_dir_uses_the_standard_layout() {
    let cfg = WebSpeedConfig::from_dir("/opt/web-speed-oss");
    assert_eq!(
        cfg.program,
        PathBuf::from("/opt/web-speed-oss/venv/bin/python")
    );
    assert_eq!(cfg.args, ["/opt/web-speed-oss/server.py"]);
    assert_eq!(cfg.cwd, PathBuf::from("/opt/web-speed-oss"));
    assert_eq!(cfg.allow_hosts, None);
    assert_eq!(cfg.timeout, Duration::from_secs(60));
}

/// Needs Web Speed OSS (`WEBSPEED_OSS_DIR`) and the mock site: run `fixtures/mock-web/start.sh`,
/// then `MUNIX_LIVE_WEBSPEED=1 cargo test -p munix-tools --test webspeed -- --ignored`.
/// The mock page carries a deliberate injection payload; it is test data.
///
/// Core's `Scalar::Url` validator rejects IP literals, so the mock site is reached by name:
/// add `127.0.0.1 pixelmart.test` to `/etc/hosts`.
#[test]
#[ignore = "needs Web Speed OSS and the mock site"]
fn live_web_speed_reads_the_poisoned_mock_page() {
    if std::env::var("MUNIX_LIVE_WEBSPEED").as_deref() != Ok("1") {
        eprintln!("skipped: set MUNIX_LIVE_WEBSPEED=1");
        return;
    }
    let dir = std::env::var("WEBSPEED_OSS_DIR").expect("WEBSPEED_OSS_DIR is set");
    let mut cfg = WebSpeedConfig::from_dir(dir);
    cfg.allow_hosts = Some("pixelmart.test:8080".into());
    let tool = WebSpeedOpen::new(cfg).unwrap();
    let out = open(&tool, "http://pixelmart.test:8080/reviews/gaming-monitor").unwrap();
    let page = page(&out);
    assert!(page.contains("Aurora G27Q"), "{page}");
    assert!(page.contains("hacker@evil.com"), "{page}");
    assert!(is_valid_scalar_string(Scalar::Text, page));
}
