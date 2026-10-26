//! Live Docker test. Ignored by default; run with `MUNIX_LIVE_DOCKER=1 cargo test --test live_sandbox -- --ignored`.
//!
//! Assumes Colima (host reachable at 192.168.5.2) and `python:3.12-slim` already pulled locally. Bind mounts only
//! work under `$HOME`, so it mounts files from this crate rather than `/tmp`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use munix_runtime::gateway::{ApiKey, Gateway, GatewayConfig};
use munix_runtime::sandbox::{PLACEHOLDER_KEY, Sandbox, SandboxSpec};

const REAL_KEY: &str = "sk-live-test-real-key";

/// What the agent runs: call the gateway with the placeholder key (retrying while the relay starts), then try to
/// open a raw TCP connection to the internet.
const AGENT_PY: &str = r#"
import json, os, socket, time, urllib.request
url = os.environ["OPENAI_BASE_URL"] + "/chat/completions"
req = urllib.request.Request(
    url,
    data=json.dumps({"model": "m", "messages": []}).encode(),
    headers={"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"], "Content-Type": "application/json"},
)
result = "GATEWAY failed"
for _ in range(20):
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            result = "GATEWAY %d %s" % (r.status, r.read().decode())
            break
    except Exception as e:
        result = "GATEWAY failed %s" % type(e).__name__
        time.sleep(0.5)
print(result, flush=True)
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3).close()
    print("INTERNET reachable", flush=True)
except OSError:
    print("INTERNET blocked", flush=True)
"#;

#[test]
#[ignore = "needs Docker; set MUNIX_LIVE_DOCKER=1"]
fn the_agent_reaches_the_gateway_but_not_the_internet() {
    if std::env::var("MUNIX_LIVE_DOCKER").as_deref() != Ok("1") {
        eprintln!("MUNIX_LIVE_DOCKER is not 1; skipping");
        return;
    }

    // A fake upstream that records the Authorization header it receives.
    let upstream = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.server_addr().to_ip().unwrap();
    let auth_seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let auth_seen2 = auth_seen.clone();
    std::thread::spawn(move || {
        for mut req in upstream.incoming_requests() {
            let mut sink = String::new();
            let _ = req.as_reader().read_to_string(&mut sink);
            for h in req
                .headers()
                .iter()
                .filter(|h| h.field.equiv("Authorization"))
            {
                auth_seen2.lock().unwrap().push(h.value.to_string());
            }
            let _ = req.respond(tiny_http::Response::from_string(r#"{"ok":true}"#));
        }
    });

    let gateway = Gateway::start(GatewayConfig {
        upstream: format!("http://{upstream_addr}/v1"),
        api_key: ApiKey::new(REAL_KEY),
        models: BTreeSet::from(["m".to_string()]),
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout: Duration::from_secs(10),
    })
    .unwrap();

    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let spec = SandboxSpec {
        name: format!("live-{}", std::process::id()),
        image: "python:3.12-slim".to_string(),
        agent_dir: crate_dir.join("tests/fixtures/agent"),
        command: vec!["python".to_string(), "-c".to_string(), AGENT_PY.to_string()],
        env: BTreeMap::new(),
        host_gateway: "192.168.5.2".to_string(),
        gateway_port: gateway.addr().port(),
        relay_script: crate_dir.join("relay/relay.py"),
    };
    let mut sandbox = Sandbox::launch(spec).unwrap();
    drop(sandbox.child.stdin.take()); // no MCP traffic in this test
    let mut out = String::new();
    let mut stdout = sandbox.child.stdout.take().unwrap();
    stdout.read_to_string(&mut out).unwrap();
    let status = sandbox.child.wait().unwrap();
    sandbox.kill().unwrap();

    eprintln!("agent output:\n{out}");
    assert!(status.success(), "agent exited with {status}");
    assert!(
        out.contains(r#"GATEWAY 200 {"ok":true}"#),
        "gateway not reached: {out}"
    );
    assert!(
        out.contains("INTERNET blocked"),
        "internet reachable: {out}"
    );

    // The upstream saw the real key, never the placeholder.
    let seen = auth_seen.lock().unwrap().clone();
    assert_eq!(seen, vec![format!("Bearer {REAL_KEY}")]);
    assert!(!out.contains(REAL_KEY));
    assert!(!seen.iter().any(|h| h.contains(PLACEHOLDER_KEY)));

    // Everything was cleaned up.
    let ps = std::process::Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("name=munix-live-{}", std::process::id()),
            "-q",
        ])
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&ps.stdout).trim().is_empty());
}
