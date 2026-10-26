//! Live Docker test. Ignored by default; run with `MUNIX_LIVE_DOCKER=1 cargo test --test live_sandbox -- --ignored`.
//!
//! Assumes Colima (host reachable at 192.168.5.2) and `python:3.12-slim` already pulled locally. Bind mounts only
//! work under `$HOME`, so it mounts files from this crate rather than `/tmp`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use munix_runtime::gateway::{ApiKey, Gateway, GatewayConfig};
use munix_runtime::sandbox::{PLACEHOLDER_KEY, Sandbox, SandboxSpec};

const REAL_KEY: &str = "sk-live-test-real-key";

/// What the agent runs: call the gateway with the placeholder key (retrying while the relay starts), try to open a
/// raw TCP connection to the internet, then report both over the MCP channel the way a real agent would: start
/// `shim.py connect` as its MCP server, write one JSON line and read one reply. Its own prints go to the shim's
/// stderr, so a stray print to stdout must never show up on the channel.
const AGENT_PY: &str = r#"
import json, os, socket, subprocess, sys, time, urllib.request
url = os.environ["OPENAI_BASE_URL"] + "/chat/completions"
req = urllib.request.Request(
    url,
    data=json.dumps({"model": "m", "messages": []}).encode(),
    headers={"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"], "Content-Type": "application/json"},
)
gateway = "GATEWAY failed"
for _ in range(20):
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            gateway = "GATEWAY %d %s" % (r.status, r.read().decode())
            break
    except Exception as e:
        gateway = "GATEWAY failed %s" % type(e).__name__
        time.sleep(0.5)
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3).close()
    internet = "INTERNET reachable"
except OSError:
    internet = "INTERNET blocked"
print("STRAY-PRINT-MUST-NOT-REACH-THE-CHANNEL", flush=True)
server = subprocess.Popen(
    ["python", "/munix/shim.py", "connect"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
)
report = {"jsonrpc": "2.0", "id": 1, "method": "report", "params": {"gateway": gateway, "internet": internet}}
server.stdin.write((json.dumps(report) + "\n").encode())
server.stdin.flush()
reply = json.loads(server.stdout.readline())
sys.exit(0 if reply.get("result") == "thanks" else 3)
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
        shim_script: crate_dir.join("shim/munix_shim.py"),
    };
    let mut sandbox = Sandbox::launch(spec).unwrap();

    // The host end of the MCP channel: read the agent's one line from the sandbox's stdout, answer on its stdin.
    let mut stdin = sandbox.child.stdin.take().unwrap();
    let mut stdout = BufReader::new(sandbox.child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let report: serde_json::Value = serde_json::from_str(&line).unwrap_or_else(|e| {
        panic!("the first line on the channel was not JSON ({e}): {line:?}");
    });
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"result":"thanks"}}"#).unwrap();
    stdin.flush().unwrap();
    drop(stdin);
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    let status = sandbox.child.wait().unwrap();
    sandbox.kill().unwrap();

    eprintln!("agent report: {report}");
    assert!(status.success(), "agent exited with {status}");
    assert_eq!(report["method"], "report");
    let gateway_line = report["params"]["gateway"].as_str().unwrap();
    let internet_line = report["params"]["internet"].as_str().unwrap();
    assert!(
        gateway_line.contains(r#"GATEWAY 200 {"ok":true}"#),
        "gateway not reached: {gateway_line}"
    );
    assert_eq!(internet_line, "INTERNET blocked");
    // The agent's own prints stayed off the channel.
    assert!(rest.is_empty(), "stray output on the channel: {rest:?}");
    let out = format!("{line}{rest}");

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
