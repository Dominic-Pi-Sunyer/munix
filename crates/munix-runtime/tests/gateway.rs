//! Gateway tests against a fake upstream on 127.0.0.1.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use munix_runtime::gateway::{ApiKey, Gateway, GatewayConfig, GatewayError, Usage};

const KEY: &str = "sk-real-upstream-key";

#[derive(Debug, Clone)]
struct Seen {
    url: String,
    authorization: Vec<String>,
    body: String,
}

struct FakeUpstream {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeUpstream {
    fn start(status: u16, body: &'static str) -> FakeUpstream {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen2, stop2) = (seen.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !stop2.load(Ordering::SeqCst) {
                let Ok(Some(mut req)) = server.recv_timeout(Duration::from_millis(50)) else {
                    continue;
                };
                let mut b = String::new();
                req.as_reader().read_to_string(&mut b).unwrap();
                let authorization = req
                    .headers()
                    .iter()
                    .filter(|h| h.field.equiv("Authorization"))
                    .map(|h| h.value.to_string())
                    .collect();
                seen2.lock().unwrap().push(Seen {
                    url: req.url().to_string(),
                    authorization,
                    body: b,
                });
                let resp = tiny_http::Response::from_string(body)
                    .with_status_code(status)
                    .with_header(
                        tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                    );
                let _ = req.respond(resp);
            }
        });
        FakeUpstream {
            addr,
            seen,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://{}/v1", self.addr)
    }
}

impl Drop for FakeUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn config(upstream: String) -> GatewayConfig {
    GatewayConfig {
        upstream,
        api_key: ApiKey::new(KEY),
        models: BTreeSet::from(["muse-spark-1.3".to_string()]),
        bind: "127.0.0.1:0".parse().unwrap(),
        timeout: Duration::from_secs(5),
    }
}

fn client() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

struct Reply {
    status: u16,
    body: String,
}

fn post(gw: &Gateway, path: &str, auth: Option<&str>, body: &str) -> Reply {
    let mut req = client().post(format!("http://{}{path}", gw.addr()));
    if let Some(a) = auth {
        req = req.header("Authorization", a);
    }
    let mut resp = req.send(body.as_bytes()).unwrap();
    Reply {
        status: resp.status().as_u16(),
        body: resp.body_mut().read_to_string().unwrap(),
    }
}

const OK_BODY: &str =
    r#"{"id":"x","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}"#;
const GOOD_REQ: &str = r#"{"model":"muse-spark-1.3","messages":[{"role":"user","content":"hi"}]}"#;

#[test]
fn forwards_with_the_configured_key_and_drops_the_agents_authorization() {
    let up = FakeUpstream::start(200, OK_BODY);
    let gw = Gateway::start(config(up.url())).unwrap();
    let r = post(
        &gw,
        "/v1/chat/completions",
        Some("Bearer munix-gateway"),
        GOOD_REQ,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body, OK_BODY);
    let seen = up.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].url, "/v1/chat/completions");
    assert_eq!(seen[0].authorization, vec![format!("Bearer {KEY}")]);
    assert_eq!(seen[0].body, GOOD_REQ);
    assert!(!r.body.contains(KEY));
}

#[test]
fn a_trailing_slash_on_the_upstream_is_fine() {
    let up = FakeUpstream::start(200, OK_BODY);
    let gw = Gateway::start(config(format!("{}/", up.url()))).unwrap();
    assert_eq!(
        post(&gw, "/v1/chat/completions", None, GOOD_REQ).status,
        200
    );
    assert_eq!(up.seen.lock().unwrap()[0].url, "/v1/chat/completions");
}

#[test]
fn a_disallowed_model_is_403_and_never_reaches_upstream() {
    let up = FakeUpstream::start(200, OK_BODY);
    let gw = Gateway::start(config(up.url())).unwrap();
    let r = post(
        &gw,
        "/v1/chat/completions",
        None,
        r#"{"model":"gpt-evil","messages":[]}"#,
    );
    assert_eq!(r.status, 403);
    assert!(up.seen.lock().unwrap().is_empty());
    assert_eq!(gw.usage(), Usage::default());
}

#[test]
fn malformed_requests_are_400() {
    let up = FakeUpstream::start(200, OK_BODY);
    let gw = Gateway::start(config(up.url())).unwrap();
    for body in [
        r#"{"messages":[]}"#,
        r#"{"model":7}"#,
        "not json",
        "",
        r#"{"model":"muse-spark-1.3","stream":true}"#,
    ] {
        let r = post(&gw, "/v1/chat/completions", None, body);
        assert_eq!(r.status, 400, "{body}");
    }
    // stream:false is fine.
    let ok = post(
        &gw,
        "/v1/chat/completions",
        None,
        r#"{"model":"muse-spark-1.3","stream":false}"#,
    );
    assert_eq!(ok.status, 200);
    assert_eq!(up.seen.lock().unwrap().len(), 1);
}

#[test]
fn an_oversize_body_is_400() {
    let up = FakeUpstream::start(200, OK_BODY);
    let gw = Gateway::start(config(up.url())).unwrap();
    let big = format!(
        r#"{{"model":"muse-spark-1.3","pad":"{}"}}"#,
        "a".repeat(4 * 1024 * 1024 + 10)
    );
    let r = post(&gw, "/v1/chat/completions", None, &big);
    assert_eq!(r.status, 400);
    assert!(up.seen.lock().unwrap().is_empty());
}

#[test]
fn wrong_path_or_method_is_404() {
    let up = FakeUpstream::start(200, OK_BODY);
    let gw = Gateway::start(config(up.url())).unwrap();
    assert_eq!(post(&gw, "/v1/models", None, GOOD_REQ).status, 404);
    assert_eq!(
        post(&gw, "/v1/chat/completions/", None, GOOD_REQ).status,
        404
    );
    assert_eq!(post(&gw, "/", None, GOOD_REQ).status, 404);
    let mut resp = client()
        .get(format!("http://{}/v1/chat/completions", gw.addr()))
        .call()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
    let _ = resp.body_mut().read_to_string();
    assert!(up.seen.lock().unwrap().is_empty());
}

#[test]
fn upstream_status_and_body_pass_through() {
    let err_body = r#"{"error":{"message":"rate limited"}}"#;
    let up = FakeUpstream::start(429, err_body);
    let gw = Gateway::start(config(up.url())).unwrap();
    let r = post(&gw, "/v1/chat/completions", None, GOOD_REQ);
    assert_eq!(r.status, 429);
    assert_eq!(r.body, err_body);
    // Failed responses add no tokens, but the call is counted.
    assert_eq!(
        gw.usage(),
        Usage {
            calls: 1,
            prompt_tokens: 0,
            completion_tokens: 0
        }
    );
}

#[test]
fn usage_adds_up() {
    let up = FakeUpstream::start(200, OK_BODY);
    let gw = Gateway::start(config(up.url())).unwrap();
    assert_eq!(gw.usage(), Usage::default());
    for _ in 0..3 {
        assert_eq!(
            post(&gw, "/v1/chat/completions", None, GOOD_REQ).status,
            200
        );
    }
    assert_eq!(
        gw.usage(),
        Usage {
            calls: 3,
            prompt_tokens: 21,
            completion_tokens: 9
        }
    );
}

#[test]
fn a_response_without_usage_counts_only_the_call() {
    let up = FakeUpstream::start(200, r#"{"id":"x"}"#);
    let gw = Gateway::start(config(up.url())).unwrap();
    assert_eq!(
        post(&gw, "/v1/chat/completions", None, GOOD_REQ).status,
        200
    );
    assert_eq!(
        gw.usage(),
        Usage {
            calls: 1,
            prompt_tokens: 0,
            completion_tokens: 0
        }
    );
}

#[test]
fn last_activity_moves_on_requests() {
    let up = FakeUpstream::start(200, OK_BODY);
    let gw = Gateway::start(config(up.url())).unwrap();
    let t0 = gw.last_activity();
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(gw.last_activity(), t0);
    post(&gw, "/v1/chat/completions", None, GOOD_REQ);
    let t1 = gw.last_activity();
    assert!(t1 > t0);
    std::thread::sleep(Duration::from_millis(60));
    // Even a rejected request counts as activity.
    post(&gw, "/nope", None, "");
    assert!(gw.last_activity() > t1);
}

#[test]
fn an_unreachable_upstream_is_502_without_the_key() {
    // Bind then drop a listener to get a port nothing listens on.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let gw = Gateway::start(config(format!("http://127.0.0.1:{port}/v1"))).unwrap();
    let r = post(&gw, "/v1/chat/completions", None, GOOD_REQ);
    assert_eq!(r.status, 502);
    assert!(!r.body.contains(KEY));
}

#[test]
fn a_non_loopback_bind_is_refused() {
    for bind in ["0.0.0.0:0", "192.168.1.5:0", "[::]:0"] {
        let mut c = config("http://127.0.0.1:1/v1".to_string());
        c.bind = bind.parse().unwrap();
        assert!(
            matches!(Gateway::start(c), Err(GatewayError::NotLoopback)),
            "{bind}"
        );
    }
}

#[test]
fn invalid_configs_are_refused() {
    let mut c = config("ftp://x".to_string());
    assert!(matches!(
        Gateway::start(c.clone()),
        Err(GatewayError::Invalid(_))
    ));
    c = config("http://127.0.0.1:1/v1".to_string());
    c.models.clear();
    assert!(matches!(
        Gateway::start(c.clone()),
        Err(GatewayError::Invalid(_))
    ));
    c = config("http://127.0.0.1:1/v1".to_string());
    c.api_key = ApiKey::new("bad\r\nkey");
    assert!(matches!(Gateway::start(c), Err(GatewayError::Invalid(_))));
}

#[test]
fn the_key_never_shows_in_debug_output() {
    let c = config("http://127.0.0.1:1/v1".to_string());
    assert!(!format!("{c:?}").contains(KEY));
    assert!(!format!("{:?}", c.api_key).contains(KEY));
}

#[test]
fn dropping_the_gateway_stops_the_server() {
    let up = FakeUpstream::start(200, OK_BODY);
    let gw = Gateway::start(config(up.url())).unwrap();
    let addr = gw.addr();
    drop(gw);
    // tiny_http's accept thread can hold the socket for a moment after the server is dropped, so wait for it.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "gateway still accepting after drop"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
