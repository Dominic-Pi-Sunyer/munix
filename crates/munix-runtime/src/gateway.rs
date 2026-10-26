//! The model gateway: a loopback HTTP server that forwards the agent's chat completions to the model provider.
//!
//! It is the only place the model API key is used. It also counts calls and tokens for the watchdog's spin budget
//! and records the time of the last call for its liveness check.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tiny_http::{Header, Method, Request, Response, Server};

/// The largest request body the gateway accepts.
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
/// The largest upstream response body the gateway relays.
const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
const CHAT_PATH: &str = "/v1/chat/completions";

/// The provider API key. `Debug` never shows it.
#[derive(Clone)]
pub struct ApiKey(String);

impl ApiKey {
    pub fn new(key: impl Into<String>) -> Self {
        ApiKey(key.into())
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey(<redacted>)")
    }
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// The provider's OpenAI-compatible base URL, such as `https://api.meta.ai/v1` (no trailing slash).
    pub upstream: String,
    pub api_key: ApiKey,
    /// The only models the agent may ask for.
    pub models: BTreeSet<String>,
    /// Must be a loopback address. Port 0 picks a free port.
    pub bind: SocketAddr,
    /// Timeout for one upstream call.
    pub timeout: Duration,
}

/// Calls and tokens through the gateway since it started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub calls: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("the gateway must bind a loopback address")]
    NotLoopback,
    #[error("invalid config: {0}")]
    Invalid(&'static str),
    #[error("could not bind: {0}")]
    Bind(String),
}

/// State shared between the server thread, request handlers and the `Gateway` handle.
struct Shared {
    upstream_url: String,
    auth_header: String,
    models: BTreeSet<String>,
    agent: ureq::Agent,
    usage: Mutex<Usage>,
    last_activity: Mutex<Instant>,
    stop: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A running gateway. Dropping it stops the server.
pub struct Gateway {
    addr: SocketAddr,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl fmt::Debug for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gateway")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl Gateway {
    /// Starts serving on a background thread.
    ///
    /// Requests: only `POST /v1/chat/completions` (anything else is 404). The body is at most 4 MiB of JSON with a
    /// string `model` in `models` (else 400 or 403); `"stream": true` is refused with 400. Any `Authorization`
    /// header from the agent is dropped and `Authorization: Bearer <key>` is added; the body is forwarded
    /// unchanged to `<upstream>/chat/completions`, and the upstream status and body come back unchanged. The usage
    /// counters add `usage.prompt_tokens` and `usage.completion_tokens` from successful responses. An unreachable
    /// upstream is 502. The key is never logged or echoed.
    pub fn start(config: GatewayConfig) -> Result<Gateway, GatewayError> {
        if !config.bind.ip().is_loopback() {
            return Err(GatewayError::NotLoopback);
        }
        if !(config.upstream.starts_with("http://") || config.upstream.starts_with("https://")) {
            return Err(GatewayError::Invalid("upstream must be an http(s) URL"));
        }
        if config.models.is_empty() {
            return Err(GatewayError::Invalid("no models allowed"));
        }
        let key = &config.api_key.0;
        if key.is_empty() || key.chars().any(|c| c.is_control()) {
            return Err(GatewayError::Invalid(
                "api key must be non-empty without control characters",
            ));
        }
        if config.timeout.is_zero() {
            return Err(GatewayError::Invalid("timeout must be positive"));
        }

        let server = Server::http(config.bind).map_err(|e| GatewayError::Bind(e.to_string()))?;
        let addr = server
            .server_addr()
            .to_ip()
            .ok_or(GatewayError::Bind("not an IP listener".to_string()))?;

        // No redirects (they could carry the key elsewhere), no proxy from the environment, and non-2xx
        // statuses come back as responses.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .timeout_global(Some(config.timeout))
            .build()
            .into();

        let shared = Arc::new(Shared {
            upstream_url: format!("{}/chat/completions", config.upstream.trim_end_matches('/')),
            auth_header: format!("Bearer {}", config.api_key.0),
            models: config.models,
            agent,
            usage: Mutex::new(Usage::default()),
            last_activity: Mutex::new(Instant::now()),
            stop: AtomicBool::new(false),
        });

        let loop_shared = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("munix-gateway".to_string())
            .spawn(move || serve(server, loop_shared))
            .map_err(|e| GatewayError::Bind(e.to_string()))?;

        Ok(Gateway {
            addr,
            shared,
            thread: Some(thread),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn usage(&self) -> Usage {
        *lock(&self.shared.usage)
    }

    /// When the last request arrived, or when the gateway started if none has.
    pub fn last_activity(&self) -> Instant {
        *lock(&self.shared.last_activity)
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn serve(server: Server, shared: Arc<Shared>) {
    while !shared.stop.load(Ordering::SeqCst) {
        match server.recv_timeout(Duration::from_millis(50)) {
            Ok(Some(request)) => {
                *lock(&shared.last_activity) = Instant::now();
                let shared = Arc::clone(&shared);
                // One thread per request, so a slow upstream call never blocks the next request.
                let _ = std::thread::Builder::new()
                    .name("munix-gateway-req".to_string())
                    .spawn(move || {
                        handle(request, &shared);
                    });
            }
            Ok(None) => {}
            Err(_) => break,
        }
    }
}

fn reply(request: Request, status: u16, content_type: Option<&str>, body: Vec<u8>) {
    let mut response = Response::from_data(body).with_status_code(status);
    let header = content_type
        .and_then(|ct| Header::from_bytes("Content-Type", ct).ok())
        .or_else(|| Header::from_bytes("Content-Type", "application/json").ok());
    if let Some(h) = header {
        response.add_header(h);
    }
    let _ = request.respond(response);
}

/// Replies with a coarse error code only; details are never echoed.
fn reject(request: Request, status: u16, code: &str) {
    reply(
        request,
        status,
        None,
        format!("{{\"error\":\"{code}\"}}").into_bytes(),
    );
}

fn handle(mut request: Request, shared: &Shared) {
    if request.method() != &Method::Post || request.url() != CHAT_PATH {
        return reject(request, 404, "not_found");
    }
    if request
        .body_length()
        .is_some_and(|n| n as u64 > MAX_REQUEST_BYTES)
    {
        return reject(request, 400, "bad_request");
    }
    let mut body = Vec::new();
    let read = request
        .as_reader()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut body);
    if read.is_err() || body.len() as u64 > MAX_REQUEST_BYTES {
        return reject(request, 400, "bad_request");
    }
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return reject(request, 400, "bad_request");
    };
    let Some(model) = json.get("model").and_then(|m| m.as_str()) else {
        return reject(request, 400, "bad_request");
    };
    if json.get("stream").and_then(|s| s.as_bool()) == Some(true) {
        return reject(request, 400, "bad_request");
    }
    if !shared.models.contains(model) {
        return reject(request, 403, "model_not_allowed");
    }

    lock(&shared.usage).calls += 1;
    let result = shared
        .agent
        .post(&shared.upstream_url)
        .header("Authorization", &shared.auth_header)
        .header("Content-Type", "application/json")
        .send(&body[..]);
    let mut response = match result {
        Ok(r) => r,
        Err(_) => return reject(request, 502, "upstream_unreachable"),
    };
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let upstream_body = match response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_vec()
    {
        Ok(b) => b,
        Err(_) => return reject(request, 502, "upstream_unreachable"),
    };
    if (200..300).contains(&status)
        && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&upstream_body)
    {
        let tokens = |name: &str| {
            v.get("usage")
                .and_then(|u| u.get(name))
                .and_then(|t| t.as_u64())
                .unwrap_or(0)
        };
        let mut usage = lock(&shared.usage);
        usage.prompt_tokens = usage.prompt_tokens.saturating_add(tokens("prompt_tokens"));
        usage.completion_tokens = usage
            .completion_tokens
            .saturating_add(tokens("completion_tokens"));
    }
    reply(request, status, content_type.as_deref(), upstream_body);
}
