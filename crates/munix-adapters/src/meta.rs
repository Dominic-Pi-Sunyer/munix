//! The Meta Model API backend (OpenAI-compatible chat completions with strict JSON-schema output).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::{
    AdapterError, ModelAdapter, ModelReply, ModelRequest, ReasoningEffort, Usage, sanitize_schema,
};

const DEFAULT_BASE_URL: &str = "https://api.meta.ai/v1";
const MAX_ATTEMPTS: u32 = 3;
const BACKOFF_BASE: Duration = Duration::from_secs(1);
const RETRY_AFTER_CAP: Duration = Duration::from_secs(60);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

type Sleeper = Arc<dyn Fn(Duration) + Send + Sync>;

/// The API key. Its `Debug` output never shows the value.
struct SecretKey(String);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

pub struct MetaAdapter {
    base_url: String,
    loopback: bool,
    model: String,
    key: SecretKey,
    timeout: Duration,
    sleeper: Sleeper,
    effort: Option<ReasoningEffort>,
}

impl fmt::Debug for MetaAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetaAdapter")
            .field("model", &self.model)
            .field("key", &self.key)
            .field("timeout", &self.timeout)
            .field("effort", &self.effort)
            .finish_non_exhaustive()
    }
}

impl MetaAdapter {
    /// Reads `MODEL_API_KEY` (required) and `MUNIX_META_URL` (default `https://api.meta.ai/v1`).
    pub fn from_env(model: &str) -> Result<Self, AdapterError> {
        let key = std::env::var("MODEL_API_KEY").ok();
        let url = std::env::var("MUNIX_META_URL").ok();
        Self::from_vars(model, key.as_deref(), url.as_deref())
    }

    fn from_vars(model: &str, key: Option<&str>, url: Option<&str>) -> Result<Self, AdapterError> {
        let key = key.map(str::trim).unwrap_or_default();
        if key.is_empty() {
            return Err(AdapterError::Config("MODEL_API_KEY is not set".to_string()));
        }
        let url = url
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .unwrap_or(DEFAULT_BASE_URL);
        Self::new(url, model, key)
    }

    /// `base_url` must be `https://` (any host) or `http://` to a loopback host, with no userinfo, query or fragment.
    pub fn new(base_url: &str, model: &str, key: &str) -> Result<Self, AdapterError> {
        if !valid_model_id(model) {
            return Err(AdapterError::Config(
                "the model name is empty or has unsupported characters".to_string(),
            ));
        }
        if key.trim().is_empty() {
            return Err(AdapterError::Config("MODEL_API_KEY is not set".to_string()));
        }
        if key.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(AdapterError::Config(
                "MODEL_API_KEY contains characters that cannot be sent".to_string(),
            ));
        }
        let (base_url, loopback) = validate_base_url(base_url)?;
        Ok(Self {
            base_url,
            loopback,
            model: model.to_string(),
            key: SecretKey(key.to_string()),
            timeout: DEFAULT_TIMEOUT,
            sleeper: Arc::new(std::thread::sleep),
            effort: None,
        })
    }

    /// Per-attempt timeout (default 120 s).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sends `"reasoning_effort"` with every request. Without it the field is left out and the server decides.
    #[must_use]
    pub fn with_reasoning_effort(mut self, effort: ReasoningEffort) -> Self {
        self.effort = Some(effort);
        self
    }

    /// Replaces the function used to wait between retries, so tests need not really sleep.
    #[must_use]
    pub fn with_sleeper(mut self, sleeper: impl Fn(Duration) + Send + Sync + 'static) -> Self {
        self.sleeper = Arc::new(sleeper);
        self
    }

    fn agent(&self) -> ureq::Agent {
        let mut builder = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .timeout_global(Some(self.timeout));
        if self.loopback {
            builder = builder.proxy(None);
        }
        ureq::Agent::new_with_config(builder.build())
    }

    fn request_body(&self, req: &ModelRequest) -> String {
        let mut body = json!({
            "model": self.model,
            "temperature": 0,
            "max_tokens": req.max_output_tokens,
            "messages": [
                {"role": "system", "content": req.system},
                {"role": "user", "content": req.user},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": req.schema_name, "strict": true, "schema": sanitize_schema(&req.schema)},
            },
        });
        if let (Some(effort), Some(map)) = (self.effort, body.as_object_mut()) {
            map.insert("reasoning_effort".to_string(), json!(effort.as_str()));
        }
        body.to_string()
    }

    /// One attempt: either a final result or a retryable failure.
    fn attempt(&self, agent: &ureq::Agent, body: &str) -> Attempt {
        let url = format!("{}/chat/completions", self.base_url);
        let sent = agent
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.key.0))
            .content_type("application/json")
            .send(body);
        let mut resp = match sent {
            Ok(resp) => resp,
            Err(ureq::Error::Timeout(_)) => return Attempt::Done(Err(AdapterError::Timeout)),
            Err(ureq::Error::Io(_) | ureq::Error::ConnectionFailed | ureq::Error::HostNotFound) => {
                return Attempt::Retry {
                    retry_after: None,
                    error: AdapterError::Unavailable(
                        "could not reach the model server".to_string(),
                    ),
                };
            }
            Err(_) => {
                return Attempt::Done(Err(AdapterError::Unavailable(
                    "the request could not be completed".to_string(),
                )));
            }
        };
        let status = resp.status().as_u16();
        match status {
            200..=299 => {
                let read = resp
                    .body_mut()
                    .with_config()
                    .limit(MAX_BODY_BYTES)
                    .read_to_vec();
                Attempt::Done(read.map_err(|e| match e {
                    ureq::Error::Timeout(_) => AdapterError::Timeout,
                    ureq::Error::BodyExceedsLimit(_) => {
                        AdapterError::BadOutput("the response was too large".to_string())
                    }
                    _ => AdapterError::Unavailable(
                        "the connection dropped while reading the response".to_string(),
                    ),
                }))
            }
            401 | 403 => Attempt::Done(Err(AdapterError::Config(format!(
                "the server rejected the credentials (HTTP {status})"
            )))),
            429 | 500 | 502 | 503 | 504 => {
                let retry_after = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .map(|s| Duration::from_secs(s).min(RETRY_AFTER_CAP));
                Attempt::Retry {
                    retry_after,
                    error: AdapterError::Unavailable(format!("HTTP {status}")),
                }
            }
            _ => Attempt::Done(Err(AdapterError::Unavailable(format!("HTTP {status}")))),
        }
    }

    fn post_with_retry(&self, body: &str) -> Result<Vec<u8>, AdapterError> {
        let agent = self.agent();
        let mut attempt = 1;
        loop {
            match self.attempt(&agent, body) {
                Attempt::Done(result) => return result,
                Attempt::Retry { error, .. } if attempt >= MAX_ATTEMPTS => return Err(error),
                Attempt::Retry { retry_after, .. } => {
                    let backoff = BACKOFF_BASE * 2u32.pow(attempt - 1);
                    (self.sleeper)(retry_after.map_or(backoff, |r| r.max(backoff)));
                    attempt += 1;
                }
            }
        }
    }
}

enum Attempt {
    Done(Result<Vec<u8>, AdapterError>),
    Retry {
        retry_after: Option<Duration>,
        error: AdapterError,
    },
}

impl ModelAdapter for MetaAdapter {
    fn name(&self) -> String {
        format!("meta:{}", self.model)
    }

    fn complete_json(&self, req: &ModelRequest) -> Result<ModelReply, AdapterError> {
        let body = self.request_body(req);
        let bytes = self.post_with_retry(&body)?;
        parse_response(&bytes)
    }
}

fn parse_response(bytes: &[u8]) -> Result<ModelReply, AdapterError> {
    let response: Value =
        serde_json::from_slice(bytes).map_err(|e| bad_json("the response", &e))?;
    let choice = response
        .pointer("/choices/0")
        .ok_or_else(|| AdapterError::BadOutput("the response had no choices".to_string()))?;
    let refusal = choice
        .pointer("/message/refusal")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !refusal.is_empty() {
        return Err(AdapterError::Refused);
    }
    match choice.get("finish_reason").and_then(Value::as_str) {
        Some("stop") => {}
        Some("length") => return Err(AdapterError::Truncated),
        Some("content_filter") => return Err(AdapterError::Refused),
        _ => {
            return Err(AdapterError::BadOutput(
                "the response did not finish normally".to_string(),
            ));
        }
    }
    let content = choice
        .pointer("/message/content")
        .and_then(Value::as_str)
        .ok_or_else(|| AdapterError::BadOutput("the response had no text content".to_string()))?;
    let value = serde_json::from_str(unwrap_json_text(content))
        .map_err(|e| bad_json("the model's answer", &e))?;
    let model = response
        .get("model")
        .and_then(Value::as_str)
        .filter(|m| valid_model_id(m))
        .unwrap_or("unknown")
        .to_string();
    Ok(ModelReply {
        value,
        model,
        usage: parse_usage(&response),
    })
}

/// Missing or malformed fields count as 0. Reasoning tokens are already part of the completion tokens.
fn parse_usage(response: &Value) -> Usage {
    let count = |pointer: &str| {
        response
            .pointer(pointer)
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    Usage {
        prompt_tokens: count("/usage/prompt_tokens"),
        completion_tokens: count("/usage/completion_tokens"),
        reasoning_tokens: count("/usage/completion_tokens_details/reasoning_tokens"),
    }
}

/// Removes a leading `<think>...</think>` block and a single surrounding code fence.
fn unwrap_json_text(content: &str) -> &str {
    let mut text = content.trim();
    if let Some(rest) = text.strip_prefix("<think>")
        && let Some(end) = rest.find("</think>")
    {
        text = rest[end + "</think>".len()..].trim();
    }
    if let Some(rest) = text.strip_prefix("```")
        && let Some((info, body)) = rest.split_once('\n')
        && info.trim().chars().all(|c| c.is_ascii_alphanumeric())
        && let Some(inner) = body.trim_end().strip_suffix("```")
    {
        text = inner.trim();
    }
    text
}

/// Only the error class and position, because serde's messages can quote the offending text.
fn bad_json(what: &str, e: &serde_json::Error) -> AdapterError {
    use serde_json::error::Category;
    let class = match e.classify() {
        Category::Io => "read error",
        Category::Syntax => "syntax error",
        Category::Data => "data error",
        Category::Eof => "unexpected end",
    };
    AdapterError::BadOutput(format!(
        "{what} was not valid JSON ({class} at line {} column {})",
        e.line(),
        e.column()
    ))
}

fn valid_model_id(id: &str) -> bool {
    (1..=100).contains(&id.len())
        && id.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '@' | '+' | '-')
        })
}

const BAD_URL: &str = "MUNIX_META_URL must be https://, or http:// to a loopback host, with no credentials, query or fragment";

/// Returns the normalized base URL (no trailing slash) and whether the host is loopback.
fn validate_base_url(raw: &str) -> Result<(String, bool), AdapterError> {
    let bad = || AdapterError::Config(BAD_URL.to_string());
    let raw = raw.trim();
    if raw
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\\' || c == '?' || c == '#')
    {
        return Err(bad());
    }
    let lower = raw.to_ascii_lowercase();
    let (secure, rest) = if lower.starts_with("https://") {
        (true, &raw["https://".len()..])
    } else if lower.starts_with("http://") {
        (false, &raw["http://".len()..])
    } else {
        return Err(bad());
    };
    let (authority, path) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    if authority.is_empty() || authority.contains('@') {
        return Err(bad());
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (host, after) = inner.split_once(']').ok_or_else(bad)?;
        if host.parse::<Ipv6Addr>().is_err() {
            return Err(bad());
        }
        (host, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if let Some(port) = port
        && (port.is_empty()
            || !port.chars().all(|c| c.is_ascii_digit())
            || port.parse::<u16>().is_err())
    {
        return Err(bad());
    }
    let bracketed = authority.starts_with('[');
    if !bracketed
        && !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(bad());
    }
    if host.is_empty() || (bracketed && authority.len() > host.len() + 2 && port.is_none()) {
        return Err(bad());
    }
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())
        || host.parse::<Ipv6Addr>().is_ok_and(|ip| ip.is_loopback());
    if !secure && !loopback {
        return Err(bad());
    }
    let scheme = if secure { "https" } else { "http" };
    Ok((
        format!("{scheme}://{authority}{}", path.trim_end_matches('/')),
        loopback,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_blank_key_is_a_config_error() {
        let expected = AdapterError::Config("MODEL_API_KEY is not set".to_string());
        assert_eq!(
            MetaAdapter::from_vars("m", None, None).unwrap_err(),
            expected
        );
        assert_eq!(
            MetaAdapter::from_vars("m", Some("   "), None).unwrap_err(),
            expected
        );
        assert_eq!(
            MetaAdapter::new("https://x.example", "m", "").unwrap_err(),
            expected
        );
    }

    #[test]
    fn url_defaults_and_is_trimmed() {
        let a = MetaAdapter::from_vars("m", Some(" k "), Some("  ")).unwrap();
        assert_eq!(a.base_url, DEFAULT_BASE_URL);
        assert!(!a.loopback);
        assert_eq!(a.key.0, "k");
        let b = MetaAdapter::from_vars("m", Some("k"), Some("http://localhost:8080/v1/")).unwrap();
        assert_eq!(b.base_url, "http://localhost:8080/v1");
        assert!(b.loopback);
    }

    #[test]
    fn transport_policy() {
        let ok = [
            "https://api.meta.ai/v1",
            "HTTPS://example.com",
            "https://203.0.113.9:8443/x",
            "http://localhost",
            "http://127.0.0.1:1234/v1",
            "http://127.9.9.9",
            "http://[::1]:8080/v1",
        ];
        for url in ok {
            assert!(validate_base_url(url).is_ok(), "{url}");
        }
        let bad = [
            "http://example.com/v1",
            "http://10.0.0.1",
            "http://localhost.evil.com",
            "http://127.0.0.1.evil.com",
            "http://[::2]/",
            "https://user:pw@example.com",
            "https://user@example.com",
            "http://127.0.0.1@evil.com",
            "https://example.com/v1?x=1",
            "https://example.com/v1#frag",
            "ftp://example.com",
            "example.com",
            "https://",
            "https://example.com:notaport",
            "https://example.com:99999",
            "https://exa mple.com",
            "https://example.com\\@evil.com",
            "http://[::1]junk",
            "",
        ];
        for url in bad {
            assert_eq!(
                validate_base_url(url).unwrap_err(),
                AdapterError::Config(BAD_URL.to_string()),
                "{url}"
            );
        }
    }

    #[test]
    fn config_error_never_echoes_the_url_or_key() {
        let err = MetaAdapter::new("http://secret-host.example/v1", "m", "sk-secret")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secret-host") && !err.contains("sk-secret"));
    }

    #[test]
    fn model_name_is_validated() {
        for bad in ["", "a b", "m\n", &"x".repeat(101)] {
            assert!(matches!(
                MetaAdapter::new("https://x.example", bad, "k"),
                Err(AdapterError::Config(_))
            ));
        }
        assert!(valid_model_id("muse-spark-1.3"));
        assert!(valid_model_id("org/model:v1@2+x_y"));
    }

    #[test]
    fn unwraps_think_and_fences() {
        assert_eq!(unwrap_json_text("{\"a\":1}"), "{\"a\":1}");
        assert_eq!(
            unwrap_json_text("<think>hmm {}</think>\n{\"a\":1}"),
            "{\"a\":1}"
        );
        assert_eq!(unwrap_json_text("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(unwrap_json_text("```\n{\"a\":1}\n```\n"), "{\"a\":1}");
        assert_eq!(unwrap_json_text("<think>x</think>```json\n{}\n```"), "{}");
        assert_eq!(unwrap_json_text("<think>unclosed {}"), "<think>unclosed {}");
    }
}
