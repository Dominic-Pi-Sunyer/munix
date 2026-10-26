//! A tiny scripted HTTP server on 127.0.0.1 that records raw requests.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use munix_adapters::{MetaAdapter, ModelRequest};
use serde_json::{Value, json};

pub const KEY: &str = "sk-test-SECRET-123";

pub struct Canned {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub delay: Duration,
}

impl Canned {
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: b"{\"error\":\"body-must-not-leak\"}".to_vec(),
            delay: Duration::ZERO,
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    pub fn json(body: &Value) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.to_string().into_bytes(),
            delay: Duration::ZERO,
        }
    }

    pub fn reply(content: &str, finish_reason: &str) -> Self {
        Self::json(&json!({
            "model": "muse-spark-1.3",
            "choices": [{"index": 0, "finish_reason": finish_reason, "message": {"role": "assistant", "content": content}}]
        }))
    }

    pub fn ok(value: &Value) -> Self {
        Self::reply(&value.to_string(), "stop")
    }
}

pub struct TestServer {
    pub addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl TestServer {
    pub fn start(responses: Vec<Canned>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = requests.clone();
        let mut queue = std::collections::VecDeque::from(responses);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(raw) = read_request(&mut stream) else {
                    continue;
                };
                log.lock().unwrap().push(raw);
                let canned = queue.pop_front().unwrap_or_else(|| Canned::status(599));
                std::thread::sleep(canned.delay);
                let mut head = format!(
                    "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    canned.status,
                    canned.body.len()
                );
                for (k, v) in &canned.headers {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&canned.body);
                let _ = stream.flush();
            }
        });
        Self { addr, requests }
    }

    pub fn base_url(&self) -> String {
        format!("http://{}/v1", self.addr)
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn read_request(stream: &mut TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
        if let Some(end) = head_end {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return Some(String::from_utf8_lossy(&buf).into_owned());
            }
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Splits a recorded raw request into (lowercased header block, body).
pub fn split(raw: &str) -> (String, String) {
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    (head.to_ascii_lowercase(), body.to_string())
}

pub fn request(schema: Value) -> ModelRequest {
    ModelRequest {
        system: "You are the supervisor.".to_string(),
        user: "Approve or deny.".to_string(),
        schema_name: "verdict".to_string(),
        schema,
        max_output_tokens: 256,
    }
}

pub fn verdict_schema() -> Value {
    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Verdict",
        "type": "object",
        "properties": {"verdict": {"type": "string", "enum": ["approve", "deny"]}, "reason": {"type": "string", "maxLength": 200}},
        "required": ["verdict"]
    })
}

/// An adapter pointed at the server whose sleeps are recorded instead of taken.
pub fn adapter(server: &TestServer) -> (MetaAdapter, Arc<Mutex<Vec<Duration>>>) {
    let sleeps = Arc::new(Mutex::new(Vec::new()));
    let log = sleeps.clone();
    let adapter = MetaAdapter::new(&server.base_url(), "muse-spark-1.3", KEY)
        .unwrap()
        .with_timeout(Duration::from_secs(10))
        .with_sleeper(move |d| log.lock().unwrap().push(d));
    (adapter, sleeps)
}
