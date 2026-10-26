//! `email.send` over SMTP to a local sink.
//!
//! The server address must be loopback, so a demo or test can never mail a real mailbox. There is
//! no TLS and no authentication: the sink is a local Mailpit. The Vault credential the Gate hands
//! in is ignored on purpose and never reaches the message or the wire.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::{Address, Message, SmtpTransport, Transport};
use munix_core::validate::Scalar;
use munix_core::validate::is_valid as is_valid_scalar_string;
use munix_gate::tool::{Tool, ToolFailure};
use munix_gate::vault::Credential;
use serde_json::{Value, json};

use crate::ToolConfigError;

/// Most recipients allowed in `to` and in `cc` (the manifest's `max: 5`).
const MAX_RECIPIENTS: usize = 5;
/// How long a send may take before it counts as unavailable.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_SERVER: &str = "127.0.0.1:1025";
/// `.example` is reserved (RFC 2606), so the default sender can never be a real mailbox.
const DEFAULT_FROM: &str = "agent@munix.example";

/// Distinguishes message ids created within the same clock tick.
static MESSAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Sends mail through an SMTP server on a loopback address.
#[derive(Debug)]
pub struct SmtpEmail {
    server: SocketAddr,
    from: String,
}

impl SmtpEmail {
    /// `server` is `host:port`, e.g. `127.0.0.1:1025`; `from` is the sender address.
    /// Errors if the address does not parse, is not loopback, or `from` is not a valid email.
    pub fn new(server: &str, from: &str) -> Result<Self, ToolConfigError> {
        let server = parse_loopback(server).ok_or_else(|| {
            ToolConfigError::Invalid("smtp server must be a loopback host:port".into())
        })?;
        if !is_valid_scalar_string(Scalar::Email, from) {
            return Err(ToolConfigError::Invalid(
                "smtp sender is not a valid email address".into(),
            ));
        }
        Ok(SmtpEmail {
            server,
            from: from.to_owned(),
        })
    }

    /// From `MUNIX_SMTP` (default `127.0.0.1:1025`) and `MUNIX_SMTP_FROM` (default `agent@munix.example`).
    pub fn from_env() -> Result<Self, ToolConfigError> {
        let server = std::env::var("MUNIX_SMTP").unwrap_or_else(|_| DEFAULT_SERVER.to_owned());
        let from = std::env::var("MUNIX_SMTP_FROM").unwrap_or_else(|_| DEFAULT_FROM.to_owned());
        Self::new(&server, &from)
    }
}

impl Tool for SmtpEmail {
    fn call(
        &self,
        args: &BTreeMap<String, Value>,
        // The manifest names a Gmail credential, but a local sink needs none. It is dropped here.
        _credential: Option<&Credential>,
    ) -> Result<BTreeMap<String, Value>, ToolFailure> {
        let mail = parse_args(args)?;
        let message = build_message(&self.from, &mail)?;

        let transport = SmtpTransport::builder_dangerous(self.server.ip().to_string())
            .port(self.server.port())
            .timeout(Some(SEND_TIMEOUT))
            .build();
        transport.send(&message).map_err(classify)?;

        let mut out = BTreeMap::new();
        out.insert("message_id".to_owned(), json!(new_message_id()));
        Ok(out)
    }
}

/// The validated arguments of one `email.send` call.
struct Mail {
    to: Vec<Address>,
    cc: Vec<Address>,
    subject: String,
    body: String,
}

/// Accepts `IP:port` for a loopback IP, and `localhost:port` (as 127.0.0.1). Nothing else.
fn parse_loopback(server: &str) -> Option<SocketAddr> {
    let addr = match server.parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            let (host, port) = server.split_once(':')?;
            if host != "localhost" {
                return None;
            }
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port.parse().ok()?)
        }
    };
    (addr.ip().is_loopback() && addr.port() != 0).then_some(addr)
}

fn parse_args(args: &BTreeMap<String, Value>) -> Result<Mail, ToolFailure> {
    const KNOWN: [&str; 5] = ["to", "cc", "subject", "body", "attachments"];
    if args.keys().any(|k| !KNOWN.contains(&k.as_str())) {
        return Err(ToolFailure::BadInput);
    }
    match args.get("attachments") {
        None => {}
        Some(Value::Array(a)) if a.is_empty() => {}
        Some(_) => return Err(ToolFailure::BadInput),
    }
    let to = addresses(args.get("to").ok_or(ToolFailure::BadInput)?)?;
    let cc = match args.get("cc") {
        Some(v) => addresses(v)?,
        None => Vec::new(),
    };
    if to.is_empty() {
        return Err(ToolFailure::BadInput);
    }
    let subject = string_arg(args, "subject")?;
    // A line break in the subject would let it start extra headers.
    if subject.contains(['\r', '\n']) {
        return Err(ToolFailure::BadInput);
    }
    let body = string_arg(args, "body")?;
    Ok(Mail {
        to,
        cc,
        subject,
        body,
    })
}

fn string_arg(args: &BTreeMap<String, Value>, key: &str) -> Result<String, ToolFailure> {
    match args.get(key) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(ToolFailure::BadInput),
    }
}

/// An array of at most [`MAX_RECIPIENTS`] valid email addresses.
fn addresses(value: &Value) -> Result<Vec<Address>, ToolFailure> {
    let Value::Array(items) = value else {
        return Err(ToolFailure::BadInput);
    };
    if items.len() > MAX_RECIPIENTS {
        return Err(ToolFailure::BadInput);
    }
    items
        .iter()
        .map(|item| match item {
            Value::String(s) if is_valid_scalar_string(Scalar::Email, s) => {
                s.parse::<Address>().map_err(|_| ToolFailure::BadInput)
            }
            _ => Err(ToolFailure::BadInput),
        })
        .collect()
}

fn build_message(from: &str, mail: &Mail) -> Result<Message, ToolFailure> {
    let from = from.parse::<Address>().map_err(|_| ToolFailure::Internal)?;
    let mut builder = Message::builder()
        .from(Mailbox::new(None, from))
        .subject(mail.subject.as_str());
    for address in &mail.to {
        builder = builder.to(Mailbox::new(None, address.clone()));
    }
    for address in &mail.cc {
        builder = builder.cc(Mailbox::new(None, address.clone()));
    }
    builder
        .header(ContentType::TEXT_PLAIN)
        .body(mail.body.clone())
        .map_err(|_| ToolFailure::BadInput)
}

/// Maps a transport error to a coarse code. The error's own text is never used.
fn classify(err: lettre::transport::smtp::Error) -> ToolFailure {
    if err.is_permanent() {
        ToolFailure::BadInput
    } else if err.is_client() || err.is_response() {
        ToolFailure::Internal
    } else {
        // Timeouts, refused or dropped connections, and 4xx replies.
        ToolFailure::Unavailable
    }
}

/// `msg-` plus 16 hex characters: 40 bits of clock and a 24-bit counter, so ids do not repeat.
fn new_message_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let counter = MESSAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("msg-{:016x}", (nanos << 24) | (counter & 0x00ff_ffff))
}
