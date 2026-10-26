//! Offline tests for `email.send`: a tiny fake SMTP server on loopback records what the tool
//! says to it. One `#[ignore]`d test talks to a real Mailpit when `MUNIX_LIVE_SMTP=1`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use munix_core::validate::Scalar;
use munix_core::validate::is_valid as is_valid_scalar_string;
use munix_gate::tool::{Tool, ToolFailure};
use munix_gate::vault::Credential;
use munix_tools::ToolConfigError;
use munix_tools::email::SmtpEmail;
use serde_json::{Value, json};

const SECRET: &str = "ya29.super-secret-oauth-token";

/// A one-connection fake SMTP server. `transcript` holds every client line, in order.
struct FakeSmtp {
    addr: String,
    transcript: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

impl FakeSmtp {
    /// Starts the server. A RCPT line containing `reject_rcpt` is answered with `550`.
    fn start(reject_rcpt: Option<&'static str>) -> FakeSmtp {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr").to_string();
        let transcript = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (t, s) = (transcript.clone(), stop.clone());
        let handle = thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking");
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .expect("timeout");
                        let _ = serve(stream, &t, reject_rcpt);
                        return;
                    }
                    Err(_) => thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        FakeSmtp {
            addr,
            transcript,
            stop,
            handle,
        }
    }

    /// Stops the server (if nobody connected) and returns what the client sent.
    fn finish(self) -> String {
        thread::sleep(Duration::from_millis(100));
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().expect("server thread");
        let lines = self.transcript.lock().expect("lock");
        lines.join("\n")
    }
}

fn serve(
    stream: TcpStream,
    transcript: &Mutex<Vec<String>>,
    reject_rcpt: Option<&str>,
) -> std::io::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    writer.write_all(b"220 fake ESMTP\r\n")?;
    let mut in_data = false;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let text = line.trim_end_matches(['\r', '\n']).to_owned();
        transcript.lock().expect("lock").push(text.clone());
        if in_data {
            if text == "." {
                in_data = false;
                writer.write_all(b"250 queued\r\n")?;
            }
            continue;
        }
        let upper = text.to_ascii_uppercase();
        let reply: &[u8] = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            b"250-fake\r\n250 8BITMIME\r\n"
        } else if upper.starts_with("RCPT") && reject_rcpt.is_some_and(|r| text.contains(r)) {
            b"550 no such user\r\n"
        } else if upper.starts_with("MAIL")
            || upper.starts_with("RCPT")
            || upper.starts_with("RSET")
        {
            b"250 ok\r\n"
        } else if upper.starts_with("DATA") {
            in_data = true;
            b"354 go ahead\r\n"
        } else if upper.starts_with("QUIT") {
            writer.write_all(b"221 bye\r\n")?;
            return Ok(());
        } else {
            b"502 unsupported\r\n"
        };
        writer.write_all(reply)?;
    }
}

fn tool(server: &FakeSmtp) -> SmtpEmail {
    SmtpEmail::new(&server.addr, "agent@munix.example").expect("config")
}

fn args(v: Value) -> BTreeMap<String, Value> {
    v.as_object()
        .expect("object")
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn good_args() -> Value {
    json!({
        "to": ["alice@example.com", "bob@example.org"],
        "cc": ["carol@example.net"],
        "subject": "Quarterly report",
        "body": "Hello from the test.\nSecond line.",
    })
}

fn send(tool: &SmtpEmail, v: Value) -> Result<BTreeMap<String, Value>, ToolFailure> {
    tool.call(&args(v), Some(&Credential::new(SECRET)))
}

#[test]
fn sends_to_all_recipients_with_subject_and_body() {
    let server = FakeSmtp::start(None);
    let out = send(&tool(&server), good_args()).expect("sent");
    let transcript = server.finish();

    assert!(
        transcript.contains("MAIL FROM:<agent@munix.example>"),
        "{transcript}"
    );
    for rcpt in ["alice@example.com", "bob@example.org", "carol@example.net"] {
        assert!(
            transcript.contains(&format!("RCPT TO:<{rcpt}>")),
            "{transcript}"
        );
    }
    assert_eq!(transcript.matches("RCPT TO:").count(), 3, "{transcript}");
    assert!(
        transcript.contains("Subject: Quarterly report"),
        "{transcript}"
    );
    assert!(transcript.contains("Hello from the test."), "{transcript}");
    assert!(transcript.contains("Second line."), "{transcript}");
    assert!(
        transcript.to_ascii_lowercase().contains("text/plain"),
        "{transcript}"
    );

    let id = out["message_id"].as_str().expect("id string");
    assert!(is_valid_scalar_string(Scalar::Id, id), "{id}");
    assert_eq!(out.len(), 1);
}

#[test]
fn credential_never_reaches_the_wire() {
    let server = FakeSmtp::start(None);
    send(&tool(&server), good_args()).expect("sent");
    let transcript = server.finish();
    assert!(!transcript.contains(SECRET), "{transcript}");
    assert!(!transcript.contains("vault://"), "{transcript}");
    assert!(
        !transcript.to_ascii_uppercase().contains("AUTH"),
        "{transcript}"
    );
}

#[test]
fn cc_and_empty_attachments_are_optional() {
    let server = FakeSmtp::start(None);
    let out = send(
        &tool(&server),
        json!({"to": ["alice@example.com"], "subject": "s", "body": "b", "attachments": []}),
    );
    let transcript = server.finish();
    assert!(out.is_ok(), "{transcript}");
    assert_eq!(transcript.matches("RCPT TO:").count(), 1);
}

#[test]
fn message_ids_are_valid_and_distinct() {
    let a = FakeSmtp::start(None);
    let b = FakeSmtp::start(None);
    let first = send(&tool(&a), good_args()).expect("first");
    let second = send(&tool(&b), good_args()).expect("second");
    a.finish();
    b.finish();
    let (x, y) = (
        first["message_id"].as_str().expect("id"),
        second["message_id"].as_str().expect("id"),
    );
    assert!(x.starts_with("msg-") && x.len() == 20, "{x}");
    assert!(is_valid_scalar_string(Scalar::Id, x) && is_valid_scalar_string(Scalar::Id, y));
    assert_ne!(x, y);
}

#[test]
fn non_loopback_servers_are_rejected() {
    for server in [
        "10.0.0.1:25",
        "smtp.gmail.com:587",
        "192.168.1.5:1025",
        "8.8.8.8:25",
        "[2001:db8::1]:25",
        "0.0.0.0:25",
        "127.0.0.1",
        "127.0.0.1:0",
        "localhost.evil.example:25",
        "evil.example:25",
        "localhost:notaport",
        "",
    ] {
        let err = SmtpEmail::new(server, "agent@munix.example").expect_err(server);
        let ToolConfigError::Invalid(text) = err;
        assert!(
            !text.contains(server) || server.is_empty(),
            "error echoes input: {text}"
        );
    }
}

#[test]
fn loopback_servers_are_accepted() {
    for server in [
        "127.0.0.1:1025",
        "127.1.2.3:2525",
        "[::1]:1025",
        "localhost:1025",
    ] {
        SmtpEmail::new(server, "agent@munix.example").unwrap_or_else(|e| panic!("{server}: {e}"));
    }
}

#[test]
fn invalid_sender_is_rejected() {
    for from in [
        "",
        "not-an-email",
        "a@b@c",
        "agent@munix.example\r\nBcc: x@evil.example",
        "a b@example.com",
    ] {
        assert!(SmtpEmail::new("127.0.0.1:1025", from).is_err(), "{from:?}");
    }
}

#[test]
fn bad_args_are_bad_input() {
    let server = FakeSmtp::start(None);
    let t = tool(&server);
    let six: Vec<String> = (0..6).map(|i| format!("u{i}@example.com")).collect();
    let cases = [
        json!({"to": "alice@example.com", "subject": "s", "body": "b"}),
        json!({"to": [], "subject": "s", "body": "b"}),
        json!({"to": six, "subject": "s", "body": "b"}),
        json!({"to": ["alice@example.com"], "cc": six, "subject": "s", "body": "b"}),
        json!({"to": ["alice@example.com"], "cc": "carol@example.com", "subject": "s", "body": "b"}),
        json!({"to": ["not-an-email"], "subject": "s", "body": "b"}),
        json!({"to": ["alice@example.com", 7], "subject": "s", "body": "b"}),
        json!({"to": ["alice@example.com>\r\nRCPT TO:<x@evil.example"], "subject": "s", "body": "b"}),
        json!({"to": ["alice@example.com"], "cc": ["bad address"], "subject": "s", "body": "b"}),
        json!({"subject": "s", "body": "b"}),
        json!({"to": ["alice@example.com"], "body": "b"}),
        json!({"to": ["alice@example.com"], "subject": "s"}),
        json!({"to": ["alice@example.com"], "subject": 5, "body": "b"}),
        json!({"to": ["alice@example.com"], "subject": "s", "body": ["b"]}),
        json!({"to": ["alice@example.com"], "subject": "s", "body": "b", "bcc": ["x@evil.example"]}),
        json!({"to": ["alice@example.com"], "subject": "s", "body": "b", "attachments": ["ref"]}),
        json!({"to": ["alice@example.com"], "subject": "s", "body": "b", "attachments": "x"}),
    ];
    for case in cases {
        assert_eq!(send(&t, case.clone()), Err(ToolFailure::BadInput), "{case}");
    }
    assert!(server.finish().is_empty(), "nothing should have been sent");
}

#[test]
fn header_injection_in_subject_sends_nothing() {
    let server = FakeSmtp::start(None);
    let t = tool(&server);
    for subject in [
        "Hi\r\nBcc: x@evil.example",
        "Hi\nBcc: x@evil.example",
        "Hi\rBcc: x@evil.example",
    ] {
        let result = send(
            &t,
            json!({"to": ["alice@example.com"], "subject": subject, "body": "b"}),
        );
        assert_eq!(result, Err(ToolFailure::BadInput), "{subject:?}");
    }
    let transcript = server.finish();
    assert!(transcript.is_empty(), "something was sent: {transcript}");
}

#[test]
fn server_not_listening_is_unavailable() {
    let addr = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr").to_string()
    };
    let t = SmtpEmail::new(&addr, "agent@munix.example").expect("config");
    assert_eq!(send(&t, good_args()), Err(ToolFailure::Unavailable));
}

#[test]
fn rejected_recipient_is_bad_input() {
    let server = FakeSmtp::start(Some("bob@example.org"));
    let result = send(&tool(&server), good_args());
    server.finish();
    assert_eq!(result, Err(ToolFailure::BadInput));
}

#[test]
fn missing_credential_is_fine() {
    let server = FakeSmtp::start(None);
    let out = tool(&server).call(&args(good_args()), None);
    server.finish();
    assert!(out.is_ok());
}

/// Sends to a real Mailpit at 127.0.0.1:1025. Run with `MUNIX_LIVE_SMTP=1 cargo test -- --ignored`.
#[test]
#[ignore = "needs Mailpit on 127.0.0.1:1025 and MUNIX_LIVE_SMTP=1"]
fn live_mailpit() {
    if std::env::var("MUNIX_LIVE_SMTP").as_deref() != Ok("1") {
        eprintln!("MUNIX_LIVE_SMTP is not 1; skipping");
        return;
    }
    let t = SmtpEmail::new("127.0.0.1:1025", "agent@munix.example").expect("config");
    let out = send(
        &t,
        json!({"to": ["demo@example.com"], "subject": "Munix live test", "body": "Sent by the munix-tools live test."}),
    )
    .expect("mailpit accepted the message");
    let id = out["message_id"].as_str().expect("id");
    assert!(is_valid_scalar_string(Scalar::Id, id));
}
