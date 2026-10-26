#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufReader, Cursor};

use munix_runtime::mcp::{
    CallResult, MAX_LINE_BYTES, McpHandler, PROTOCOL_VERSION, ServeEnd, ToolInfo, serve,
};
use serde_json::{Value, json};

#[derive(Default)]
struct Fake {
    calls: Vec<(String, Value)>,
    stop_after: Option<usize>,
}

impl McpHandler for Fake {
    fn tools(&self) -> Vec<ToolInfo> {
        vec![ToolInfo {
            name: "web_open".into(),
            description: "Open a page".into(),
            input_schema: json!({"type": "object", "properties": {"url": {"type": "string"}}}),
        }]
    }

    fn call(&mut self, name: &str, arguments: &Value) -> CallResult {
        self.calls.push((name.to_string(), arguments.clone()));
        CallResult {
            text: format!("called {name}"),
            is_error: name == "bad",
        }
    }

    fn should_stop(&self) -> bool {
        self.stop_after.is_some_and(|n| self.calls.len() >= n)
    }
}

fn run_bytes(input: &[u8], handler: &mut Fake) -> (ServeEnd, Vec<Value>, String) {
    let mut reader = Cursor::new(input.to_vec());
    let mut out = Vec::new();
    let end = serve(&mut reader, &mut out, handler).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.is_empty() || text.ends_with('\n'));
    let replies = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    (end, replies, text)
}

fn run(lines: &[&str], handler: &mut Fake) -> (ServeEnd, Vec<Value>, String) {
    let mut input = lines.join("\n");
    input.push('\n');
    run_bytes(input.as_bytes(), handler)
}

#[test]
fn the_normal_round_trips() {
    let mut h = Fake::default();
    let (end, r, _) = run(
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"web_open","arguments":{"url":"ref:u1"}}}"#,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"bad","arguments":{}}}"#,
        ],
        &mut h,
    );
    assert_eq!(end, ServeEnd::Closed);
    assert_eq!(r.len(), 5);
    assert_eq!(r[0]["id"], 1);
    assert_eq!(r[0]["jsonrpc"], "2.0");
    assert_eq!(r[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(r[0]["result"]["capabilities"], json!({"tools": {}}));
    assert_eq!(r[0]["result"]["serverInfo"]["name"], "munix");
    assert!(r[0]["result"]["serverInfo"]["version"].is_string());
    assert_eq!(r[1]["result"], json!({}));
    assert_eq!(
        r[2]["result"]["tools"],
        json!([{
            "name": "web_open",
            "description": "Open a page",
            "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
        }])
    );
    assert_eq!(
        r[3]["result"],
        json!({"content": [{"type": "text", "text": "called web_open"}], "isError": false})
    );
    assert_eq!(r[4]["result"]["isError"], true);
    assert_eq!(
        h.calls,
        vec![
            ("web_open".to_string(), json!({"url": "ref:u1"})),
            ("bad".to_string(), json!({})),
        ]
    );
}

#[test]
fn notifications_get_no_reply_and_client_responses_are_ignored() {
    let mut h = Fake::default();
    let (end, r, text) = run(
        &[
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}"#,
            r#"{"jsonrpc":"2.0","method":"nope"}"#,
            r#"{"jsonrpc":"2.0","id":7,"result":{"ok":true}}"#,
            r#"{"jsonrpc":"2.0","id":8,"error":{"code":-1,"message":"m"}}"#,
        ],
        &mut h,
    );
    assert_eq!(end, ServeEnd::Closed);
    assert!(r.is_empty(), "{text}");
    // A `tools/call` sent as a notification is dropped, not executed.
    assert!(h.calls.is_empty());
}

#[test]
fn parse_errors_and_invalid_requests_use_id_null() {
    let mut h = Fake::default();
    let (end, r, _) = run(
        &[
            "{not json",
            "[1,2]",
            "42",
            r#"{"jsonrpc":"2.0","id":1,"method":5}"#,
            r#"{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0"}"#,
            r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#,
        ],
        &mut h,
    );
    assert_eq!(end, ServeEnd::Closed);
    let codes: Vec<i64> = r
        .iter()
        .map(|v| v["error"]["code"].as_i64().unwrap_or(0))
        .collect();
    assert_eq!(
        codes,
        vec![
            -32700, -32600, -32600, -32600, -32600, -32600, -32600, -32600, 0
        ]
    );
    for v in &r[..8] {
        assert_eq!(v["id"], Value::Null);
    }
    assert_eq!(r[8]["id"], 9);
    assert_eq!(r[8]["result"], json!({}));
}

#[test]
fn unknown_methods_and_bad_call_params() {
    let mut h = Fake::default();
    let (_, r, _) = run(
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/list"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":5}}"#,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":"x"}"#,
        ],
        &mut h,
    );
    assert_eq!(r[0]["error"]["code"], -32601);
    for v in &r[1..] {
        assert_eq!(v["error"]["code"], -32602);
    }
    assert_eq!(
        r.iter().map(|v| v["id"].clone()).collect::<Vec<_>>(),
        vec![json!(1), json!(2), json!(3), json!(4), json!(5)]
    );
    assert!(h.calls.is_empty());
}

#[test]
fn arguments_are_passed_through_as_given() {
    let mut h = Fake::default();
    run(
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","arguments":[1,2]}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"b","arguments":"text"}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"c"}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"d","arguments":null}}"#,
        ],
        &mut h,
    );
    assert_eq!(
        h.calls,
        vec![
            ("a".to_string(), json!([1, 2])),
            ("b".to_string(), json!("text")),
            ("c".to_string(), Value::Null),
            ("d".to_string(), Value::Null),
        ]
    );
}

#[test]
fn ids_are_echoed_exactly() {
    let mut h = Fake::default();
    let (_, r, text) = run(
        &[
            r#"{"jsonrpc":"2.0","id":"abc-1","method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":"7","method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":0,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":-3,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":18446744073709551615,"method":"ping"}"#,
        ],
        &mut h,
    );
    assert_eq!(r[0]["id"], json!("abc-1"));
    assert_eq!(r[1]["id"], json!("7"));
    assert_eq!(r[2]["id"], json!(7));
    assert_eq!(r[3]["id"], json!(0));
    assert_eq!(r[4]["id"], json!(-3));
    assert!(text.contains("18446744073709551615"));
}

#[test]
fn blank_lines_crlf_and_a_missing_final_newline() {
    let mut h = Fake::default();
    let input = "\n  \r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}";
    let (end, r, _) = run_bytes(input.as_bytes(), &mut h);
    assert_eq!(end, ServeEnd::Closed);
    assert_eq!(r.len(), 2);
    assert_eq!(r[1]["id"], 2);
}

#[test]
fn an_oversize_line_is_answered_once_and_the_next_line_works() {
    for capacity in [8usize, 4096, 1 << 22] {
        let mut h = Fake::default();
        let mut input = vec![b'x'; MAX_LINE_BYTES + 10];
        input.push(b'\n');
        input.extend_from_slice(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
        input.push(b'\n');
        let mut reader = BufReader::with_capacity(capacity, Cursor::new(input));
        let mut out = Vec::new();
        let end = serve(&mut reader, &mut out, &mut h).unwrap();
        assert_eq!(end, ServeEnd::Closed);
        let r: Vec<Value> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(r.len(), 2, "capacity {capacity}");
        assert_eq!(r[0]["error"]["code"], -32700);
        assert_eq!(r[0]["id"], Value::Null);
        assert_eq!(r[1]["id"], 1);
    }
}

#[test]
fn an_oversize_line_at_end_of_input_is_answered_then_closed() {
    let mut h = Fake::default();
    let input = vec![b'y'; MAX_LINE_BYTES * 2];
    let (end, r, _) = run_bytes(&input, &mut h);
    assert_eq!(end, ServeEnd::Closed);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["error"]["code"], -32700);
}

#[test]
fn a_line_of_exactly_the_cap_is_still_read() {
    let mut h = Fake::default();
    let prefix = br#"{"jsonrpc":"2.0","id":1,"method":"ping","x":""#;
    let suffix = br#""}"#;
    let mut line = prefix.to_vec();
    line.resize(MAX_LINE_BYTES - suffix.len(), b'a');
    line.extend_from_slice(suffix);
    assert_eq!(line.len(), MAX_LINE_BYTES);
    line.push(b'\n');
    let (_, r, _) = run_bytes(&line, &mut h);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["result"], json!({}));
}

#[test]
fn should_stop_ends_the_session_with_stopped() {
    let mut h = Fake {
        stop_after: Some(1),
        ..Fake::default()
    };
    let (end, r, _) = run(
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
        ],
        &mut h,
    );
    assert_eq!(end, ServeEnd::Stopped);
    // The call that triggered the stop is still answered; nothing after it is.
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["id"], 1);
}

#[test]
fn end_of_input_ends_with_closed() {
    let mut h = Fake::default();
    let (end, r, _) = run_bytes(b"", &mut h);
    assert_eq!(end, ServeEnd::Closed);
    assert!(r.is_empty());
}

#[test]
fn error_messages_never_echo_the_input() {
    let mut h = Fake::default();
    let (_, r, text) = run(
        &[
            "{SECRET-PARSE-MARKER",
            "[\"SECRET-ARRAY-MARKER\"]",
            r#"{"jsonrpc":"2.0","id":1,"method":"SECRET-METHOD-MARKER"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":{"x":"SECRET-NAME-MARKER"}}}"#,
            r#"{"jsonrpc":"2.0","id":{"k":"SECRET-ID-MARKER"},"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":{"k":"SECRET-M2-MARKER"}}"#,
        ],
        &mut h,
    );
    assert_eq!(r.len(), 6);
    assert!(!text.contains("SECRET"), "{text}");
}

#[test]
fn a_writer_failure_is_an_error_not_a_panic() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("boom"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut reader = Cursor::new(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec());
    assert!(serve(&mut reader, &mut Broken, &mut Fake::default()).is_err());
}
