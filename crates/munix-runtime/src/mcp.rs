//! The agent's MCP channel: a minimal MCP server over newline-delimited JSON-RPC 2.0 on a reader and a writer (the
//! sandbox's stdout and stdin).
//!
//! It implements only what an MCP client needs to list and call tools: `initialize`, `notifications/initialized`,
//! `ping`, `tools/list` and `tools/call`. Everything the agent sends is untrusted input: malformed lines are
//! answered with JSON-RPC errors (or dropped, for notifications) and never end the session.

use std::io::{BufRead, Write};

use serde_json::Value;

/// One tool as the agent sees it in `tools/list`.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    /// A JSON Schema object for the arguments.
    pub input_schema: Value,
}

/// The answer to one `tools/call`: text content, flagged as an error or not (`isError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallResult {
    pub text: String,
    pub is_error: bool,
}

/// What the server asks of its owner.
pub trait McpHandler {
    fn tools(&self) -> Vec<ToolInfo>;

    /// Called for every `tools/call`, whatever the name. `arguments` is the request's `arguments` value as sent
    /// (an object, or `null` when absent).
    fn call(&mut self, name: &str, arguments: &Value) -> CallResult;

    /// Asked after every call: `true` ends the session (for example after a takeover). Defaults to never.
    fn should_stop(&self) -> bool {
        false
    }
}

/// Why `serve` returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeEnd {
    /// The agent closed its side (end of input).
    Closed,
    /// The handler asked to stop.
    Stopped,
}

#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// The longest line accepted. A longer line is answered with a parse error (id `null`) and skipped.
pub const MAX_LINE_BYTES: usize = 1 << 20;

/// The protocol version this server speaks. `initialize` answers with this version, whatever the client asked for.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Serves until the input ends or the handler asks to stop.
///
/// - Each line is one JSON-RPC message. Blank lines are ignored. A line that isn't valid JSON, or isn't an object,
///   gets error `-32700` / `-32600` with id `null`.
/// - Requests (with an `id`, a string or integer): `initialize` → `{protocolVersion, capabilities: {tools: {}},
///   serverInfo: {name: "munix", version}}`; `ping` → `{}`; `tools/list` → `{tools: [{name, description,
///   inputSchema}]}`; `tools/call` with `params.name` a string → `{content: [{type: "text", text}], isError}`;
///   a `tools/call` without a string name is `-32602`; any other method is `-32601`.
/// - Notifications (no `id`) are never answered. Responses from the client (with `result` or `error`) are ignored.
/// - Every reply is one line of JSON, flushed at once. Error messages are fixed strings: nothing from the agent's
///   input is echoed back except its `id`.
pub fn serve(
    reader: &mut dyn BufRead,
    writer: &mut dyn Write,
    handler: &mut dyn McpHandler,
) -> Result<ServeEnd, McpError> {
    loop {
        let line = match read_capped_line(reader)? {
            None => return Ok(ServeEnd::Closed),
            Some(Line::TooLong) => {
                send(writer, &error_reply(&Value::Null, -32700, "Parse error"))?;
                continue;
            }
            Some(Line::Bytes(bytes)) => bytes,
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let message: Value = match serde_json::from_slice(&line) {
            Ok(v) => v,
            Err(_) => {
                send(writer, &error_reply(&Value::Null, -32700, "Parse error"))?;
                continue;
            }
        };
        let Some(object) = message.as_object() else {
            send(
                writer,
                &error_reply(&Value::Null, -32600, "Invalid request"),
            )?;
            continue;
        };

        // A response from the client (or anything without a method that carries a result or error): ignored.
        let method = match object.get("method") {
            Some(Value::String(m)) => m.as_str(),
            Some(_) => {
                send(
                    writer,
                    &error_reply(&Value::Null, -32600, "Invalid request"),
                )?;
                continue;
            }
            None if object.contains_key("result") || object.contains_key("error") => continue,
            None => {
                send(
                    writer,
                    &error_reply(&Value::Null, -32600, "Invalid request"),
                )?;
                continue;
            }
        };
        let id = match object.get("id") {
            None => None,
            Some(v) if v.is_string() || v.is_i64() || v.is_u64() => Some(v.clone()),
            Some(_) => {
                send(
                    writer,
                    &error_reply(&Value::Null, -32600, "Invalid request"),
                )?;
                continue;
            }
        };
        // Notifications are never answered.
        let Some(id) = id else { continue };

        match method {
            "initialize" => {
                let result = serde_json::json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "munix", "version": env!("CARGO_PKG_VERSION") },
                });
                send(writer, &result_reply(&id, result))?;
            }
            "ping" => send(writer, &result_reply(&id, serde_json::json!({})))?,
            "tools/list" => {
                let tools: Vec<Value> = handler
                    .tools()
                    .into_iter()
                    .map(|t| {
                        serde_json::json!({
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": t.input_schema,
                        })
                    })
                    .collect();
                send(
                    writer,
                    &result_reply(&id, serde_json::json!({ "tools": tools })),
                )?;
            }
            "tools/call" => {
                let params = object.get("params");
                let Some(name) = params.and_then(|p| p.get("name")).and_then(Value::as_str) else {
                    send(writer, &error_reply(&id, -32602, "Invalid params"))?;
                    continue;
                };
                let null = Value::Null;
                let arguments = params.and_then(|p| p.get("arguments")).unwrap_or(&null);
                let outcome = handler.call(name, arguments);
                let result = serde_json::json!({
                    "content": [{ "type": "text", "text": outcome.text }],
                    "isError": outcome.is_error,
                });
                send(writer, &result_reply(&id, result))?;
                if handler.should_stop() {
                    return Ok(ServeEnd::Stopped);
                }
            }
            _ => send(writer, &error_reply(&id, -32601, "Method not found"))?,
        }
    }
}

fn result_reply(id: &Value, result: Value) -> Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_reply(id: &Value, code: i32, message: &'static str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

/// Writes one reply as a single line and flushes it.
fn send(writer: &mut dyn Write, reply: &Value) -> Result<(), McpError> {
    let mut text = serde_json::to_string(reply).map_err(std::io::Error::other)?;
    text.push('\n');
    writer.write_all(text.as_bytes())?;
    writer.flush()?;
    Ok(())
}

enum Line {
    Bytes(Vec<u8>),
    TooLong,
}

/// Reads one line without its newline, keeping at most `MAX_LINE_BYTES` in memory: the rest of a longer line is
/// read in chunks and thrown away. `None` is the end of input with nothing pending.
fn read_capped_line(reader: &mut dyn BufRead) -> Result<Option<Line>, McpError> {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let chunk = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if chunk.is_empty() {
            return Ok((too_long || !line.is_empty()).then(|| finish(line, too_long)));
        }
        let newline = chunk.iter().position(|b| *b == b'\n');
        let take = newline.unwrap_or(chunk.len());
        if !too_long {
            if line.len() + take > MAX_LINE_BYTES {
                too_long = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(&chunk[..take]);
            }
        }
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(finish(line, too_long)));
        }
    }
}

fn finish(mut line: Vec<u8>, too_long: bool) -> Line {
    if too_long {
        return Line::TooLong;
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Line::Bytes(line)
}
