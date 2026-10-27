//! `web.open` through Web Speed OSS, an MCP server over stdio.
//!
//! The child is started on the first call and reused. One call is one `tools/call` of
//! `interpret_page`; the answer is rendered as plain text and a short list of links, cleaned of
//! invisible and control characters so the Gate's validators accept it. Anything that goes wrong
//! with the child (timeout, closed pipe, protocol garbage) kills it and surfaces as
//! [`ToolFailure::Unavailable`]; the next call starts a fresh one. Web Speed's own error
//! messages are never copied: only its error code picks a coarse [`ToolFailure`].
//!
//! A [`SiteTemplate`] for the requested site splits the page into fields the manifest labels by region (listing,
//! editorial, reviews) instead of one `page` text. It applies only when the page map's final URL is still on the
//! template's host and paths, so a redirect to another site gets the plain `page`.
//!
//! The child gets a cleared environment plus a short allowlist of variables, so secrets in the
//! parent (model API keys, SMTP passwords) never reach it.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use munix_core::ids::RefId;
use munix_core::validate::Scalar;
use munix_core::validate::{is_clean_text, is_valid as is_valid_scalar_string};
use munix_gate::tool::{Tool, ToolFailure};
use munix_gate::vault::Credential;
use serde_json::{Value, json};

use crate::ToolConfigError;
use crate::site::{SiteTemplate, SiteTemplates};

/// MCP protocol revision announced in `initialize`.
const PROTOCOL_VERSION: &str = "2025-06-18";
/// Longest single line read from the child.
const MAX_LINE_BYTES: u64 = 16 * 1024 * 1024;
/// Longest `page` text, in characters.
const MAX_PAGE_CHARS: usize = 20_000;
/// Most links returned.
const MAX_LINKS: usize = 50;
/// Most entries in one template field built with `each`.
const MAX_ITEMS: usize = 50;
/// Parent environment variables the child may see.
const PASSED_ENV: [&str; 4] = ["PATH", "HOME", "LANG", "PLAYWRIGHT_BROWSERS_PATH"];

/// How to launch Web Speed OSS.
#[derive(Clone, Debug, PartialEq)]
pub struct WebSpeedConfig {
    /// Interpreter, e.g. `<dir>/venv/bin/python`.
    pub program: PathBuf,
    /// Arguments, e.g. `[<dir>/server.py]`.
    pub args: Vec<String>,
    /// Working directory for the child.
    pub cwd: PathBuf,
    /// Passed to the child as `WEBSPEED_ALLOW_HOSTS` when set (e.g. `127.0.0.1:8080`).
    pub allow_hosts: Option<String>,
    /// Limit for one `tools/call` round trip (and for the startup handshake).
    pub timeout: Duration,
    /// Site templates; none by default, so every page is one unclassified `page` text.
    pub templates: SiteTemplates,
}

impl WebSpeedConfig {
    /// The standard layout of a Web Speed OSS checkout: `<dir>/venv/bin/python <dir>/server.py`,
    /// 60 s timeout, no allowlist.
    pub fn from_dir(dir: impl Into<PathBuf>) -> Self {
        let dir: PathBuf = dir.into();
        Self {
            program: dir.join("venv").join("bin").join("python"),
            args: vec![dir.join("server.py").to_string_lossy().into_owned()],
            cwd: dir,
            allow_hosts: None,
            timeout: Duration::from_secs(60),
            templates: SiteTemplates::default(),
        }
    }
}

/// The `web.open` tool. Starts Web Speed OSS lazily on first use and keeps it running.
pub struct WebSpeedOpen {
    config: WebSpeedConfig,
    session: Mutex<Option<Session>>,
}

impl WebSpeedOpen {
    /// Checks that `config.program` exists. Does not start the child yet.
    pub fn new(config: WebSpeedConfig) -> Result<Self, ToolConfigError> {
        if !config.program.is_file() {
            return Err(ToolConfigError::Invalid(format!(
                "web.open: program {} is not a file",
                config.program.display()
            )));
        }
        if config.timeout.is_zero() {
            return Err(ToolConfigError::Invalid(
                "web.open: timeout must be above zero".into(),
            ));
        }
        Ok(Self {
            config,
            session: Mutex::new(None),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Option<Session>> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Tool for WebSpeedOpen {
    fn call(
        &self,
        args: &BTreeMap<String, Value>,
        _credential: Option<&Credential>,
    ) -> Result<BTreeMap<String, Value>, ToolFailure> {
        let url = url_arg(args)?;
        let mut guard = self.lock();

        // A child that died between calls is replaced without failing the call.
        if guard.as_mut().is_some_and(|s| !s.is_alive()) {
            *guard = None;
        }
        if guard.is_none() {
            *guard = Some(Session::start(&self.config)?);
        }
        let Some(session) = guard.as_mut() else {
            return Err(ToolFailure::Internal);
        };

        let reply = session.call_tool(
            "interpret_page",
            json!({"url": url, "read": true}),
            self.config.timeout,
        );
        let response = match reply {
            Ok(response) => response,
            Err(failure) => {
                // The stream may hold a half-read answer or a wedged server: start over next time.
                *guard = None;
                return Err(failure);
            }
        };
        drop(guard);
        interpret(&response, &self.config.templates, url)
    }
}

/// The single `url` argument, checked once more here because the tool also runs without the Gate.
/// Where Web Speed's Python writes and reads bytecode caches: a per-process directory outside every sealed tree.
fn pycache_prefix() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("munix-webspeed-pycache-{}", std::process::id()))
}

fn url_arg(args: &BTreeMap<String, Value>) -> Result<&str, ToolFailure> {
    if args.len() != 1 {
        return Err(ToolFailure::BadInput);
    }
    match args.get("url").and_then(Value::as_str) {
        Some(url) if is_valid_scalar_string(Scalar::Url, url) => Ok(url),
        _ => Err(ToolFailure::BadInput),
    }
}

// ---------------------------------------------------------------------------------------------
// MCP session over the child's stdio
// ---------------------------------------------------------------------------------------------

/// What the reader thread sends.
enum Line {
    Text(String),
    /// End of stream, a read error, or a line over the cap.
    Closed,
}

/// A running child with a completed MCP handshake.
struct Session {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<Line>,
    next_id: u64,
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Session {
    /// Spawn the child and run the `initialize` handshake.
    fn start(config: &WebSpeedConfig) -> Result<Self, ToolFailure> {
        let mut command = Command::new(&config.program);
        command
            .args(&config.args)
            .current_dir(&config.cwd)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for name in PASSED_ENV {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        if let Some(hosts) = &config.allow_hosts {
            command.env("WEBSPEED_ALLOW_HOSTS", hosts);
        }
        // Web Speed OSS shares every page map it builds with a hosted registry unless told not to. Pages the agent
        // reads stay on this machine, so sync is always off and not configurable.
        command.env("WEB_SPEED_REGISTRY_SYNC", "false");
        // Python must not read bytecode caches from inside Web Speed's tree: the Integrity Seal skips `__pycache__`,
        // so a planted `.pyc` there would run unsealed code. Caches go to a private directory instead.
        command.env("PYTHONPYCACHEPREFIX", pycache_prefix());
        let mut child = command.spawn().map_err(|_| ToolFailure::Unavailable)?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ToolFailure::Unavailable);
        };
        let (tx, lines) = mpsc::channel();
        thread::spawn(move || read_lines(stdout, &tx));

        // From here on `Drop` reaps the child on every early return.
        let mut session = Self {
            child,
            stdin,
            lines,
            next_id: 1,
        };
        let init = session.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "munix", "version": env!("CARGO_PKG_VERSION")},
            }),
            config.timeout,
        )?;
        if init.get("error").is_some() || init.get("result").is_none() {
            return Err(ToolFailure::Unavailable);
        }
        session.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
        Ok(session)
    }

    fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn send(&mut self, message: &Value) -> Result<(), ToolFailure> {
        let mut bytes = serde_json::to_vec(message).map_err(|_| ToolFailure::Internal)?;
        bytes.push(b'\n');
        self.stdin
            .write_all(&bytes)
            .and_then(|()| self.stdin.flush())
            .map_err(|_| ToolFailure::Unavailable)
    }

    /// Send a request and wait for the response with its id. Lines that are not JSON, or are
    /// notifications or server requests, are skipped.
    fn request(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, ToolFailure> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let line = match self.lines.recv_timeout(remaining) {
                Ok(Line::Text(line)) => line,
                Ok(Line::Closed)
                | Err(RecvTimeoutError::Disconnected | RecvTimeoutError::Timeout) => {
                    return Err(ToolFailure::Unavailable);
                }
            };
            let Ok(message) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if message.get("method").is_none()
                && message.get("id").and_then(Value::as_u64) == Some(id)
            {
                return Ok(message);
            }
        }
    }

    fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
        timeout: Duration,
    ) -> Result<Value, ToolFailure> {
        self.request(
            "tools/call",
            json!({"name": name, "arguments": arguments}),
            timeout,
        )
    }
}

/// Reader thread: one message per line, ended by EOF, an I/O error, or an oversized line.
fn read_lines(stdout: impl Read, tx: &mpsc::Sender<Line>) {
    let mut reader = BufReader::new(stdout);
    loop {
        let mut buf = Vec::new();
        let read = (&mut reader)
            .take(MAX_LINE_BYTES + 1)
            .read_until(b'\n', &mut buf);
        let complete = buf.last() == Some(&b'\n');
        match read {
            Ok(0) | Err(_) => break,
            Ok(_) if !complete => break,
            Ok(_) => {
                let line = String::from_utf8_lossy(&buf).trim_end().to_owned();
                if tx.send(Line::Text(line)).is_err() {
                    return;
                }
            }
        }
    }
    let _ = tx.send(Line::Closed);
}

// ---------------------------------------------------------------------------------------------
// Turning Web Speed's answer into the manifest's output
// ---------------------------------------------------------------------------------------------

/// Map one `tools/call` response to the tool output or a coarse failure.
///
/// With a template that matches both the requested URL and the page map's final URL, the output is the template's
/// fields plus `links`; otherwise it is `page` plus `links`.
fn interpret(
    response: &Value,
    templates: &SiteTemplates,
    requested: &str,
) -> Result<BTreeMap<String, Value>, ToolFailure> {
    let result = response.get("result").ok_or(ToolFailure::Internal)?;
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        return Err(ToolFailure::Internal);
    }
    let text = result
        .pointer("/content/0/text")
        .and_then(Value::as_str)
        .ok_or(ToolFailure::Internal)?;
    let map: Value = serde_json::from_str(text).map_err(|_| ToolFailure::Internal)?;
    if !map.is_object() {
        return Err(ToolFailure::Internal);
    }
    if map.get("error").and_then(Value::as_bool) == Some(true) {
        return Err(match map.get("code").and_then(Value::as_str) {
            Some("BLOCKED" | "NOT_HTML") => ToolFailure::BadInput,
            Some("FETCH_FAILED" | "TIMEOUT") => ToolFailure::Unavailable,
            _ => ToolFailure::Internal,
        });
    }

    let mut out = match templates
        .find(requested)
        .filter(|template| final_url_matches(template, &map))
    {
        Some(template) => template_output(template, &map)?,
        None => {
            let page = render_page(&map);
            if !is_valid_scalar_string(Scalar::Text, &page) {
                return Err(ToolFailure::Internal);
            }
            BTreeMap::from([("page".to_owned(), Value::String(page))])
        }
    };
    out.insert(
        "links".to_owned(),
        Value::Array(collect_links(&map).into_iter().map(Value::String).collect()),
    );
    Ok(out)
}

/// The page the child ended on is still covered by the template: same host and port, and under its paths. A
/// missing or odd final URL means no template.
fn final_url_matches(template: &SiteTemplate, map: &Value) -> bool {
    map.get("url")
        .and_then(Value::as_str)
        .is_some_and(|url| template.matches(url))
}

/// The template's fields, each text cleaned like `page` is. Texts that are empty after cleaning, or are a whole
/// `ref:` token, are dropped, and so are fields left with nothing.
fn template_output(
    template: &SiteTemplate,
    map: &Value,
) -> Result<BTreeMap<String, Value>, ToolFailure> {
    let mut out = BTreeMap::new();
    for (name, value) in template.apply(map) {
        let cleaned = match value {
            Value::String(text) => clean_field(&text).map(Value::String),
            Value::Array(items) => {
                let texts: Vec<Value> = items
                    .iter()
                    .filter_map(Value::as_str)
                    .filter_map(clean_field)
                    .take(MAX_ITEMS)
                    .map(Value::String)
                    .collect();
                (!texts.is_empty()).then_some(Value::Array(texts))
            }
            _ => None,
        };
        let Some(cleaned) = cleaned else { continue };
        let texts_ok = match &cleaned {
            Value::String(text) => is_valid_scalar_string(Scalar::Text, text),
            Value::Array(items) => items
                .iter()
                .filter_map(Value::as_str)
                .all(|text| is_valid_scalar_string(Scalar::Text, text)),
            _ => false,
        };
        if !texts_ok {
            return Err(ToolFailure::Internal);
        }
        out.insert(name, cleaned);
    }
    Ok(out)
}

/// One field text, cleaned; `None` when nothing is left. A text that is only a `ref:` token would be refused by
/// the Gate (it could forge a Gate ref) and sink the whole output, so it is dropped here.
fn clean_field(text: &str) -> Option<String> {
    let cleaned = clean_block(text);
    (!cleaned.is_empty() && cleaned.parse::<RefId>().is_err()).then_some(cleaned)
}

/// A string or number as text; anything else is nothing.
pub(crate) fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub(crate) fn field_text(object: &Value, key: &str) -> Option<String> {
    object.get(key).and_then(scalar_text)
}

/// Deterministic plain text from whatever keys the page map has. One item per line.
fn render_page(map: &Value) -> String {
    let mut lines: Vec<String> = Vec::new();

    if let Some(title) = field_text(map, "title") {
        lines.push(format!("Title: {title}"));
    }
    if let Some(description) = field_text(map, "description") {
        lines.push(description);
    }
    for heading in array(map, "headings") {
        if let Some(text) = field_text(heading, "text") {
            let level = heading
                .get("level")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                .clamp(1, 6);
            lines.push(format!(
                "{} {text}",
                "#".repeat(usize::try_from(level).unwrap_or(1))
            ));
        }
    }
    for block in array(map, "text_blocks") {
        lines.extend(field_text(block, "text"));
    }
    if let Some(article) = map.get("article") {
        render_article(article, &mut lines);
    }
    if let Some(product) = map.get("product") {
        render_product(product, &mut lines);
    }
    for item in map
        .pointer("/listing/items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let parts: Vec<String> = ["title", "snippet", "price"]
            .into_iter()
            .filter_map(|key| field_text(item, key))
            .collect();
        if !parts.is_empty() {
            lines.push(format!("- {}", parts.join(" | ")));
        }
    }
    for table in array(map, "tables") {
        lines.extend(table_rows(table));
    }

    clean_block(&lines.join("\n"))
}

/// A table as text lines: the header row, then each row, cells joined with " | ". Rows with no cells are skipped.
pub(crate) fn table_rows(table: &Value) -> Vec<String> {
    let rows = std::iter::once(table.get("headers")).chain(array(table, "rows").map(Some));
    let mut lines = Vec::new();
    for row in rows.flatten() {
        if let Some(cells) = row.as_array() {
            let cells: Vec<String> = cells.iter().filter_map(scalar_text).collect();
            if !cells.is_empty() {
                lines.push(cells.join(" | "));
            }
        }
    }
    lines
}

/// Elements of an array-valued key; empty when the key is missing or not an array.
pub(crate) fn array<'a>(value: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn render_article(article: &Value, lines: &mut Vec<String>) {
    lines.extend(field_text(article, "intro"));
    for section in array(article, "sections") {
        if let Some(text) = scalar_text(section) {
            lines.push(text);
            continue;
        }
        lines.extend(field_text(section, "heading").or_else(|| field_text(section, "title")));
        lines.extend(field_text(section, "text").or_else(|| field_text(section, "body")));
        for paragraph in array(section, "paragraphs") {
            lines.extend(scalar_text(paragraph).or_else(|| field_text(paragraph, "text")));
        }
    }
}

fn render_product(product: &Value, lines: &mut Vec<String>) {
    for (label, key) in [
        ("Product", "name"),
        ("Price", "price"),
        ("Rating", "rating"),
        ("Availability", "availability"),
    ] {
        if let Some(text) = field_text(product, key) {
            lines.push(format!("{label}: {text}"));
        }
    }
    match product.get("specs") {
        Some(Value::Object(specs)) => {
            for (name, value) in specs {
                if let Some(text) = scalar_text(value) {
                    lines.push(format!("{name}: {text}"));
                }
            }
        }
        Some(Value::Array(specs)) => {
            for spec in specs {
                match (field_text(spec, "name"), field_text(spec, "value")) {
                    (Some(name), Some(value)) => lines.push(format!("{name}: {value}")),
                    _ => lines.extend(scalar_text(spec)),
                }
            }
        }
        _ => {}
    }
}

/// Characters removed from page text: everything core's text validator rejects (controls other than newline and
/// tab, bidi controls, zero-width and other invisible format characters, the tag block), checked one character at
/// a time with that validator so the two can't drift apart, plus a few blank-looking fillers core allows but a page
/// could use to hide text. One stray soft hyphen on a real page then can't sink the whole output.
fn is_stripped(c: char) -> bool {
    if c == '\n' || c == '\t' {
        return false;
    }
    let mut buf = [0u8; 4];
    !is_clean_text(c.encode_utf8(&mut buf), false)
        || matches!(
            c,
            '\u{34f}' | '\u{115f}' | '\u{1160}' | '\u{17b4}' | '\u{17b5}' | '\u{180b}'
                ..='\u{180f}' | '\u{2800}' | '\u{3164}' | '\u{ffa0}'
        )
}

fn clean_text(s: &str) -> String {
    s.chars().filter(|c| !is_stripped(*c)).collect()
}

/// The cleaning every text that leaves the tool gets: invisible and control characters stripped, then tidied and
/// capped by [`finish_text`].
fn clean_block(text: &str) -> String {
    finish_text(&clean_text(text))
}

/// Trim trailing blanks, allow at most two blank lines in a row, cap the length.
fn finish_text(text: &str) -> String {
    let mut out = String::new();
    let mut blank_run = 0;
    for line in text.split('\n') {
        let line = line.trim_end();
        if line.is_empty() {
            blank_run += 1;
            if blank_run > 2 {
                continue;
            }
        } else {
            blank_run = 0;
        }
        out.push_str(line);
        out.push('\n');
    }
    let capped: String = out.trim().chars().take(MAX_PAGE_CHARS).collect();
    capped.trim_end().to_owned()
}

/// Links from content links, the article and listing items: valid URLs only, no repeats, capped.
fn collect_links(map: &Value) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut take = |candidate: Option<&str>| {
        if let Some(url) = candidate
            && found.len() < MAX_LINKS
            && is_valid_scalar_string(Scalar::Url, url)
            && !found.iter().any(|seen| seen == url)
        {
            found.push(url.to_owned());
        }
    };
    for item in map
        .pointer("/content_links/items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        take(item.get("url").and_then(Value::as_str));
    }
    for link in map
        .pointer("/article/links")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        take(
            link.as_str()
                .or_else(|| link.get("url").and_then(Value::as_str)),
        );
    }
    for item in map
        .pointer("/listing/items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        take(item.get("url").and_then(Value::as_str));
    }
    found
}
