#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::time::Duration;

use std::sync::Arc;

use munix_adapters::{
    AdapterError, MetaAdapter, Metered, MockAdapter, ModelAdapter, ModelReply, Pricing,
    ReasoningEffort, Usage,
};
use serde_json::{Value, json};
use support::{Canned, KEY, TestServer, adapter, request, split, verdict_schema};

fn call(server: &TestServer) -> Result<ModelReply, AdapterError> {
    adapter(server).0.complete_json(&request(verdict_schema()))
}

fn one(canned: Canned) -> Result<ModelReply, AdapterError> {
    call(&TestServer::start(vec![canned]))
}

#[test]
fn request_has_the_exact_shape_and_bearer_header() {
    let server = TestServer::start(vec![Canned::ok(
        &json!({"verdict": "approve", "reason": "fine"}),
    )]);
    let reply = call(&server).unwrap();
    assert_eq!(reply.value, json!({"verdict": "approve", "reason": "fine"}));
    assert_eq!(reply.model, "muse-spark-1.3");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let (head, body) = split(&requests[0]);
    assert!(
        head.starts_with("post /v1/chat/completions http/1.1"),
        "{head}"
    );
    assert!(
        head.contains(&format!(
            "authorization: bearer {}",
            KEY.to_ascii_lowercase()
        )),
        "{head}"
    );
    assert!(head.contains("content-type: application/json"), "{head}");
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        body,
        json!({
            "model": "muse-spark-1.3",
            "temperature": 0,
            "max_tokens": 256,
            "messages": [
                {"role": "system", "content": "You are the supervisor."},
                {"role": "user", "content": "Approve or deny."}
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "verdict",
                    "strict": true,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "verdict": {"type": "string", "enum": ["approve", "deny"]},
                            "reason": {"type": "string"}
                        },
                        "required": ["reason", "verdict"],
                        "additionalProperties": false
                    }
                }
            }
        })
    );
}

fn sent_body(server: &TestServer) -> Value {
    let requests = server.requests();
    serde_json::from_str(&split(&requests[0]).1).unwrap()
}

#[test]
fn no_effort_means_no_reasoning_effort_field() {
    let server = TestServer::start(vec![Canned::ok(&json!({"verdict": "approve"}))]);
    call(&server).unwrap();
    assert!(sent_body(&server).get("reasoning_effort").is_none());
}

#[test]
fn effort_is_sent_as_its_wire_name() {
    for effort in [
        ReasoningEffort::Minimal,
        ReasoningEffort::Low,
        ReasoningEffort::Medium,
        ReasoningEffort::High,
        ReasoningEffort::Xhigh,
        ReasoningEffort::Max,
    ] {
        let server = TestServer::start(vec![Canned::ok(&json!({"verdict": "approve"}))]);
        let a = adapter(&server).0.with_reasoning_effort(effort);
        a.complete_json(&request(verdict_schema())).unwrap();
        let body = sent_body(&server);
        assert_eq!(body["reasoning_effort"], effort.as_str());
        // Nothing else about the request changes.
        assert_eq!(body["model"], "muse-spark-1.3");
        assert_eq!(body["temperature"], 0);
        assert_eq!(body["max_tokens"], 256);
    }
}

fn with_usage(usage: Value) -> Canned {
    Canned::json(&json!({
        "model": "muse-spark-1.3",
        "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}],
        "usage": usage
    }))
}

#[test]
fn usage_is_read_from_the_response() {
    let reply = one(with_usage(json!({
        "prompt_tokens": 120,
        "completion_tokens": 80,
        "total_tokens": 200,
        "completion_tokens_details": {"reasoning_tokens": 50}
    })))
    .unwrap();
    assert_eq!(
        reply.usage,
        Usage {
            prompt_tokens: 120,
            completion_tokens: 80,
            reasoning_tokens: 50
        }
    );
}

#[test]
fn missing_or_malformed_usage_fields_are_zero() {
    assert_eq!(
        one(Canned::reply("{}", "stop")).unwrap().usage,
        Usage::default()
    );
    assert_eq!(
        one(with_usage(json!({"prompt_tokens": 7}))).unwrap().usage,
        Usage {
            prompt_tokens: 7,
            ..Usage::default()
        }
    );
    assert_eq!(
        one(with_usage(
            json!({"completion_tokens": 9, "completion_tokens_details": {}})
        ))
        .unwrap()
        .usage,
        Usage {
            completion_tokens: 9,
            ..Usage::default()
        }
    );
    let junk = json!({
        "prompt_tokens": "many", "completion_tokens": -3,
        "completion_tokens_details": {"reasoning_tokens": null}
    });
    assert_eq!(one(with_usage(junk)).unwrap().usage, Usage::default());
    assert_eq!(
        one(with_usage(json!("nope"))).unwrap().usage,
        Usage::default()
    );
}

#[test]
fn metered_totals_calls_and_usage_across_clones_and_errors() {
    let server = TestServer::start(vec![
        with_usage(json!({
            "prompt_tokens": 100, "completion_tokens": 40,
            "completion_tokens_details": {"reasoning_tokens": 30}
        })),
        Canned::status(400),
        with_usage(json!({
            "prompt_tokens": 10, "completion_tokens": 5,
            "completion_tokens_details": {"reasoning_tokens": 1}
        })),
    ]);
    let metered = Metered::new(Arc::new(adapter(&server).0));
    assert_eq!(metered.total(), (0, Usage::default()));
    assert_eq!(metered.name(), "meta:muse-spark-1.3");
    let handle = metered.clone();

    let req = request(verdict_schema());
    metered.complete_json(&req).unwrap();
    assert!(handle.complete_json(&req).is_err());
    metered.complete_json(&req).unwrap();

    let expected = (
        3,
        Usage {
            prompt_tokens: 110,
            completion_tokens: 45,
            reasoning_tokens: 31,
        },
    );
    assert_eq!(metered.total(), expected);
    assert_eq!(handle.total(), expected);
    let cost = Pricing::default().cost_usd(&expected.1);
    assert!((cost - (110.0 * 1.25 + 45.0 * 4.25) / 1e6).abs() < 1e-12);
}

#[test]
fn metered_mock_replies_have_zero_usage() {
    let mock = MockAdapter::new(vec![Ok(json!({"a": 1}))]);
    let metered = Metered::new(Arc::new(mock));
    let reply = metered.complete_json(&request(verdict_schema())).unwrap();
    assert_eq!(reply.usage, Usage::default());
    assert_eq!(metered.total(), (1, Usage::default()));
}

#[test]
fn the_key_never_shows_in_name_debug_or_errors() {
    let server = TestServer::start(vec![
        Canned::status(401),
        Canned::status(503),
        Canned::status(503),
        Canned::status(503),
    ]);
    let (a, _) = adapter(&server);
    assert_eq!(a.name(), "meta:muse-spark-1.3");
    assert!(!a.name().contains(KEY));
    let debug = format!("{a:?}");
    assert!(!debug.contains(KEY), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");

    let messages: Vec<String> = (0..2)
        .map(|_| {
            a.complete_json(&request(verdict_schema()))
                .unwrap_err()
                .to_string()
        })
        .collect();
    for m in messages {
        assert!(
            !m.contains(KEY) && !m.contains("body-must-not-leak") && !m.contains("127.0.0.1"),
            "{m}"
        );
    }
    let bad = MetaAdapter::new("http://example.com/v1", "m", KEY).unwrap_err();
    assert!(!bad.to_string().contains(KEY) && !bad.to_string().contains("example.com"));
}

#[test]
fn transport_policy_is_enforced_by_the_constructor() {
    assert!(MetaAdapter::new("https://api.meta.ai/v1", "m", KEY).is_ok());
    assert!(MetaAdapter::new("http://127.0.0.1:9/v1", "m", KEY).is_ok());
    assert!(MetaAdapter::new("http://[::1]:9/v1", "m", KEY).is_ok());
    for url in [
        "http://api.meta.ai/v1",
        "https://user:pw@api.meta.ai/v1",
        "https://api.meta.ai/v1?a=b",
        "https://api.meta.ai/#x",
    ] {
        assert!(
            matches!(
                MetaAdapter::new(url, "m", KEY),
                Err(AdapterError::Config(_))
            ),
            "{url}"
        );
    }
}

#[test]
fn credentials_errors_are_not_retried() {
    for status in [401u16, 403] {
        let server = TestServer::start(vec![Canned::status(status), Canned::ok(&json!({}))]);
        let (a, sleeps) = adapter(&server);
        let err = a.complete_json(&request(verdict_schema())).unwrap_err();
        assert_eq!(
            err,
            AdapterError::Config(format!(
                "the server rejected the credentials (HTTP {status})"
            ))
        );
        assert_eq!(server.requests().len(), 1);
        assert!(sleeps.lock().unwrap().is_empty());
    }
}

#[test]
fn retries_429_and_503_honoring_retry_after_then_succeeds() {
    let server = TestServer::start(vec![
        Canned::status(429).header("Retry-After", "5"),
        Canned::status(503),
        Canned::ok(&json!({"verdict": "deny", "reason": "no"})),
    ]);
    let (a, sleeps) = adapter(&server);
    let reply = a.complete_json(&request(verdict_schema())).unwrap();
    assert_eq!(reply.value["verdict"], "deny");
    assert_eq!(server.requests().len(), 3);
    assert_eq!(
        *sleeps.lock().unwrap(),
        vec![Duration::from_secs(5), Duration::from_secs(2)]
    );
}

#[test]
fn retry_after_is_capped_at_60_seconds() {
    let server = TestServer::start(vec![
        Canned::status(502).header("Retry-After", "3600"),
        Canned::ok(&json!({"verdict": "approve"})),
    ]);
    let (a, sleeps) = adapter(&server);
    a.complete_json(&request(verdict_schema())).unwrap();
    assert_eq!(*sleeps.lock().unwrap(), vec![Duration::from_secs(60)]);
}

#[test]
fn gives_up_after_three_attempts_with_exponential_backoff() {
    for status in [429u16, 500, 502, 503, 504] {
        let server = TestServer::start(vec![
            Canned::status(status),
            Canned::status(status),
            Canned::status(status),
            Canned::ok(&json!({})),
        ]);
        let (a, sleeps) = adapter(&server);
        let err = a.complete_json(&request(verdict_schema())).unwrap_err();
        assert_eq!(err, AdapterError::Unavailable(format!("HTTP {status}")));
        assert_eq!(server.requests().len(), 3);
        assert_eq!(
            *sleeps.lock().unwrap(),
            vec![Duration::from_secs(1), Duration::from_secs(2)]
        );
    }
}

#[test]
fn connection_errors_are_retried_then_reported() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let sleeps = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = sleeps.clone();
    let a = MetaAdapter::new(&format!("http://127.0.0.1:{port}/v1"), "m", KEY)
        .unwrap()
        .with_sleeper(move |d| log.lock().unwrap().push(d));
    let err = a.complete_json(&request(verdict_schema())).unwrap_err();
    assert_eq!(
        err,
        AdapterError::Unavailable("could not reach the model server".to_string())
    );
    assert_eq!(sleeps.lock().unwrap().len(), 2);
}

#[test]
fn other_statuses_fail_at_once_and_redirects_are_not_followed() {
    let server = TestServer::start(vec![Canned::status(400), Canned::ok(&json!({}))]);
    assert_eq!(
        call(&server).unwrap_err(),
        AdapterError::Unavailable("HTTP 400".to_string())
    );
    assert_eq!(server.requests().len(), 1);

    let target = TestServer::start(vec![Canned::ok(&json!({"verdict": "approve"}))]);
    let redirect = TestServer::start(vec![Canned::status(302).header(
        "Location",
        &format!("{}/chat/completions", target.base_url()),
    )]);
    assert_eq!(
        call(&redirect).unwrap_err(),
        AdapterError::Unavailable("HTTP 302".to_string())
    );
    assert!(target.requests().is_empty());
}

#[test]
fn a_slow_server_times_out_without_retrying() {
    let server = TestServer::start(vec![
        Canned::ok(&json!({})).delayed(Duration::from_millis(1500)),
    ]);
    let (a, sleeps) = adapter(&server);
    let a = a.with_timeout(Duration::from_millis(200));
    assert_eq!(
        a.complete_json(&request(verdict_schema())).unwrap_err(),
        AdapterError::Timeout
    );
    assert!(sleeps.lock().unwrap().is_empty());
}

#[test]
fn an_oversized_body_is_rejected() {
    let mut big = Canned::status(200);
    big.body = vec![b' '; 8 * 1024 * 1024 + 1];
    let err = one(big).unwrap_err();
    assert_eq!(
        err,
        AdapterError::BadOutput("the response was too large".to_string())
    );
}

#[test]
fn finish_reasons_map_to_errors() {
    assert_eq!(
        one(Canned::reply("{\"verdict\":\"approve\"}", "stop"))
            .unwrap()
            .value["verdict"],
        "approve"
    );
    assert_eq!(
        one(Canned::reply("{\"verd", "length")).unwrap_err(),
        AdapterError::Truncated
    );
    assert_eq!(
        one(Canned::reply("{}", "content_filter")).unwrap_err(),
        AdapterError::Refused
    );
    assert!(matches!(
        one(Canned::reply("{}", "tool_calls")).unwrap_err(),
        AdapterError::BadOutput(_)
    ));
    assert!(matches!(
        one(Canned::reply("{}", "function_call")).unwrap_err(),
        AdapterError::BadOutput(_)
    ));
    let missing = Canned::json(&json!({"choices": [{"message": {"content": "{}"}}]}));
    assert!(matches!(
        one(missing).unwrap_err(),
        AdapterError::BadOutput(_)
    ));
    let none = Canned::json(&json!({"choices": []}));
    assert!(matches!(one(none).unwrap_err(), AdapterError::BadOutput(_)));
    let null_content = Canned::json(
        &json!({"choices": [{"finish_reason": "stop", "message": {"content": null}}]}),
    );
    assert!(matches!(
        one(null_content).unwrap_err(),
        AdapterError::BadOutput(_)
    ));
}

#[test]
fn a_refusal_field_means_refused() {
    let refused = Canned::json(&json!({
        "choices": [{"finish_reason": "stop", "message": {"content": "{}", "refusal": "I can't help with that."}}]
    }));
    assert_eq!(one(refused).unwrap_err(), AdapterError::Refused);
    let empty_ok = Canned::json(&json!({
        "choices": [{"finish_reason": "stop", "message": {"content": "{\"a\":1}", "refusal": null}}]
    }));
    assert_eq!(one(empty_ok).unwrap().value, json!({"a": 1}));
    let blank_ok = Canned::json(&json!({
        "choices": [{"finish_reason": "stop", "message": {"content": "{\"a\":1}", "refusal": ""}}]
    }));
    assert_eq!(one(blank_ok).unwrap().value, json!({"a": 1}));
}

#[test]
fn think_prefix_and_code_fence_are_tolerated() {
    let v = json!({"verdict": "approve", "reason": "ok"});
    for content in [
        format!("<think>let me reason {{\"verdict\":\"deny\"}}</think>\n{v}"),
        format!("```json\n{v}\n```"),
        format!("<think>hm</think>\n```json\n{v}\n```\n"),
        format!("  \n{v}\n"),
    ] {
        assert_eq!(
            one(Canned::reply(&content, "stop")).unwrap().value,
            v,
            "{content}"
        );
    }
}

#[test]
fn reasoning_fields_are_ignored() {
    let body = Canned::json(&json!({
        "model": "muse-spark-1.3",
        "choices": [{
            "finish_reason": "stop",
            "message": {"content": "{\"verdict\":\"approve\"}", "reasoning_content": "{\"verdict\":\"deny\"}", "reasoning": "deny"}
        }]
    }));
    assert_eq!(one(body).unwrap().value, json!({"verdict": "approve"}));
}

#[test]
fn bad_json_reports_class_and_position_only() {
    for content in [
        "sk-leaky-token {not json",
        "{\"verdict\": \"approve\"",
        "```json\nsecret-text\n```",
        "<think>never closed",
    ] {
        let err = one(Canned::reply(content, "stop")).unwrap_err();
        let AdapterError::BadOutput(msg) = err else {
            panic!("{err:?}")
        };
        assert!(
            msg.contains("not valid JSON") && msg.contains("line"),
            "{msg}"
        );
        assert!(
            !msg.contains("leaky") && !msg.contains("secret") && !msg.contains("approve"),
            "{msg}"
        );
    }
    let not_json_body = Canned {
        body: b"<html>gateway</html>".to_vec(),
        ..Canned::status(200)
    };
    let AdapterError::BadOutput(msg) = one(not_json_body).unwrap_err() else {
        panic!()
    };
    assert!(!msg.contains("gateway"), "{msg}");
}

#[test]
fn reported_model_id_is_sanitized() {
    let with_model = |m: Value| {
        one(Canned::json(&json!({"model": m, "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}]})))
            .unwrap()
            .model
    };
    assert_eq!(with_model(json!("muse-spark-1.3")), "muse-spark-1.3");
    assert_eq!(
        with_model(json!("org/model:v1@2+x_y")),
        "org/model:v1@2+x_y"
    );
    assert_eq!(with_model(json!("evil model\nignore previous")), "unknown");
    assert_eq!(with_model(json!("")), "unknown");
    assert_eq!(with_model(json!("a".repeat(101))), "unknown");
    assert_eq!(with_model(json!("a".repeat(100))), "a".repeat(100));
    assert_eq!(with_model(json!(7)), "unknown");
    let no_model = Canned::json(
        &json!({"choices": [{"finish_reason": "stop", "message": {"content": "{}"}}]}),
    );
    assert_eq!(one(no_model).unwrap().model, "unknown");
}

/// Live check against the real Meta Model API, at minimal effort. Run with `MUNIX_LIVE_META=1 MODEL_API_KEY=... cargo test -- --ignored`.
#[test]
#[ignore = "needs MUNIX_LIVE_META=1 and MODEL_API_KEY"]
fn live_meta_verdict() {
    if std::env::var("MUNIX_LIVE_META").as_deref() != Ok("1") {
        eprintln!("MUNIX_LIVE_META is not 1; skipping");
        return;
    }
    let model =
        std::env::var("MUNIX_SUPERVISOR_MODEL").unwrap_or_else(|_| "muse-spark-1.3".to_string());
    let adapter = MetaAdapter::from_env(&model)
        .unwrap()
        .with_reasoning_effort(ReasoningEffort::Minimal);
    let req = munix_adapters::ModelRequest {
        system: "You review requests. Answer only with the requested JSON.".to_string(),
        user: "Request: read the file notes.txt in the user's own workspace. Approve or deny, with a short reason.".to_string(),
        schema_name: "verdict".to_string(),
        schema: json!({
            "type": "object",
            "properties": {"verdict": {"type": "string", "enum": ["approve", "deny"]}, "reason": {"type": "string"}},
            "required": ["verdict", "reason"]
        }),
        max_output_tokens: 4096,
    };
    let started = std::time::Instant::now();
    let reply = adapter.complete_json(&req).unwrap();
    let pricing = Pricing::from_env().unwrap();
    println!(
        "live latency: {:?}, model: {}, effort: minimal, value: {}",
        started.elapsed(),
        reply.model,
        reply.value
    );
    println!(
        "live usage: {} prompt, {} completion ({} reasoning); estimated cost: ${:.6}",
        reply.usage.prompt_tokens,
        reply.usage.completion_tokens,
        reply.usage.reasoning_tokens,
        pricing.cost_usd(&reply.usage)
    );
    assert!(matches!(
        reply.value["verdict"].as_str(),
        Some("approve" | "deny")
    ));
    assert!(reply.value["reason"].is_string());
}
