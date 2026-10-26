#![allow(clippy::unwrap_used, clippy::expect_used)]

use munix_adapters::{
    AdapterError, MockAdapter, ModelAdapter, ModelRequest, complete_typed, from_spec,
};
use serde::Deserialize;
use serde_json::json;

fn req(user: &str) -> ModelRequest {
    ModelRequest {
        system: "sys".to_string(),
        user: user.to_string(),
        schema_name: "v".to_string(),
        schema: json!({"type": "object"}),
        max_output_tokens: 64,
    }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Verdict {
    verdict: String,
}

#[test]
fn mock_returns_scripted_replies_in_order_and_records_requests() {
    let mock = MockAdapter::new(vec![
        Ok(json!({"n": 1})),
        Err(AdapterError::Refused),
        Ok(json!({"n": 3})),
    ]);
    assert_eq!(mock.name(), "mock");
    assert_eq!(
        mock.complete_json(&req("one")).unwrap().value,
        json!({"n": 1})
    );
    assert_eq!(
        mock.complete_json(&req("two")).unwrap_err(),
        AdapterError::Refused
    );
    assert_eq!(
        mock.complete_json(&req("three")).unwrap().value,
        json!({"n": 3})
    );
    assert!(matches!(
        mock.complete_json(&req("four")),
        Err(AdapterError::Unavailable(_))
    ));
    let seen = mock.seen();
    assert_eq!(
        seen.iter().map(|r| r.user.as_str()).collect::<Vec<_>>(),
        ["one", "two", "three", "four"]
    );
    assert_eq!(seen[0], req("one"));
}

#[test]
fn complete_typed_deserializes_and_passes_errors_through() {
    let mock = MockAdapter::new(vec![
        Ok(json!({"verdict": "approve"})),
        Err(AdapterError::Timeout),
    ]);
    assert_eq!(
        complete_typed::<Verdict>(&mock, &req("a")).unwrap(),
        Verdict {
            verdict: "approve".to_string()
        }
    );
    assert_eq!(
        complete_typed::<Verdict>(&mock, &req("b")).unwrap_err(),
        AdapterError::Timeout
    );
}

#[test]
fn complete_typed_shape_mismatch_echoes_nothing() {
    let mock = MockAdapter::new(vec![
        Ok(json!({"verdict": "approve", "extra": "TOP-SECRET-VALUE"})),
        Ok(json!({"verdict": 7})),
    ]);
    for _ in 0..2 {
        let AdapterError::BadOutput(msg) = complete_typed::<Verdict>(&mock, &req("a")).unwrap_err()
        else {
            panic!()
        };
        assert!(
            !msg.contains("TOP-SECRET")
                && !msg.contains("extra")
                && !msg.contains("approve")
                && !msg.contains('7'),
            "{msg}"
        );
    }
}

#[test]
fn from_spec_accepts_mock_and_rejects_everything_else() {
    assert_eq!(from_spec("mock").unwrap().name(), "mock");
    for spec in [
        "",
        "meta:",
        "meta",
        "openai:gpt-4",
        "MOCK",
        "mock:x",
        "anthropic:claude",
        "meta:bad model",
    ] {
        assert!(
            matches!(from_spec(spec), Err(AdapterError::Config(_))),
            "{spec:?}"
        );
    }
    let err = from_spec("openai:SECRETNAME").err().unwrap().to_string();
    assert!(!err.contains("SECRETNAME"));
}
