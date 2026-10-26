//! munix-adapters: model adapters behind one structured-output interface.
//!
//! Models only run in the Supervisor, the Readers and the demo Worker, and they reach them through this crate.
//! An adapter turns a [`ModelRequest`] (system prompt, user prompt, JSON Schema) into a JSON value. The enforcement
//! code never trusts what comes back: callers validate the value against their own types.

mod effort;
mod meta;
mod mock;
mod schema;
mod usage;

use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde_json::Value;

pub use effort::{ReasoningEffort, Role, effort_for};
pub use meta::MetaAdapter;
pub use mock::MockAdapter;
pub use schema::sanitize_schema;
pub use usage::{Metered, Pricing, Usage};

/// One structured-output call.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelRequest {
    pub system: String,
    pub user: String,
    /// Short identifier for the schema (letters, digits, `_`, `-`).
    pub schema_name: String,
    pub schema: Value,
    pub max_output_tokens: u32,
}

/// A parsed JSON reply, the (sanitized) id of the model that produced it, and the tokens it used.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelReply {
    pub value: Value,
    pub model: String,
    /// Zero for adapters that do not meter (the mock).
    pub usage: Usage,
}

/// Why a call failed. Messages never contain keys, URLs or response bodies.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum AdapterError {
    #[error("adapter configuration error: {0}")]
    Config(String),
    #[error("model unavailable: {0}")]
    Unavailable(String),
    #[error("model call timed out")]
    Timeout,
    #[error("the model refused to answer")]
    Refused,
    #[error("the model's answer was cut off")]
    Truncated,
    #[error("unusable model output: {0}")]
    BadOutput(String),
}

pub trait ModelAdapter: Send + Sync {
    /// Stable label for logs, such as `meta:muse-spark-1.3`. Never contains secrets.
    fn name(&self) -> String;

    fn complete_json(&self, req: &ModelRequest) -> Result<ModelReply, AdapterError>;
}

/// Calls the adapter and deserializes the reply. A shape mismatch is `BadOutput` and echoes nothing from the reply.
pub fn complete_typed<T: DeserializeOwned>(
    adapter: &dyn ModelAdapter,
    req: &ModelRequest,
) -> Result<T, AdapterError> {
    let reply = adapter.complete_json(req)?;
    serde_json::from_value(reply.value).map_err(|_| {
        AdapterError::BadOutput("the reply did not match the expected shape".to_string())
    })
}

/// Builds an adapter from a spec string: `meta:<model>`, `meta:<model>@<effort>` or `mock`.
///
/// A suffix after the last `@` must be a reasoning effort (`minimal`, `low`, `medium`, `high`, `xhigh`, `max`);
/// anything else is a config error. Without a suffix the adapter sends no `reasoning_effort` at all.
pub fn from_spec(spec: &str) -> Result<Arc<dyn ModelAdapter>, AdapterError> {
    build_from_spec(spec, None)
}

/// Like [`from_spec`], but a `meta:` spec without an `@<effort>` suffix gets the effort configured for `role`
/// (see [`effort_for`]).
pub fn from_spec_for(spec: &str, role: Role) -> Result<Arc<dyn ModelAdapter>, AdapterError> {
    build_from_spec(spec, Some(role))
}

fn build_from_spec(spec: &str, role: Option<Role>) -> Result<Arc<dyn ModelAdapter>, AdapterError> {
    if spec == "mock" {
        return Ok(Arc::new(MockAdapter::new(Vec::new())));
    }
    if let Some(rest) = spec.strip_prefix("meta:") {
        let (model, suffix) = split_effort_suffix(rest)?;
        let adapter = MetaAdapter::from_env(model)?;
        let effort = match (suffix, role) {
            (Some(effort), _) => Some(effort),
            (None, Some(role)) => Some(effort_for(role)?),
            (None, None) => None,
        };
        return Ok(Arc::new(match effort {
            Some(effort) => adapter.with_reasoning_effort(effort),
            None => adapter,
        }));
    }
    Err(AdapterError::Config(
        "unknown model spec (expected `meta:<model>` or `mock`)".to_string(),
    ))
}

/// Splits `<model>[@<effort>]`. The suffix, when there is an `@`, must be a valid effort.
fn split_effort_suffix(rest: &str) -> Result<(&str, Option<ReasoningEffort>), AdapterError> {
    match rest.rsplit_once('@') {
        Some((model, effort)) => Ok((model, Some(effort.parse()?))),
        None => Ok((rest, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effort_suffix_is_split_off_the_last_at_sign() {
        assert_eq!(
            split_effort_suffix("muse-spark-1.3").unwrap(),
            ("muse-spark-1.3", None)
        );
        assert_eq!(
            split_effort_suffix("muse-spark-1.3@minimal").unwrap(),
            ("muse-spark-1.3", Some(ReasoningEffort::Minimal))
        );
        assert_eq!(
            split_effort_suffix("org/m@2@max").unwrap(),
            ("org/m@2", Some(ReasoningEffort::Max))
        );
    }

    #[test]
    fn a_bad_or_empty_suffix_is_a_config_error() {
        for rest in ["m@", "m@fast", "m@2", "m@low@"] {
            assert!(
                matches!(split_effort_suffix(rest), Err(AdapterError::Config(_))),
                "{rest}"
            );
            let spec = format!("meta:{rest}");
            assert!(
                matches!(from_spec(&spec), Err(AdapterError::Config(_))),
                "{spec}"
            );
            assert!(
                matches!(
                    from_spec_for(&spec, Role::Planner),
                    Err(AdapterError::Config(_))
                ),
                "{spec}"
            );
        }
    }

    #[test]
    fn mock_ignores_effort_and_role() {
        assert_eq!(
            from_spec_for("mock", Role::Reviewer).unwrap().name(),
            "mock"
        );
    }
}
