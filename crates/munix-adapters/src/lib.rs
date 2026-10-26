//! munix-adapters: model adapters behind one structured-output interface.
//!
//! Models only run in the Supervisor, the Readers and the demo Worker, and they reach them through this crate.
//! An adapter turns a [`ModelRequest`] (system prompt, user prompt, JSON Schema) into a JSON value. The enforcement
//! code never trusts what comes back: callers validate the value against their own types.

mod meta;
mod mock;
mod schema;

use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde_json::Value;

pub use meta::MetaAdapter;
pub use mock::MockAdapter;
pub use schema::sanitize_schema;

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

/// A parsed JSON reply and the (sanitized) id of the model that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelReply {
    pub value: Value,
    pub model: String,
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

/// Builds an adapter from a spec string: `meta:<model>` or `mock`.
pub fn from_spec(spec: &str) -> Result<Arc<dyn ModelAdapter>, AdapterError> {
    if spec == "mock" {
        return Ok(Arc::new(MockAdapter::new(Vec::new())));
    }
    if let Some(model) = spec.strip_prefix("meta:") {
        return Ok(Arc::new(MetaAdapter::from_env(model)?));
    }
    Err(AdapterError::Config(
        "unknown model spec (expected `meta:<model>` or `mock`)".to_string(),
    ))
}
