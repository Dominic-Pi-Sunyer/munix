//! The one error type for the crate. Messages never echo attacker-chosen values.

/// Errors from validation, parsing and signature checks.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A value, manifest, plan or message broke a rule.
    #[error("invalid: {0}")]
    Invalid(String),
    /// A signature did not verify (wrong key, wrong purpose or a changed body).
    #[error("bad signature")]
    BadSignature,
    /// YAML could not be parsed.
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    /// JSON could not be produced or parsed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Result alias used across the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Shorthand for `Error::Invalid`.
pub fn invalid(msg: impl Into<String>) -> Error {
    Error::Invalid(msg.into())
}
