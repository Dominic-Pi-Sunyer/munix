//! The Tool Proxy's view of a tool: a synchronous call with resolved arguments.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::vault::Credential;

/// Why a tool call failed. Coarse codes only: a tool's own error text could carry attacker-chosen content
/// or echo a credential, so the Gate never accepts any.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolFailure {
    /// The service could not be reached or timed out.
    Unavailable,
    /// The service rejected the arguments.
    BadInput,
    /// The service rejected the credential.
    Unauthorized,
    /// Anything else.
    Internal,
}

/// A tool the Gate can execute.
///
/// `args` arrive with every ref already resolved to its real value. `credential` is `Some` exactly when the
/// tool's manifest names one. The output is validated against the manifest before anything reaches the agent.
pub trait Tool: Send + Sync {
    fn call(
        &self,
        args: &BTreeMap<String, Value>,
        credential: Option<&Credential>,
    ) -> Result<BTreeMap<String, Value>, ToolFailure>;
}

impl<F> Tool for F
where
    F: Fn(
            &BTreeMap<String, Value>,
            Option<&Credential>,
        ) -> Result<BTreeMap<String, Value>, ToolFailure>
        + Send
        + Sync,
{
    fn call(
        &self,
        args: &BTreeMap<String, Value>,
        credential: Option<&Credential>,
    ) -> Result<BTreeMap<String, Value>, ToolFailure> {
        self(args, credential)
    }
}
