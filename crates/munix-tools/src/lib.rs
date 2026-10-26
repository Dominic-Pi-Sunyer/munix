//! Real tools behind the Gate's [`Tool`](munix_gate::tool::Tool) trait.
//!
//! - [`email::SmtpEmail`]: `email.send` over SMTP to a **loopback** sink (Mailpit in the demo). It refuses any
//!   non-loopback server, so a demo or test can never mail a real mailbox.
//! - [`webspeed::WebSpeedOpen`]: `web.open` through Web Speed OSS, an MCP server over stdio, kept running as one
//!   child process. A [`site::SiteTemplate`] lets it split a known site's page into fields the manifest labels by
//!   region.
//!
//! These run on the clean side, inside the Tool Proxy: they get resolved argument values and the Vault
//! credential, and their output is validated and labeled by the Gate before the agent sees any of it. Failures
//! are coarse [`ToolFailure`](munix_gate::tool::ToolFailure) codes only, so no remote text or credential can ride
//! out in an error.

pub mod email;
pub mod site;
pub mod webspeed;

use thiserror::Error;

/// A tool was configured wrongly. Raised at construction, before any task runs.
#[derive(Debug, Error, PartialEq)]
pub enum ToolConfigError {
    #[error("tool config: {0}")]
    Invalid(String),
}
