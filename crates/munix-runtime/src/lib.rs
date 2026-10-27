//! munix-runtime: Munix runs the agent, not the other way round (invariant 9).
//!
//! The agent runs in a container on an internal Docker network with no route out. Its only ways out are the MCP
//! channel on its stdio (owned by the Gate) and the model gateway, reached through a relay container that forwards
//! one port to the host. The gateway adds the model API key, so the agent never holds one.

pub mod gateway;
pub mod mcp;
pub mod sandbox;
pub mod watchdog;
