//! munix-gate: the only path from the agent to tools, credentials and the network.
//!
//! Plain code with no model inside (design spec section 3, "Gate sub-modules"). It validates each request
//! from the agent, traces where every destination value came from, applies the deterministic Stage-1 policy,
//! executes only signed decisions through the Tool Proxy, labels and filters what comes back, and writes
//! everything to the ledger.

pub mod facts;
pub mod gate;
pub mod ingest;
pub mod policy;
pub mod quarantine;
pub mod refs;
pub mod seal;
pub mod tool;
pub mod trace;
pub mod vault;
pub mod view;
