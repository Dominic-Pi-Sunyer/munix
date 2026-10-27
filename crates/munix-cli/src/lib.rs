//! munix-cli: `munix run`, which starts the Gate, the model gateway and the sandboxed agent, and connects the
//! agent's MCP channel to the Gate; and `munix dashboard`, a read-only view of the ledger files in `runs/`.

pub mod bridge;
pub mod confirm;
pub mod dashboard;
pub mod front;
pub mod ledger;
pub mod run;
