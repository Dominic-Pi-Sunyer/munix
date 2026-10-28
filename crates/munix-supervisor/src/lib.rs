//! munix-supervisor: Agent B. It plans the task before anything is read and reviews gray-zone requests from the
//! Gate's metadata view. Its model never sees attacker-chosen text (invariant 3), and it can never override a
//! deterministic deny (invariant 6): the Gate only asks it about requests Stage 1 already allowed in principle.

pub mod memory;
pub mod planner;
pub mod reviewer;
