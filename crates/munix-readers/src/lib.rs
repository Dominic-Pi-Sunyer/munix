//! munix-readers: Readers (design spec 8). A Reader is a fresh model call with no tools. Its context holds only
//! the risky content, a fixed prompt and an output schema, and it may answer only with small typed values (bools,
//! enums from fixed lists, bounded numbers). No string ever comes back, so nothing an attacker wrote can reach the
//! agent through it. Its outputs stay under the 64-bit budget, so the Gate does not lower the agent's context trust
//! for them, while their labels keep the source's low trust for argument checks.
//!
//! A Reader that flags instructions names the field `flagged_instructions`, or `<item>_flags` for a per-item list:
//! the agent's tool output then carries Munix's note on what a flag means (`munix-cli`'s `front::FLAG_NOTE`).

pub mod banking;
pub mod reviews;
