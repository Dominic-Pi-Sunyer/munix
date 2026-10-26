//! munix-core: shared wire types, validators and signing. Every other crate depends on it.
//!
//! Nothing in this crate calls a model. Everything here is plain, deterministic code.

pub mod context;
pub mod crypto;
pub mod decision;
pub mod error;
pub mod ids;
pub mod label;
pub mod manifest;
pub mod plan;
pub mod prompt;
pub mod request;
pub mod validate;

pub use error::{Error, Result};
