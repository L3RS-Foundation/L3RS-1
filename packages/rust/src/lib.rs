#![allow(dead_code, unused_imports, clippy::module_name_repetitions)]
//! l3rs1 — L3RS-1 Reference Implementation — Rust
//! CROSSCHAIN conformance class — all invariants I₁–I₁₁

pub mod crypto;
pub mod modules;
pub mod types;

pub use crypto::*;
pub use modules::*;
pub use types::*;

pub const SDK_VERSION: &str = "1.0.1";
pub const STANDARD_VERSION: &str = "L3RS-1.0.0";
pub const CONFORMANCE_CLASS: &str = "CROSSCHAIN";

#[derive(Debug, thiserror::Error)]
pub enum L3rsError {
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}
