//! Application Protocols subsystem.
//!
//! Provides a trait-based provider architecture for application-level protocols
//! that frame datagrams over TLS byte streams.
//!
//! Built-in providers:
//! - **ALE** (UNISIG Subset-037/098): EuroRadio ALEPKT framing with AU1/AU2 handshake
//! - **Raw**: Simple length-prefix framing without handshake

pub mod ale_provider;
pub mod provider;
pub mod raw_provider;
