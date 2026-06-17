//! Application Protocols subsystem.
//!
//! Provides a trait-based provider architecture for application-level protocols
//! that frame datagrams over TLS byte streams.
//!
//! Built-in providers:
//! - **ALE** (UNISIG Subset-037/098): EuroRadio ALEPKT framing with AU1/AU2 handshake
//! - **Raw**: Simple length-prefix framing without handshake

#[allow(dead_code)]
pub mod ale_provider;
#[allow(dead_code)]
pub mod provider;
#[allow(dead_code)]
pub mod raw_provider;
