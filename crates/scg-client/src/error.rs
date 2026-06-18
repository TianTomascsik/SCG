//! Error type shared by the Rust API and the C ABI.

use std::fmt;

/// Errors returned by the client library.
#[derive(Debug)]
pub enum ScgError {
    /// A management gRPC call failed (transport or status error).
    Management(String),
    /// The data-plane endpoint was closed by the gateway (clean EOF).
    Closed,
    /// A frame exceeded the negotiated maximum size.
    FrameTooLarge,
    /// The gateway's shared-memory offer was malformed or unsupported.
    BadOffer(String),
    /// An underlying OS/I-O call failed.
    Io(std::io::Error),
}

impl fmt::Display for ScgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScgError::Management(m) => write!(f, "management call failed: {m}"),
            ScgError::Closed => write!(f, "endpoint closed by gateway"),
            ScgError::FrameTooLarge => write!(f, "frame exceeds maximum size"),
            ScgError::BadOffer(m) => write!(f, "invalid shared-memory offer: {m}"),
            ScgError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for ScgError {}

impl From<std::io::Error> for ScgError {
    fn from(e: std::io::Error) -> Self {
        ScgError::Io(e)
    }
}

impl From<tonic::Status> for ScgError {
    fn from(s: tonic::Status) -> Self {
        ScgError::Management(format!("{}: {}", s.code(), s.message()))
    }
}

impl From<tonic::transport::Error> for ScgError {
    fn from(e: tonic::transport::Error) -> Self {
        ScgError::Management(e.to_string())
    }
}

/// Convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, ScgError>;
