//! Generated gRPC client/server stubs for the SCG management API.
//!
//! The actual types are produced at build time from
//! `proto/scg_management.proto` by [`build.rs`].

/// Management API protobuf types and gRPC stubs (`scg.management.v1`).
pub mod management {
    /// Version 1 of the management API.
    pub mod v1 {
        tonic::include_proto!("scg.management.v1");
    }
}

pub use management::v1;
