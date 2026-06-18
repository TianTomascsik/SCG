//! Application Interfaces & Workers subsystem.
//!
//! Network listeners (TPROXY and non-TPROXY), sender workers, and I/O adapters.

pub mod endpoint;
pub mod manager;
pub mod shm;
pub mod stubs;
pub mod tproxy;
pub mod uds;
