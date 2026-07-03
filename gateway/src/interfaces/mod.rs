//! Application Interfaces & Workers subsystem.
//!
//! Owns the local-interface data plane: the [`manager`] control plane that
//! authorises and spawns endpoints, the per-endpoint [`uds`] and [`shm`]
//! implementations, their shared [`endpoint`] helpers (peer auth, TLS
//! dial/accept, relay), and the [`tproxy`] transparent-socket utilities.

pub mod endpoint;
pub mod manager;
pub mod shm;
pub mod tproxy;
pub mod uds;
