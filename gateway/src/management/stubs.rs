//! Stub modules for unimplemented Management & Configuration components.
//!
//! These are placeholders matching the architecture diagram. Each section
//! marks where a future subsystem will be implemented.

// TODO: Identity & Access Manager (IAM)
// - Role-based access control for gateway management
// - Authentication for gRPC admin API
// - Service identity management

// TODO: PSK Registry
// - Pre-shared key storage and rotation
// - PSK identity mapping
// - Integration with TLS/DTLS engines for PSK cipher suites

// TODO: Crypto Policy & Algorithm Manager
// - Cipher suite selection and enforcement
// - Algorithm allowlists/denylists per rule
// - FIPS mode configuration
// - Key length and protocol version policies

// TODO: Network Namespace & Firewall Manager
// - iptables/nftables rule management (SCG_ENCRYPT, SCG_DECRYPT chains)
// - TPROXY routing policy setup (ip rule fwmark 1 lookup 100)
// - Network namespace creation for isolation
// - Automated setup_gateway.sh equivalent

// TODO: Certificate Revocation & OCSP
// - CRL download and caching
// - OCSP stapling support
// - Real-time certificate validity checking
// - Integration with cert_store for revocation events

// TODO: Storage Manager
// - Persistent storage for configuration state
// - Secure key material storage (potentially HSM-backed)
// - Audit log archival
