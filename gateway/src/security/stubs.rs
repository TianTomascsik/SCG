//! Stub modules for unimplemented Security Enforcer components.

// TODO: IPSec Engine (IKEv2 + XFRM)
// - IKEv2 key exchange (initiator and responder)
// - Linux XFRM policy and state management via netlink
// - SA (Security Association) lifecycle
// - Integration with cert_store for IKE authentication
// - ESP/AH transform configuration

// WireGuard is implemented as a kernel-offload crypto provider — see
// `security::wireguard_engine` and `security::providers::wireguard_provider`.

// TODO: GDOI (Group Domain of Interpretation)
// - Group key management protocol
// - Key server and group member roles
// - Rekey and group SA distribution
// - Integration with IPSec for group SAs
