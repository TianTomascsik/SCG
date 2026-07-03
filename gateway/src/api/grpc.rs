//! gRPC management server.
//!
//! Runs on a dedicated thread with its own tokio runtime, completely off the
//! synchronous data path. The default transport is gRPC over a Unix-domain
//! socket so the gateway can read `SO_PEERCRED` and authenticate the caller's
//! uid/gid/pid; an optional TCP bind is available for remote admin but cannot
//! create endpoints (no peer credentials).

// `tonic::Status` is a large error type (~per clippy's 128-byte threshold), but
// the generated `ManagementApi` service trait fixes every method signature as
// `Result<_, Status>` — the error cannot be boxed for trait methods. Allow the
// lint for this module rather than fighting the framework's required signatures.
#![allow(clippy::result_large_err)]

use crate::interfaces::manager::{CallerCred, InterfaceManager};
use crate::management::config::{ApiConfig, Direction, TrafficClass};

use scg_proto::v1::management_api_server::{ManagementApi, ManagementApiServer};
use scg_proto::v1::{
    CloseEndpointRequest, CloseEndpointResponse, CreateEndpointRequest, HealthRequest,
    HealthResponse, ListRulesRequest, ListRulesResponse, ShmEndpointResponse, UdsEndpointResponse,
};

use log::{error, info, warn};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use tonic::transport::server::UdsConnectInfo;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

// ── HTTP/2 resource limits for the management server (CP-01 / DoS-09) ──────────
// Conservative bounds so an unauthenticated client on the optional TCP bind
// cannot exhaust the (2-worker) runtime via HTTP/2 stream/frame/keepalive/reset
// floods before `caller_cred` ever runs. Applied to both binds — the same limits
// contain a buggy or hostile *authorised* UDS client, and a uniform posture is
// simpler than a TCP-only branch. Deliberately not config-tunable (YAGNI): the
// management surface issues small serial unary RPCs, so these ceilings never bind
// on legitimate traffic.
const MGMT_MAX_CONCURRENT_STREAMS: u32 = 16;
const MGMT_CONCURRENCY_PER_CONN: usize = 16;
const MGMT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MGMT_MAX_FRAME_SIZE: u32 = 16 * 1024;
const MGMT_MAX_HEADER_LIST_SIZE: u32 = 16 * 1024;
const MGMT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const MGMT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const MGMT_MAX_PENDING_RESET_STREAMS: usize = 32;

/// A `Server` builder pre-configured with the management-API HTTP/2 limits
/// (CP-01). All bind sites go through this so no listener is created unbounded.
fn hardened_server() -> Server {
    Server::builder()
        .concurrency_limit_per_connection(MGMT_CONCURRENCY_PER_CONN)
        .max_concurrent_streams(Some(MGMT_MAX_CONCURRENT_STREAMS))
        .max_frame_size(Some(MGMT_MAX_FRAME_SIZE))
        .http2_max_header_list_size(Some(MGMT_MAX_HEADER_LIST_SIZE))
        .http2_keepalive_interval(Some(MGMT_KEEPALIVE_INTERVAL))
        .http2_keepalive_timeout(Some(MGMT_KEEPALIVE_TIMEOUT))
        .http2_max_pending_accept_reset_streams(Some(MGMT_MAX_PENDING_RESET_STREAMS))
        .timeout(MGMT_REQUEST_TIMEOUT)
}

/// The management API service implementation.
#[derive(Clone)]
pub struct ManagementService {
    manager: Arc<InterfaceManager>,
}

/// Extract the caller's peer credentials from a UDS gRPC request. Returns
/// `PermissionDenied` for connections without peer credentials (i.e. TCP).
fn caller_cred<T>(req: &Request<T>) -> Result<CallerCred, Status> {
    if let Some(info) = req.extensions().get::<UdsConnectInfo>() {
        if let Some(ucred) = info.peer_cred {
            return Ok(CallerCred {
                uid: ucred.uid(),
                gid: ucred.gid(),
                pid: ucred.pid().unwrap_or(0),
            });
        }
    }
    Err(Status::permission_denied(
        "endpoint operations require a peer-authenticated UDS connection",
    ))
}

/// Map the proto traffic-class integer to the config enum.
fn map_traffic_class(v: i32) -> Result<TrafficClass, Status> {
    match v {
        0 => Ok(TrafficClass::Normal),
        1 => Ok(TrafficClass::Safety),
        _ => Err(Status::invalid_argument(format!(
            "unknown traffic_class {v}"
        ))),
    }
}

/// Map the proto direction integer to the config enum.
fn map_direction(v: i32) -> Result<Direction, Status> {
    match v {
        0 => Ok(Direction::Encrypt),
        1 => Ok(Direction::Decrypt),
        _ => Err(Status::invalid_argument(format!("unknown direction {v}"))),
    }
}

#[tonic::async_trait]
impl ManagementApi for ManagementService {
    async fn create_uds_endpoint(
        &self,
        request: Request<CreateEndpointRequest>,
    ) -> Result<Response<UdsEndpointResponse>, Status> {
        let caller = caller_cred(&request)?;
        let req = request.into_inner();
        let class = map_traffic_class(req.traffic_class)?;
        let direction = map_direction(req.direction)?;
        let created = self.manager.create_uds(
            caller,
            &req.app_id,
            class,
            direction,
            req.ring_capacity as usize,
        )?;
        Ok(Response::new(UdsEndpointResponse {
            socket_path: created.socket_path,
            token: created.token,
            endpoint_id: created.endpoint_id,
        }))
    }

    async fn create_shm_endpoint(
        &self,
        request: Request<CreateEndpointRequest>,
    ) -> Result<Response<ShmEndpointResponse>, Status> {
        let caller = caller_cred(&request)?;
        let req = request.into_inner();
        let class = map_traffic_class(req.traffic_class)?;
        let direction = map_direction(req.direction)?;
        let created = self.manager.create_shm(
            caller,
            &req.app_id,
            class,
            direction,
            req.ring_capacity as usize,
        )?;
        Ok(Response::new(ShmEndpointResponse {
            token: created.token,
            endpoint_id: created.endpoint_id,
            control_socket_path: created.control_socket_path,
            cap_c2g: created.cap_c2g,
            cap_g2c: created.cap_g2c,
            notify: created.notify,
        }))
    }

    async fn close_endpoint(
        &self,
        request: Request<CloseEndpointRequest>,
    ) -> Result<Response<CloseEndpointResponse>, Status> {
        let caller = caller_cred(&request)?;
        let req = request.into_inner();
        self.manager.close(caller, req.endpoint_id)?;
        Ok(Response::new(CloseEndpointResponse { closed: true }))
    }

    async fn health(
        &self,
        request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        // Liveness stays unauthenticated (probes need it), but the exact version
        // string is fingerprinting material (CP-03 / M-3): disclose it only to a
        // peer-authenticated UDS caller, leaving it empty for the optional TCP bind.
        let version = match caller_cred(&request) {
            Ok(_) => self.manager.version().to_string(),
            Err(_) => String::new(),
        };
        Ok(Response::new(HealthResponse {
            healthy: true,
            version,
        }))
    }

    async fn list_rules(
        &self,
        request: Request<ListRulesRequest>,
    ) -> Result<Response<ListRulesResponse>, Status> {
        // ListRules discloses the full rule topology (names, app_ids, classes,
        // listen/upstream protos). Require the same peer-authenticated UDS
        // connection as the mutating RPCs so it is not readable over the
        // optional, unauthenticated TCP bind (#40).
        let _ = caller_cred(&request)?;
        Ok(Response::new(ListRulesResponse {
            rules: self.manager.list_rules(),
        }))
    }
}

/// Start the management API on a dedicated thread with its own tokio runtime.
/// Returns the thread handle; the server stops when `shutdown` is set.
pub fn start_management_server(
    manager: Arc<InterfaceManager>,
    api: ApiConfig,
    shutdown: Arc<AtomicBool>,
) -> io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("mgmt-grpc".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    error!("management API: failed to build tokio runtime: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                if let Err(e) = serve(manager, api, shutdown).await {
                    error!("management API server error: {e}");
                }
            });
        })
}

/// Build the listeners and run the gRPC server until shutdown.
async fn serve(
    manager: Arc<InterfaceManager>,
    api: ApiConfig,
    shutdown: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let svc = ManagementService { manager };

    // Prepare the UDS path: ensure its parent dir exists, drop any stale socket.
    let uds_path = api.uds_path.clone();
    if let Some(parent) = Path::new(&uds_path).parent() {
        let _ = scg_ipc::os::mkdir_mode(parent, 0o755);
    }
    let _ = std::fs::remove_file(&uds_path);

    let uds_listener = tokio::net::UnixListener::bind(&uds_path)?;
    // The control socket is group-accessible; per-app authorisation is still
    // enforced from config via SO_PEERCRED on each request.
    let _ = scg_ipc::os::chmod(Path::new(&uds_path), 0o660);
    let uds_stream = tokio_stream::wrappers::UnixListenerStream::new(uds_listener);

    info!("management API (gRPC) listening on unix:{uds_path}");

    let uds_shutdown = wait_for_shutdown(shutdown.clone());

    if let Some(tcp_addr) = api.tcp_addr.clone() {
        let addr: std::net::SocketAddr = tcp_addr
            .parse()
            .map_err(|e| format!("invalid api.tcp_addr '{tcp_addr}': {e}"))?;
        warn!(
            "management API also listening on tcp://{addr} \
             (no peer-cred auth; endpoint creation is refused over TCP)"
        );
        let tcp_shutdown = wait_for_shutdown(shutdown.clone());
        let uds_server = hardened_server()
            .add_service(ManagementApiServer::new(svc.clone()))
            .serve_with_incoming_shutdown(uds_stream, uds_shutdown);
        let tcp_server = hardened_server()
            .add_service(ManagementApiServer::new(svc))
            .serve_with_shutdown(addr, tcp_shutdown);
        let (uds_res, tcp_res) = tokio::join!(uds_server, tcp_server);
        uds_res?;
        tcp_res?;
    } else {
        hardened_server()
            .add_service(ManagementApiServer::new(svc))
            .serve_with_incoming_shutdown(uds_stream, uds_shutdown)
            .await?;
    }

    let _ = std::fs::remove_file(&uds_path);
    info!("management API server stopped");
    Ok(())
}

/// A future that resolves once the shutdown flag is set.
async fn wait_for_shutdown(shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management::config::GatewayConfig;
    use scg_proto::v1::management_api_server::ManagementApi;

    fn service(version: &str) -> ManagementService {
        let cfg: GatewayConfig = serde_json::from_str(r#"{"rules":[]}"#).unwrap();
        let manager = InterfaceManager::new(&cfg, version, None);
        ManagementService { manager }
    }

    // M-3 / CP-03: a caller with no UDS peer credentials (i.e. the optional TCP
    // bind) gets liveness but not the version fingerprint.
    #[tokio::test]
    async fn health_without_peer_cred_omits_version() {
        let svc = service("secret-9.9");
        let resp = svc.health(Request::new(HealthRequest {})).await.unwrap();
        let body = resp.into_inner();
        assert!(body.healthy);
        assert!(
            body.version.is_empty(),
            "version must not be disclosed to an unauthenticated caller"
        );
    }

    // The hardened builder must construct without panicking and stay usable — a
    // regression guard for the CP-01 limit wiring (the constants are valid tonic
    // arguments and the builder still accepts a service).
    #[test]
    fn hardened_server_builds() {
        let cfg: GatewayConfig = serde_json::from_str(r#"{"rules":[]}"#).unwrap();
        let manager = InterfaceManager::new(&cfg, "t", None);
        let _router =
            hardened_server().add_service(ManagementApiServer::new(ManagementService { manager }));
    }
}
