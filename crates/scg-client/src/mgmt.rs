//! Management-plane client: dials the gateway's gRPC control socket (a Unix
//! domain socket by default) to create or close an endpoint.
//!
//! A short-lived current-thread tokio runtime is built for each call so the
//! synchronous data-plane object never has to own async resources.

use std::path::{Path, PathBuf};

use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use scg_proto::v1::management_api_client::ManagementApiClient;
use scg_proto::v1::{CloseEndpointRequest, CreateEndpointRequest};

use crate::error::{Result, ScgError};
use crate::{Direction, TrafficClass, Transport};

/// Default management socket path (matches the gateway's `ApiConfig` default).
pub const DEFAULT_MGMT_SOCKET: &str = "/run/scg/management.sock";

/// Outcome of a successful endpoint-creation request.
pub enum Created {
    /// A UDS endpoint: connect to `socket_path` and present `token`.
    Uds {
        socket_path: String,
        token: Vec<u8>,
        endpoint_id: u32,
    },
    /// A SHM endpoint: connect to `control_socket_path`, present `token`, and
    /// receive the ring descriptors (geometry is carried in the SCM_RIGHTS
    /// offer, which is authoritative).
    Shm {
        control_socket_path: String,
        token: Vec<u8>,
        endpoint_id: u32,
    },
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ScgError::Io)
}

/// Dial the management API over a Unix-domain socket.
async fn dial(path: PathBuf) -> Result<ManagementApiClient<Channel>> {
    // The URI is a placeholder; the custom connector ignores it and dials the
    // UDS path instead.
    let channel = Endpoint::try_from("http://[::]:50051")
        .map_err(ScgError::from)?
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .map_err(ScgError::from)?;
    Ok(ManagementApiClient::new(channel))
}

/// Ask the gateway to create (or atomically replace) an endpoint.
pub fn create_endpoint(
    mgmt_socket: &Path,
    app_id: &str,
    transport: Transport,
    class: TrafficClass,
    direction: Direction,
    ring_capacity: u64,
) -> Result<Created> {
    let rt = runtime()?;
    let mgmt_socket = mgmt_socket.to_path_buf();
    rt.block_on(async move {
        let mut client = dial(mgmt_socket).await?;
        let req = CreateEndpointRequest {
            app_id: app_id.to_string(),
            traffic_class: class as i32,
            direction: direction as i32,
            ring_capacity,
        };
        match transport {
            Transport::Uds => {
                let resp = client.create_uds_endpoint(req).await?.into_inner();
                Ok(Created::Uds {
                    socket_path: resp.socket_path,
                    token: resp.token,
                    endpoint_id: resp.endpoint_id,
                })
            }
            Transport::Shm => {
                let resp = client.create_shm_endpoint(req).await?.into_inner();
                Ok(Created::Shm {
                    control_socket_path: resp.control_socket_path,
                    token: resp.token,
                    endpoint_id: resp.endpoint_id,
                })
            }
        }
    })
}

/// Tear down a previously created endpoint.
pub fn close_endpoint(mgmt_socket: &Path, endpoint_id: u32) -> Result<()> {
    let rt = runtime()?;
    let mgmt_socket = mgmt_socket.to_path_buf();
    rt.block_on(async move {
        let mut client = dial(mgmt_socket).await?;
        client
            .close_endpoint(CloseEndpointRequest { endpoint_id })
            .await?;
        Ok(())
    })
}
