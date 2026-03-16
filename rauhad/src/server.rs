use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::zone::registry::ZoneRegistry;

pub mod pb {
    pub mod zone {
        tonic::include_proto!("rauha.zone.v1");
    }
    pub mod container {
        tonic::include_proto!("rauha.container.v1");
    }
    pub mod image {
        tonic::include_proto!("rauha.image.v1");
    }
}

use pb::zone::zone_service_server::ZoneService;
use pb::container::container_service_server::ContainerService;
use pb::image::image_service_server::ImageService;

// --- Zone Service ---

pub struct ZoneServiceImpl {
    registry: Arc<ZoneRegistry>,
    root: String,
}

impl ZoneServiceImpl {
    pub fn new(registry: Arc<ZoneRegistry>, root: String) -> Self {
        Self { registry, root }
    }
}

#[tonic::async_trait]
impl ZoneService for ZoneServiceImpl {
    async fn create_zone(
        &self,
        request: Request<pb::zone::CreateZoneRequest>,
    ) -> Result<Response<pb::zone::CreateZoneResponse>, Status> {
        let req = request.into_inner();

        let (zone_type, policy) = if req.policy_toml.is_empty() {
            (
                match req.zone_type.as_str() {
                    "privileged" => rauha_common::zone::ZoneType::Privileged,
                    _ => rauha_common::zone::ZoneType::NonGlobal,
                },
                rauha_common::zone::ZonePolicy::default(),
            )
        } else {
            crate::zone::policy::parse_policy(&req.policy_toml, &self.root)
                .map_err(|e| Status::invalid_argument(e.to_string()))?
        };

        let zone = self
            .registry
            .create_zone(&req.name, zone_type, policy)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(pb::zone::CreateZoneResponse {
            zone_id: zone.id.to_string(),
            name: zone.name,
            state: format!("{:?}", zone.state),
        }))
    }

    async fn delete_zone(
        &self,
        request: Request<pb::zone::DeleteZoneRequest>,
    ) -> Result<Response<pb::zone::DeleteZoneResponse>, Status> {
        let req = request.into_inner();
        self.registry
            .delete_zone(&req.name, req.force)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(pb::zone::DeleteZoneResponse {}))
    }

    async fn get_zone(
        &self,
        request: Request<pb::zone::GetZoneRequest>,
    ) -> Result<Response<pb::zone::GetZoneResponse>, Status> {
        let req = request.into_inner();
        let zone = self
            .registry
            .get_zone(&req.name)
            .await
            .map_err(|e| Status::not_found(e.to_string()))?;

        let containers = self
            .registry
            .list_containers(Some(&req.name))
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(pb::zone::GetZoneResponse {
            zone: Some(pb::zone::ZoneInfo {
                id: zone.id.to_string(),
                name: zone.name,
                zone_type: format!("{:?}", zone.zone_type),
                state: format!("{:?}", zone.state),
                container_count: containers.len() as u32,
                created_at: zone.created_at.to_rfc3339(),
            }),
        }))
    }

    async fn list_zones(
        &self,
        _request: Request<pb::zone::ListZonesRequest>,
    ) -> Result<Response<pb::zone::ListZonesResponse>, Status> {
        let zones = self
            .registry
            .list_zones()
            .map_err(|e| Status::internal(e.to_string()))?;

        let zone_infos = zones
            .into_iter()
            .map(|z| {
                let container_count = self
                    .registry
                    .list_containers(Some(&z.name))
                    .map(|c| c.len() as u32)
                    .unwrap_or(0);
                pb::zone::ZoneInfo {
                    id: z.id.to_string(),
                    name: z.name,
                    zone_type: format!("{:?}", z.zone_type),
                    state: format!("{:?}", z.state),
                    container_count,
                    created_at: z.created_at.to_rfc3339(),
                }
            })
            .collect();

        Ok(Response::new(pb::zone::ListZonesResponse {
            zones: zone_infos,
        }))
    }

    async fn apply_policy(
        &self,
        request: Request<pb::zone::ApplyPolicyRequest>,
    ) -> Result<Response<pb::zone::ApplyPolicyResponse>, Status> {
        let req = request.into_inner();
        let (_zone_type, policy) =
            crate::zone::policy::parse_policy(&req.policy_toml, &self.root)
                .map_err(|e| Status::invalid_argument(e.to_string()))?;

        self.registry
            .apply_policy(&req.zone_name, policy)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(pb::zone::ApplyPolicyResponse {}))
    }

    async fn get_policy(
        &self,
        request: Request<pb::zone::GetPolicyRequest>,
    ) -> Result<Response<pb::zone::GetPolicyResponse>, Status> {
        let req = request.into_inner();
        let zone = self
            .registry
            .get_zone(&req.zone_name)
            .await
            .map_err(|e| Status::not_found(e.to_string()))?;

        let toml =
            crate::zone::policy::policy_to_toml(&zone.name, zone.zone_type, &zone.policy);

        Ok(Response::new(pb::zone::GetPolicyResponse {
            policy_toml: toml,
        }))
    }

    async fn zone_stats(
        &self,
        request: Request<pb::zone::ZoneStatsRequest>,
    ) -> Result<Response<pb::zone::ZoneStatsResponse>, Status> {
        let req = request.into_inner();
        let stats = self
            .registry
            .zone_stats(&req.zone_name)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(pb::zone::ZoneStatsResponse {
            zone_id: stats.zone_id.to_string(),
            container_count: stats.container_count,
            cpu_usage_percent: stats.cpu_usage_percent,
            memory_usage_bytes: stats.memory_usage_bytes,
            memory_limit_bytes: stats.memory_limit_bytes,
            network_rx_bytes: stats.network_rx_bytes,
            network_tx_bytes: stats.network_tx_bytes,
            pids_current: stats.pids_current,
        }))
    }

    async fn verify_isolation(
        &self,
        request: Request<pb::zone::VerifyIsolationRequest>,
    ) -> Result<Response<pb::zone::VerifyIsolationResponse>, Status> {
        let req = request.into_inner();
        let report = self
            .registry
            .verify_isolation(&req.zone_name)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(pb::zone::VerifyIsolationResponse {
            is_isolated: report.is_isolated,
            checks: report
                .checks
                .into_iter()
                .map(|c| pb::zone::IsolationCheck {
                    name: c.name,
                    passed: c.passed,
                    detail: c.detail,
                })
                .collect(),
        }))
    }

    type WatchEventsStream = ReceiverStream<Result<pb::zone::ZoneEvent, Status>>;

    async fn watch_events(
        &self,
        _request: Request<pb::zone::WatchEventsRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        let (_tx, rx) = mpsc::channel(128);
        // TODO: Wire up event broadcasting from zone registry.
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

// --- Container Service ---

pub struct ContainerServiceImpl {
    registry: Arc<ZoneRegistry>,
}

impl ContainerServiceImpl {
    pub fn new(registry: Arc<ZoneRegistry>) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl ContainerService for ContainerServiceImpl {
    async fn create_container(
        &self,
        request: Request<pb::container::CreateContainerRequest>,
    ) -> Result<Response<pb::container::CreateContainerResponse>, Status> {
        let req = request.into_inner();
        let spec = rauha_common::container::ContainerSpec {
            name: req.name,
            image: req.image,
            command: req.command,
            env: req.env.into_iter().collect(),
            working_dir: if req.working_dir.is_empty() {
                None
            } else {
                Some(req.working_dir)
            },
            rootfs_path: None,
            overlay_layers: None,
        };

        let container = self
            .registry
            .create_container(&req.zone_name, spec)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(pb::container::CreateContainerResponse {
            container_id: container.id.to_string(),
            name: container.name,
            state: format!("{:?}", container.state),
        }))
    }

    async fn start_container(
        &self,
        request: Request<pb::container::StartContainerRequest>,
    ) -> Result<Response<pb::container::StartContainerResponse>, Status> {
        let req = request.into_inner();
        let container_id = req
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        self.registry
            .start_container(&container_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(pb::container::StartContainerResponse {}))
    }

    async fn stop_container(
        &self,
        request: Request<pb::container::StopContainerRequest>,
    ) -> Result<Response<pb::container::StopContainerResponse>, Status> {
        let req = request.into_inner();
        let container_id = req
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        self.registry
            .stop_container(&container_id, req.timeout_seconds)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(pb::container::StopContainerResponse {}))
    }

    async fn delete_container(
        &self,
        request: Request<pb::container::DeleteContainerRequest>,
    ) -> Result<Response<pb::container::DeleteContainerResponse>, Status> {
        let req = request.into_inner();
        let container_id = req
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        self.registry
            .delete_container(&container_id, req.force)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(pb::container::DeleteContainerResponse {}))
    }

    async fn get_container(
        &self,
        request: Request<pb::container::GetContainerRequest>,
    ) -> Result<Response<pb::container::GetContainerResponse>, Status> {
        let req = request.into_inner();
        let container_id = req
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        let container = self
            .registry
            .get_container(&container_id)
            .map_err(|e| Status::not_found(e.to_string()))?;

        Ok(Response::new(pb::container::GetContainerResponse {
            container: Some(pb::container::ContainerInfo {
                id: container.id.to_string(),
                name: container.name,
                zone_id: container.zone_id.to_string(),
                zone_name: String::new(), // TODO: reverse lookup
                image: container.image,
                state: format!("{:?}", container.state),
                pid: container.pid.unwrap_or(0),
                created_at: container.created_at.to_rfc3339(),
                started_at: container
                    .started_at
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default(),
            }),
        }))
    }

    async fn list_containers(
        &self,
        request: Request<pb::container::ListContainersRequest>,
    ) -> Result<Response<pb::container::ListContainersResponse>, Status> {
        let req = request.into_inner();
        let zone_filter = if req.zone_name.is_empty() {
            None
        } else {
            Some(req.zone_name.as_str())
        };

        let containers = self
            .registry
            .list_containers(zone_filter)
            .map_err(|e| Status::internal(e.to_string()))?;

        let infos = containers
            .into_iter()
            .map(|c| pb::container::ContainerInfo {
                id: c.id.to_string(),
                name: c.name,
                zone_id: c.zone_id.to_string(),
                zone_name: String::new(), // TODO: reverse lookup
                image: c.image,
                state: format!("{:?}", c.state),
                pid: c.pid.unwrap_or(0),
                created_at: c.created_at.to_rfc3339(),
                started_at: c.started_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
            })
            .collect();

        Ok(Response::new(pb::container::ListContainersResponse {
            containers: infos,
        }))
    }

    type ContainerLogsStream = ReceiverStream<Result<pb::container::ContainerLogEntry, Status>>;

    async fn container_logs(
        &self,
        request: Request<pb::container::ContainerLogsRequest>,
    ) -> Result<Response<Self::ContainerLogsStream>, Status> {
        let req = request.into_inner();
        let container_id = req
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        // Verify container exists.
        self.registry
            .get_container(&container_id)
            .map_err(|e| Status::not_found(e.to_string()))?;

        let (tx, rx) = mpsc::channel(256);
        let follow = req.follow;
        let tail = req.tail;
        let id_str = container_id.to_string();

        // Cancellation flag: set when the tx channel is dropped (client disconnects).
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancelled_clone = cancelled.clone();

        // Monitor the receiver: when the client drops, signal cancellation.
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            tx_clone.closed().await;
            cancelled_clone.store(true, std::sync::atomic::Ordering::Relaxed);
        });

        tokio::task::spawn_blocking(move || {
            crate::logs::tail_logs(&id_str, follow, tail, &cancelled, |log_line| {
                tx.blocking_send(Ok(pb::container::ContainerLogEntry {
                    source: log_line.source,
                    line: log_line.line,
                    timestamp: log_line.timestamp,
                }))
                .is_ok()
            });
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn exec_in_container(
        &self,
        _request: Request<pb::container::ExecInContainerRequest>,
    ) -> Result<Response<pb::container::ExecInContainerResponse>, Status> {
        Err(Status::unimplemented(
            "exec_in_container: use ExecStream for interactive exec",
        ))
    }

    type ExecStreamStream = ReceiverStream<Result<pb::container::ExecStreamResponse, Status>>;

    async fn exec_stream(
        &self,
        request: Request<Streaming<pb::container::ExecStreamRequest>>,
    ) -> Result<Response<Self::ExecStreamStream>, Status> {
        use tokio_stream::StreamExt;

        let mut in_stream = request.into_inner();

        // First message must be ExecStreamStart.
        let start = match in_stream.next().await {
            Some(Ok(msg)) => match msg.message {
                Some(pb::container::exec_stream_request::Message::Start(s)) => s,
                _ => return Err(Status::invalid_argument("first message must be ExecStreamStart")),
            },
            _ => return Err(Status::invalid_argument("empty stream")),
        };

        let container_id = start
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        // Verify container exists and get its zone.
        let container = self
            .registry
            .get_container(&container_id)
            .map_err(|e| Status::not_found(e.to_string()))?;

        // Look up zone name.
        let zone_name = self
            .registry
            .zone_name_for_container(&container.zone_id)
            .await
            .ok_or_else(|| Status::internal("zone not found for container"))?;

        // Send Exec request to shim.
        let exec_req = rauha_common::shim::ShimRequest::Exec {
            id: container_id.to_string(),
            command: start.command,
            env: start.env.into_iter().map(|(k, v)| format!("{k}={v}")).collect(),
            pty: start.tty,
        };

        let response = self
            .registry
            .shim_request(&zone_name, &exec_req)
            .await
            .map_err(|e| Status::internal(format!("shim exec failed: {e}")))?;

        let socket_path = match response {
            rauha_common::shim::ShimResponse::AttachReady { socket_path } => socket_path,
            rauha_common::shim::ShimResponse::Error { message } => {
                return Err(Status::internal(format!("exec failed: {message}")));
            }
            _ => return Err(Status::internal("unexpected shim response")),
        };

        // Connect to the attach socket.
        let stream = tokio::net::UnixStream::connect(&socket_path)
            .await
            .map_err(|e| Status::internal(format!("failed to connect to attach socket: {e}")))?;

        let (read_half, write_half) = stream.into_split();

        let (tx, rx) = mpsc::channel(256);

        // Read from attach socket → send to gRPC client.
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut reader = read_half;
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let resp = pb::container::ExecStreamResponse {
                            message: Some(
                                pb::container::exec_stream_response::Message::StdoutData(
                                    buf[..n].to_vec(),
                                ),
                            ),
                        };
                        if tx.send(Ok(resp)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Read from gRPC client → write to attach socket.
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut writer = write_half;
            while let Some(Ok(msg)) = in_stream.next().await {
                match msg.message {
                    Some(pb::container::exec_stream_request::Message::StdinData(data)) => {
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(pb::container::exec_stream_request::Message::Resize(_resize)) => {
                        // TODO: send TIOCSWINSZ to PTY via shim
                    }
                    _ => {}
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type AttachStream = ReceiverStream<Result<pb::container::AttachResponse, Status>>;

    async fn attach(
        &self,
        request: Request<Streaming<pb::container::AttachRequest>>,
    ) -> Result<Response<Self::AttachStream>, Status> {
        use tokio_stream::StreamExt;

        let mut in_stream = request.into_inner();

        // First message must be AttachStart.
        let start = match in_stream.next().await {
            Some(Ok(msg)) => match msg.message {
                Some(pb::container::attach_request::Message::Start(s)) => s,
                _ => return Err(Status::invalid_argument("first message must be AttachStart")),
            },
            _ => return Err(Status::invalid_argument("empty stream")),
        };

        let container_id = start
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        let container = self
            .registry
            .get_container(&container_id)
            .map_err(|e| Status::not_found(e.to_string()))?;

        let zone_name = self
            .registry
            .zone_name_for_container(&container.zone_id)
            .await
            .ok_or_else(|| Status::internal("zone not found for container"))?;

        let attach_req = rauha_common::shim::ShimRequest::Attach {
            id: container_id.to_string(),
            pty: true,
        };

        let response = self
            .registry
            .shim_request(&zone_name, &attach_req)
            .await
            .map_err(|e| Status::internal(format!("shim attach failed: {e}")))?;

        match response {
            rauha_common::shim::ShimResponse::AttachReady { socket_path } => {
                let stream = tokio::net::UnixStream::connect(&socket_path)
                    .await
                    .map_err(|e| {
                        Status::internal(format!("failed to connect to attach socket: {e}"))
                    })?;

                let (read_half, write_half) = stream.into_split();
                let (tx, rx) = mpsc::channel(256);

                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut reader = read_half;
                    let mut buf = [0u8; 4096];
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                let resp = pb::container::AttachResponse {
                                    message: Some(
                                        pb::container::attach_response::Message::StdoutData(
                                            buf[..n].to_vec(),
                                        ),
                                    ),
                                };
                                if tx.send(Ok(resp)).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });

                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let mut writer = write_half;
                    while let Some(Ok(msg)) = in_stream.next().await {
                        match msg.message {
                            Some(pb::container::attach_request::Message::StdinData(data)) => {
                                if writer.write_all(&data).await.is_err() {
                                    break;
                                }
                            }
                            Some(pb::container::attach_request::Message::Resize(_resize)) => {
                                // TODO: send TIOCSWINSZ to PTY via shim
                            }
                            _ => {}
                        }
                    }
                });

                Ok(Response::new(ReceiverStream::new(rx)))
            }
            rauha_common::shim::ShimResponse::Error { message } => {
                Err(Status::internal(format!("attach failed: {message}")))
            }
            _ => Err(Status::internal("unexpected shim response")),
        }
    }
}

// --- Image Service ---

pub struct ImageServiceImpl {
    image_service: Arc<rauha_oci::image::ImageService>,
}

impl ImageServiceImpl {
    pub fn new(image_service: Arc<rauha_oci::image::ImageService>) -> Self {
        Self { image_service }
    }
}

#[tonic::async_trait]
impl ImageService for ImageServiceImpl {
    type PullStream = ReceiverStream<Result<pb::image::PullProgress, Status>>;

    async fn pull(
        &self,
        request: Request<pb::image::PullRequest>,
    ) -> Result<Response<Self::PullStream>, Status> {
        let req = request.into_inner();
        let (tx, rx) = mpsc::channel(64);
        let svc = self.image_service.clone();

        tokio::spawn(async move {
            let reference = req.reference;
            let tx_clone = tx.clone();

            let result = svc
                .pull(&reference, |progress| {
                    let _ = tx_clone.try_send(Ok(pb::image::PullProgress {
                        status: progress.status,
                        layer: progress.layer,
                        current: progress.current,
                        total: progress.total,
                        done: progress.done,
                    }));
                })
                .await;

            if let Err(e) = result {
                let _ = tx.send(Err(Status::internal(e.to_string()))).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn list(
        &self,
        _request: Request<pb::image::ListImagesRequest>,
    ) -> Result<Response<pb::image::ListImagesResponse>, Status> {
        let images = self
            .image_service
            .list_images()
            .map_err(|e| Status::internal(e.to_string()))?;

        let infos = images
            .into_iter()
            .map(|img| pb::image::ImageInfo {
                digest: img.digest,
                tags: vec![img.reference],
                size: img.size,
                created_at: String::new(),
            })
            .collect();

        Ok(Response::new(pb::image::ListImagesResponse {
            images: infos,
        }))
    }

    async fn remove(
        &self,
        request: Request<pb::image::RemoveImageRequest>,
    ) -> Result<Response<pb::image::RemoveImageResponse>, Status> {
        let req = request.into_inner();
        self.image_service
            .remove_image(&req.reference)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(pb::image::RemoveImageResponse {}))
    }

    async fn inspect(
        &self,
        request: Request<pb::image::InspectImageRequest>,
    ) -> Result<Response<pb::image::InspectImageResponse>, Status> {
        let req = request.into_inner();
        let config = self
            .image_service
            .inspect(&req.reference)
            .map_err(|e| Status::not_found(e.to_string()))?;

        let config_json =
            serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".into());

        Ok(Response::new(pb::image::InspectImageResponse {
            digest: String::new(),
            tags: vec![req.reference],
            size: 0,
            config_json,
            layers: Vec::new(),
        }))
    }
}
