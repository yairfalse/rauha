//! Task service implementation — the core shim logic.
//!
//! Maps containerd's Task ttrpc calls to Rauha's gRPC zone/container API.
//!
//! Sandbox lifecycle:
//!   1. containerd calls Create with annotation `container-type: sandbox`
//!      → we create a Rauha zone named after the sandbox ID
//!   2. containerd calls Create with annotation `container-type: container`
//!      → we create a Rauha container in the sandbox's zone
//!   3. Delete of sandbox → Rauha zone delete (force)

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use containerd_shim::asynchronous::{spawn, ExitSignal, Shim};
use containerd_shim::publisher::RemotePublisher;
use containerd_shim::{api, Config, Error, Flags, StartOpts, TtrpcResult};
use containerd_shim_protos::shim_async::Task;
use containerd_shim_protos::ttrpc::r#async::TtrpcContext;
use log::info;
use tokio::sync::Mutex;

use crate::rauha_client::pb;
use crate::rauha_client::RauhaClient;

/// OCI annotation keys used by CRI to distinguish sandbox vs container.
const ANNOTATION_CONTAINER_TYPE: &str = "io.kubernetes.cri.container-type";
const ANNOTATION_SANDBOX_ID: &str = "io.kubernetes.cri.sandbox-id";

/// Per-container state tracked by the shim.
struct ContainerState {
    /// Rauha container ID (UUID) returned by CreateContainer.
    rauha_id: String,
    /// The zone this container belongs to.
    zone_name: String,
    /// PID of the container process (set after Start).
    pid: u32,
    /// Whether this is the sandbox (pause) container.
    is_sandbox: bool,
    /// Exit code, set when the container exits.
    exit_code: Option<i32>,
}

#[derive(Clone)]
pub struct RauhaShim {
    exit: Arc<ExitSignal>,
    /// Rauha gRPC client.
    client: Arc<Mutex<Option<RauhaClient>>>,
    /// Container states keyed by containerd task ID.
    containers: Arc<Mutex<HashMap<String, ContainerState>>>,
    /// The zone name for this shim's sandbox.
    zone_name: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl Shim for RauhaShim {
    type T = Self;

    async fn new(_runtime_id: &str, _args: &Flags, _config: &mut Config) -> Self {
        Self {
            exit: Arc::new(ExitSignal::default()),
            client: Arc::new(Mutex::new(None)),
            containers: Arc::new(Mutex::new(HashMap::new())),
            zone_name: Arc::new(Mutex::new(None)),
        }
    }

    async fn start_shim(&mut self, opts: StartOpts) -> Result<String, Error> {
        let grouping = opts.id.clone();
        let address = spawn(opts, &grouping, Vec::new()).await?;
        Ok(address)
    }

    async fn delete_shim(&mut self) -> Result<api::DeleteResponse, Error> {
        Ok(api::DeleteResponse::new())
    }

    async fn wait(&mut self) {
        self.exit.wait().await;
    }

    async fn create_task_service(&self, _publisher: RemotePublisher) -> Self::T {
        // Connect to rauhad.
        let endpoint = RauhaClient::endpoint();
        let client = RauhaClient::connect(&endpoint).await.ok();
        if client.is_none() {
            log::warn!("failed to connect to rauhad at {endpoint} — will retry on first request");
        }

        Self {
            exit: self.exit.clone(),
            client: Arc::new(Mutex::new(client)),
            containers: self.containers.clone(),
            zone_name: self.zone_name.clone(),
        }
    }
}

impl RauhaShim {
    /// Get the Rauha client, connecting if needed.
    async fn client(&self) -> Result<RauhaClient, Error> {
        {
            let guard = self.client.lock().await;
            if let Some(c) = guard.as_ref() {
                return Ok(c.clone());
            }
        }

        // Try to connect.
        let endpoint = RauhaClient::endpoint();
        let client = RauhaClient::connect(&endpoint)
            .await
            .map_err(|e| Error::Other(format!("failed to connect to rauhad: {e}")))?;

        *self.client.lock().await = Some(client.clone());
        Ok(client)
    }

    /// Derive zone name from containerd sandbox ID.
    fn zone_name_for_sandbox(sandbox_id: &str) -> String {
        let short = if sandbox_id.len() > 12 {
            &sandbox_id[..12]
        } else {
            sandbox_id
        };
        format!("k8s-{short}")
    }

    /// Read the container-type annotation from the OCI bundle config.json.
    fn read_container_type(bundle: &str) -> (bool, Option<String>) {
        let config_path = std::path::Path::new(bundle).join("config.json");
        let data = match std::fs::read_to_string(&config_path) {
            Ok(d) => d,
            Err(_) => return (false, None),
        };
        let spec: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => return (false, None),
        };

        let annotations = spec.get("annotations").and_then(|a| a.as_object());
        let container_type = annotations
            .and_then(|a| a.get(ANNOTATION_CONTAINER_TYPE))
            .and_then(|v| v.as_str());
        let sandbox_id = annotations
            .and_then(|a| a.get(ANNOTATION_SANDBOX_ID))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let is_sandbox = container_type == Some("sandbox");
        (is_sandbox, sandbox_id)
    }
}

#[async_trait]
impl Task for RauhaShim {
    async fn create(
        &self,
        _ctx: &TtrpcContext,
        req: api::CreateTaskRequest,
    ) -> TtrpcResult<api::CreateTaskResponse> {
        let mut client = self.client().await?;
        let (is_sandbox, sandbox_id) = Self::read_container_type(&req.bundle);

        if is_sandbox {
            let zone_name = Self::zone_name_for_sandbox(&req.id);

            client
                .zones
                .create_zone(pb::zone::CreateZoneRequest {
                    name: zone_name.clone(),
                    zone_type: "non-global".into(),
                    policy_toml: String::new(),
                })
                .await
                .map_err(|e| Error::Other(format!("zone create failed: {e}")))?;

            *self.zone_name.lock().await = Some(zone_name.clone());

            self.containers.lock().await.insert(
                req.id.clone(),
                ContainerState {
                    rauha_id: String::new(),
                    zone_name,
                    pid: 0,
                    is_sandbox: true,
                    exit_code: None,
                },
            );

            info!("created sandbox zone for {}", req.id);
        } else {
            let zone_name = match &sandbox_id {
                Some(sid) => Self::zone_name_for_sandbox(sid),
                None => self
                    .zone_name
                    .lock()
                    .await
                    .clone()
                    .ok_or_else(|| Error::Other("no sandbox zone".into()))?,
            };

            // Parse command from the OCI bundle.
            let config_path = std::path::Path::new(&req.bundle).join("config.json");
            let spec: oci_spec::runtime::Spec = {
                let data = std::fs::read_to_string(&config_path)
                    .map_err(|e| Error::Other(format!("read config.json: {e}")))?;
                serde_json::from_str(&data)
                    .map_err(|e| Error::Other(format!("parse config.json: {e}")))?
            };

            let process = spec.process().as_ref();
            let command: Vec<String> = process
                .and_then(|p| p.args().as_ref())
                .cloned()
                .unwrap_or_default();
            let env: HashMap<String, String> = process
                .and_then(|p| p.env().as_ref())
                .map(|vars| {
                    vars.iter()
                        .filter_map(|e| {
                            let (k, v) = e.split_once('=')?;
                            Some((k.to_string(), v.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let working_dir = process
                .map(|p| p.cwd().to_string_lossy().to_string())
                .unwrap_or_default();

            let resp = client
                .containers
                .create_container(pb::container::CreateContainerRequest {
                    zone_name: zone_name.clone(),
                    name: req.id.clone(),
                    image: req.id.clone(),
                    command,
                    env,
                    working_dir,
                })
                .await
                .map_err(|e| Error::Other(format!("container create failed: {e}")))?;

            let rauha_id = resp.into_inner().container_id;

            self.containers.lock().await.insert(
                req.id.clone(),
                ContainerState {
                    rauha_id,
                    zone_name,
                    pid: 0,
                    is_sandbox: false,
                    exit_code: None,
                },
            );

            info!("created container {} in zone", req.id);
        }

        Ok(api::CreateTaskResponse {
            pid: std::process::id(),
            ..Default::default()
        })
    }

    async fn start(
        &self,
        _ctx: &TtrpcContext,
        req: api::StartRequest,
    ) -> TtrpcResult<api::StartResponse> {
        let containers = self.containers.lock().await;
        let state = containers
            .get(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;

        if state.is_sandbox {
            return Ok(api::StartResponse {
                pid: std::process::id(),
                ..Default::default()
            });
        }

        let rauha_id = state.rauha_id.clone();
        drop(containers);

        let mut client = self.client().await?;
        client
            .containers
            .start_container(pb::container::StartContainerRequest {
                container_id: rauha_id,
            })
            .await
            .map_err(|e| Error::Other(format!("container start failed: {e}")))?;

        let pid = std::process::id();
        self.containers
            .lock()
            .await
            .get_mut(&req.id)
            .map(|s| s.pid = pid);

        info!("started container {}", req.id);
        Ok(api::StartResponse {
            pid,
            ..Default::default()
        })
    }

    async fn kill(
        &self,
        _ctx: &TtrpcContext,
        req: api::KillRequest,
    ) -> TtrpcResult<api::Empty> {
        let containers = self.containers.lock().await;
        let state = containers
            .get(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;

        if state.is_sandbox {
            drop(containers);
            return Ok(api::Empty::default());
        }

        let rauha_id = state.rauha_id.clone();
        drop(containers);

        let mut client = self.client().await?;
        let _ = client
            .containers
            .stop_container(pb::container::StopContainerRequest {
                container_id: rauha_id,
                timeout_seconds: 10,
            })
            .await;

        Ok(api::Empty::default())
    }

    async fn delete(
        &self,
        _ctx: &TtrpcContext,
        req: api::DeleteRequest,
    ) -> TtrpcResult<api::DeleteResponse> {
        let state = match self.containers.lock().await.remove(&req.id) {
            Some(s) => s,
            None => return Ok(api::DeleteResponse::new()),
        };

        let mut client = self.client().await?;

        if state.is_sandbox {
            let _ = client
                .zones
                .delete_zone(pb::zone::DeleteZoneRequest {
                    name: state.zone_name.clone(),
                    force: true,
                })
                .await;

            info!("deleted sandbox zone {}", state.zone_name);
            self.exit.signal();
        } else {
            let _ = client
                .containers
                .delete_container(pb::container::DeleteContainerRequest {
                    container_id: state.rauha_id,
                    force: true,
                })
                .await;

            info!("deleted container {}", req.id);
        }

        Ok(api::DeleteResponse {
            exit_status: state.exit_code.unwrap_or(0) as u32,
            ..Default::default()
        })
    }

    async fn state(
        &self,
        _ctx: &TtrpcContext,
        req: api::StateRequest,
    ) -> TtrpcResult<api::StateResponse> {
        let containers = self.containers.lock().await;
        let state = containers
            .get(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;

        let status = if state.exit_code.is_some() {
            containerd_shim_protos::types::task::Status::STOPPED
        } else if state.pid > 0 {
            containerd_shim_protos::types::task::Status::RUNNING
        } else {
            containerd_shim_protos::types::task::Status::CREATED
        };

        Ok(api::StateResponse {
            id: req.id,
            bundle: String::new(),
            pid: state.pid,
            status: status.into(),
            ..Default::default()
        })
    }

    async fn wait(
        &self,
        _ctx: &TtrpcContext,
        req: api::WaitRequest,
    ) -> TtrpcResult<api::WaitResponse> {
        loop {
            {
                let containers = self.containers.lock().await;
                if let Some(state) = containers.get(&req.id) {
                    if let Some(code) = state.exit_code {
                        return Ok(api::WaitResponse {
                            exit_status: code as u32,
                            ..Default::default()
                        });
                    }

                    if state.is_sandbox {
                        drop(containers);
                        self.exit.wait().await;
                        return Ok(api::WaitResponse::new());
                    }

                    let rauha_id = state.rauha_id.clone();
                    drop(containers);

                    if let Ok(mut client) = self.client().await {
                        if let Ok(resp) = client
                            .containers
                            .get_container(pb::container::GetContainerRequest {
                                container_id: rauha_id,
                            })
                            .await
                        {
                            if let Some(c) = resp.into_inner().container {
                                if c.state == "exited" || c.state == "stopped" {
                                    self.containers
                                        .lock()
                                        .await
                                        .get_mut(&req.id)
                                        .map(|s| s.exit_code = Some(0));
                                    return Ok(api::WaitResponse {
                                        exit_status: 0,
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                } else {
                    return Ok(api::WaitResponse::new());
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    async fn connect(
        &self,
        _ctx: &TtrpcContext,
        req: api::ConnectRequest,
    ) -> TtrpcResult<api::ConnectResponse> {
        let containers = self.containers.lock().await;
        let pid = containers
            .get(&req.id)
            .map(|s| s.pid)
            .unwrap_or(std::process::id());

        Ok(api::ConnectResponse {
            shim_pid: std::process::id(),
            task_pid: pid,
            ..Default::default()
        })
    }

    async fn shutdown(
        &self,
        _ctx: &TtrpcContext,
        _req: api::ShutdownRequest,
    ) -> TtrpcResult<api::Empty> {
        let containers = self.containers.lock().await;
        if containers.is_empty() {
            self.exit.signal();
        }
        Ok(api::Empty::default())
    }

    async fn stats(
        &self,
        _ctx: &TtrpcContext,
        req: api::StatsRequest,
    ) -> TtrpcResult<api::StatsResponse> {
        let containers = self.containers.lock().await;
        let state = containers
            .get(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;

        let zone_name = state.zone_name.clone();
        drop(containers);

        let mut client = self.client().await?;
        let _ = client
            .zones
            .zone_stats(pb::zone::ZoneStatsRequest { zone_name })
            .await;

        // TODO: convert Rauha zone stats to containerd's cgroup metrics format
        Ok(api::StatsResponse::new())
    }
}
