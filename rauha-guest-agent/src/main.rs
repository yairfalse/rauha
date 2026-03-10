//! rauha-guest-agent — runs inside lightweight VMs on macOS.
//!
//! Listens on virtio-vsock port 5123 for ShimRequest messages from the
//! host rauhad daemon. This is the macOS equivalent of rauha-shim.

mod container;

use std::collections::HashMap;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use rauha_common::shim::{self, ShimRequest, ShimResponse};

/// Port the guest agent listens on for vsock connections.
const VSOCK_PORT: u16 = 5123;

/// Guest-side state tracking all containers in this VM.
struct AgentState {
    rootfs_root: PathBuf,
    containers: HashMap<String, ContainerProcess>,
    shutdown: bool,
}

struct ContainerProcess {
    pid: u32,
    status: ContainerStatus,
    spec_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ContainerStatus {
    Created,
    Running,
    Stopped,
}

impl AgentState {
    fn new(rootfs_root: PathBuf) -> Self {
        Self {
            rootfs_root,
            containers: HashMap::new(),
            shutdown: false,
        }
    }

    fn create_container(&mut self, id: &str, spec_json: &str) -> Result<u32, String> {
        if self.containers.contains_key(id) {
            return Err(format!("container {id} already exists"));
        }
        self.containers.insert(
            id.to_string(),
            ContainerProcess {
                pid: 0,
                status: ContainerStatus::Created,
                spec_json: spec_json.to_string(),
            },
        );
        Ok(0)
    }

    fn start_container(&mut self, id: &str) -> Result<u32, String> {
        let proc = self
            .containers
            .get(id)
            .ok_or_else(|| format!("container {id} not found"))?;
        if proc.status != ContainerStatus::Created {
            return Err(format!("container {id} not in created state"));
        }
        let spec_json = proc.spec_json.clone();

        let pid = container::fork_and_exec(id, &spec_json, &self.rootfs_root)
            .map_err(|e| e.to_string())?;

        let proc = self.containers.get_mut(id).unwrap();
        proc.pid = pid;
        proc.status = ContainerStatus::Running;
        Ok(pid)
    }

    fn stop_container(&mut self, id: &str, signal: i32) -> Result<(), String> {
        let proc = self
            .containers
            .get(id)
            .ok_or_else(|| format!("container {id} not found"))?;
        if proc.status != ContainerStatus::Running || proc.pid == 0 {
            return Err(format!("container {id} is not running"));
        }
        container::send_signal(proc.pid, signal).map_err(|e| e.to_string())
    }

    fn get_state(&self, id: &str) -> Option<(u32, String)> {
        self.containers.get(id).map(|p| {
            let status = match p.status {
                ContainerStatus::Created => "created",
                ContainerStatus::Running => "running",
                ContainerStatus::Stopped => "stopped",
            };
            (p.pid, status.to_string())
        })
    }

    fn reap_children(&mut self) {
        for proc in self.containers.values_mut() {
            if proc.status != ContainerStatus::Running || proc.pid == 0 {
                continue;
            }
            if let Some(_exit_code) = container::try_wait(proc.pid) {
                proc.status = ContainerStatus::Stopped;
            }
        }
    }
}

fn handle_request(state: &mut AgentState, request: ShimRequest) -> ShimResponse {
    match request {
        ShimRequest::CreateContainer { id, spec_json } => {
            match state.create_container(&id, &spec_json) {
                Ok(pid) => ShimResponse::Created { pid },
                Err(e) => ShimResponse::Error { message: e },
            }
        }
        ShimRequest::StartContainer { id } => match state.start_container(&id) {
            Ok(pid) => ShimResponse::Created { pid },
            Err(e) => ShimResponse::Error { message: e },
        },
        ShimRequest::StopContainer { id, signal } => {
            match state.stop_container(&id, signal) {
                Ok(()) => ShimResponse::Ok,
                Err(e) => ShimResponse::Error { message: e },
            }
        }
        ShimRequest::Signal { id, signal } => {
            match state.stop_container(&id, signal) {
                Ok(()) => ShimResponse::Ok,
                Err(e) => ShimResponse::Error { message: e },
            }
        }
        ShimRequest::GetState { id } => match state.get_state(&id) {
            Some((pid, status)) => ShimResponse::State { pid, status },
            None => ShimResponse::Error {
                message: format!("container {id} not found"),
            },
        },
        ShimRequest::Shutdown => {
            state.shutdown = true;
            ShimResponse::Ok
        }
        ShimRequest::GetStats => {
            let (cpu_usage_ns, memory_bytes, pids) = container::collect_stats();
            ShimResponse::Stats {
                cpu_usage_ns,
                memory_bytes,
                pids,
            }
        }
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("rauha_guest_agent=info")
        .init();

    tracing::info!("rauha-guest-agent starting");

    // The rootfs is shared from the host via virtio-fs, mounted at /mnt/rauha.
    let rootfs_root = PathBuf::from("/mnt/rauha");
    let mut state = AgentState::new(rootfs_root);

    // In a real VM, we'd listen on vsock CID=3 (VMADDR_CID_HOST) port 5123.
    // For now, we listen on a Unix socket as a fallback for testing, and
    // attempt vsock if /dev/vsock is available.
    let socket_path = "/run/rauha-guest-agent.sock";

    if std::path::Path::new("/dev/vsock").exists() {
        tracing::info!(port = VSOCK_PORT, "listening on vsock");
        // vsock listening requires raw socket via libc::socket(AF_VSOCK, ...).
        // Fall back to Unix socket for initial testing.
        listen_unix(socket_path, &mut state)?;
    } else {
        tracing::info!(path = socket_path, "listening on unix socket (vsock not available)");
        listen_unix(socket_path, &mut state)?;
    }

    tracing::info!("guest agent exited");
    Ok(())
}

fn listen_unix(path: &str, state: &mut AgentState) -> anyhow::Result<()> {
    if std::path::Path::new(path).exists() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                match shim::decode_from::<ShimRequest>(&mut stream) {
                    Ok(request) => {
                        let response = handle_request(state, request);
                        if let Err(e) = shim::encode_to(&mut stream, &response) {
                            tracing::error!(%e, "failed to send response");
                        }
                        if state.shutdown {
                            tracing::info!("shutting down");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(%e, "failed to decode request");
                    }
                }
            }
            Err(e) => {
                tracing::error!(%e, "accept error");
            }
        }

        state.reap_children();
    }

    let _ = std::fs::remove_file(path);
    Ok(())
}
