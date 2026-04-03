//! Container watcher — enumerates existing container cgroups and watches
//! for new containers via containerd's event stream.
//!
//! Zone assignment is label-driven: containers with a `rauha.dev/zone`
//! annotation in their OCI spec are assigned to the named zone. Containers
//! without the label are treated as global (no enforcement).

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rauha_common::zone::ZonePolicy;
use tokio::sync::mpsc;

/// Label key for zone assignment.
const ANNOTATION_ZONE: &str = "rauha.dev/zone";

/// A container's zone assignment.
pub struct ZoneAssignment {
    pub container_id: String,
    pub zone_name: String,
    pub cgroup_id: u64,
}

/// Enumerate existing container cgroups and assign zones by label.
///
/// Walks /sys/fs/cgroup looking for containerd-managed cgroups. For each one,
/// reads the OCI config.json to find the `rauha.dev/zone` annotation.
/// Containers without the annotation are skipped (global zone, no enforcement).
pub fn enumerate_cgroups(
    policies: &HashMap<String, ZonePolicy>,
) -> anyhow::Result<Vec<ZoneAssignment>> {
    let mut assignments = Vec::new();

    let cgroup_roots = [
        "/sys/fs/cgroup/system.slice",
        "/sys/fs/cgroup/kubepods.slice",
        "/sys/fs/cgroup/kubepods",
    ];

    for root in &cgroup_roots {
        let root_path = Path::new(root);
        if !root_path.exists() {
            continue;
        }

        scan_cgroup_dir(root_path, policies, &mut assignments)?;
    }

    if assignments.is_empty() {
        tracing::info!("no labelled containers found — running in monitor-only mode");
    }

    Ok(assignments)
}

fn scan_cgroup_dir(
    dir: &Path,
    policies: &HashMap<String, ZonePolicy>,
    assignments: &mut Vec<ZoneAssignment>,
) -> anyhow::Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        // Look for containerd scope cgroups (e.g., containerd-<id>.scope).
        if name.starts_with("containerd-") && name.ends_with(".scope") {
            let container_id = name
                .strip_prefix("containerd-")
                .and_then(|s| s.strip_suffix(".scope"))
                .unwrap_or(&name)
                .to_string();

            let cgroup_id = resolve_cgroup_id(&path);
            if cgroup_id == 0 {
                continue;
            }

            // Read zone label from the container's OCI config.json.
            if let Some(zone_name) = read_container_zone_label(&container_id) {
                if policies.contains_key(&zone_name) {
                    assignments.push(ZoneAssignment {
                        container_id,
                        zone_name,
                        cgroup_id,
                    });
                } else {
                    tracing::warn!(
                        container = container_id,
                        zone = zone_name,
                        "container has rauha.dev/zone label but no matching policy — skipping"
                    );
                }
            }
            // No label → silently skip (global zone, no enforcement).
        }

        // Recurse into subdirectories (for nested cgroup hierarchies).
        scan_cgroup_dir(&path, policies, assignments)?;
    }

    Ok(())
}

/// Read the `rauha.dev/zone` annotation from a container's OCI config.json.
///
/// Containerd writes the OCI runtime spec at a well-known path for each
/// container task. The annotations map contains container labels.
fn read_container_zone_label(container_id: &str) -> Option<String> {
    let state_paths = [
        format!(
            "/run/containerd/io.containerd.runtime.v2.task/default/{container_id}/config.json"
        ),
        format!(
            "/run/containerd/io.containerd.runtime.v2.task/k8s.io/{container_id}/config.json"
        ),
        format!(
            "/run/containerd/io.containerd.runtime.v2.task/moby/{container_id}/config.json"
        ),
    ];

    for path in &state_paths {
        if let Ok(data) = std::fs::read_to_string(path) {
            if let Ok(spec) = serde_json::from_str::<serde_json::Value>(&data) {
                if let Some(zone) = spec
                    .get("annotations")
                    .and_then(|a| a.get(ANNOTATION_ZONE))
                    .and_then(|v| v.as_str())
                {
                    return Some(zone.to_string());
                }
            }
        }
    }
    None
}

/// Resolve a cgroup directory path to its cgroup_id.
///
/// The cgroup_id is the inode number of the cgroup directory in cgroupfs.
/// This matches what `bpf_get_current_cgroup_id()` returns for processes
/// in that cgroup.
pub fn resolve_cgroup_id(cgroup_path: &Path) -> u64 {
    match std::fs::metadata(cgroup_path) {
        Ok(meta) => meta.ino(),
        Err(e) => {
            tracing::debug!(path = %cgroup_path.display(), %e, "failed to stat cgroup dir");
            0
        }
    }
}

// --- Live container event watching ---

/// Events emitted by the live container watcher.
pub enum WatcherEvent {
    /// A new container with a zone label was started.
    Add(ZoneAssignment),
    /// A container was stopped/deleted.
    Remove { container_id: String, cgroup_id: u64 },
}

/// Watch containerd for container start/stop events.
///
/// Connects to containerd's gRPC API and subscribes to task events.
/// For each TaskStart, reads the container's zone label and emits an Add event.
/// For each TaskDelete, emits a Remove event.
///
/// Reconnects automatically with exponential backoff if the connection drops.
pub async fn watch_containerd_events(
    socket_path: String,
    policies: Arc<HashMap<String, ZonePolicy>>,
    tx: mpsc::Sender<WatcherEvent>,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);

    loop {
        match try_watch(&socket_path, &policies, &tx).await {
            Ok(()) => {
                // End-of-stream means containerd closed the connection.
                // Reset backoff — the connection was healthy before it dropped.
                tracing::warn!("containerd event stream ended — reconnecting");
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                tracing::warn!(
                    %e,
                    backoff_secs = backoff.as_secs(),
                    "containerd event watch failed — reconnecting"
                );
                backoff = (backoff * 2).min(max_backoff);
            }
        }
        tokio::time::sleep(backoff).await;
    }
}

async fn try_watch(
    socket_path: &str,
    policies: &HashMap<String, ZonePolicy>,
    tx: &mpsc::Sender<WatcherEvent>,
) -> anyhow::Result<()> {
    use containerd_client::{connect, services::v1::events_client::EventsClient};
    use containerd_client::services::v1::SubscribeRequest;

    let channel = connect(socket_path).await
        .map_err(|e| anyhow::anyhow!("failed to connect to containerd at {socket_path}: {e}"))?;

    let mut client = EventsClient::new(channel);

    // Subscribe to task events.
    let request = SubscribeRequest {
        filters: vec![
            "topic==/tasks/start".to_string(),
            "topic==/tasks/delete".to_string(),
        ],
    };

    let mut stream = client.subscribe(request).await?.into_inner();

    tracing::info!(socket = socket_path, "subscribed to containerd events");

    while let Some(envelope) = stream.message().await? {
        let topic = &envelope.topic;
        let event = match &envelope.event {
            Some(e) => e,
            None => continue,
        };

        if topic == "/tasks/start" {
            handle_task_start(event, policies, tx).await;
        } else if topic == "/tasks/delete" {
            handle_task_delete(event, tx).await;
        }
    }

    Ok(())
}

async fn handle_task_start(
    event: &prost_types::Any,
    policies: &HashMap<String, ZonePolicy>,
    tx: &mpsc::Sender<WatcherEvent>,
) {
    use prost::Message;

    // Decode container_id and pid from the TaskStart event.
    let start = match TaskStartEvent::decode(event.value.as_slice()) {
        Ok(s) if !s.container_id.is_empty() => s,
        _ => return,
    };
    let container_id = start.container_id;

    // Wait briefly for the cgroup to be created.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Read zone label from OCI config.
    let zone_name = match read_container_zone_label(&container_id) {
        Some(z) => z,
        None => return, // No label → global, skip.
    };

    if !policies.contains_key(&zone_name) {
        tracing::warn!(
            container = container_id,
            zone = zone_name,
            "live: container has zone label but no matching policy — skipping"
        );
        return;
    }

    // Resolve cgroup_id — prefer /proc/pid/cgroup (fast), fall back to known paths.
    let cgroup_id = if start.pid > 0 {
        let id = resolve_cgroup_id_from_pid(start.pid);
        if id != 0 { id } else { resolve_container_cgroup_id(&container_id) }
    } else {
        resolve_container_cgroup_id(&container_id)
    };
    if cgroup_id == 0 {
        tracing::warn!(container = container_id, "live: could not resolve cgroup_id");
        return;
    }

    let _ = tx
        .send(WatcherEvent::Add(ZoneAssignment {
            container_id,
            zone_name,
            cgroup_id,
        }))
        .await;
}

async fn handle_task_delete(
    event: &prost_types::Any,
    tx: &mpsc::Sender<WatcherEvent>,
) {
    let container_id = match extract_container_id(event) {
        Some(id) => id,
        None => return,
    };

    // We don't know the cgroup_id after deletion (cgroup is gone).
    // The caller should track container_id → cgroup_id from Add events.
    let _ = tx
        .send(WatcherEvent::Remove {
            container_id,
            cgroup_id: 0,
        })
        .await;
}

/// Minimal containerd event payloads for proper protobuf decoding.
#[derive(Clone, PartialEq, prost::Message)]
struct TaskStartEvent {
    #[prost(string, tag = "1")]
    container_id: String,
    #[prost(uint32, tag = "2")]
    pid: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct TaskDeleteEvent {
    #[prost(string, tag = "1")]
    container_id: String,
}

/// Extract container_id from a containerd TaskStart/TaskDelete protobuf Any.
fn extract_container_id(event: &prost_types::Any) -> Option<String> {
    use prost::Message;

    let from_start = || {
        let msg = TaskStartEvent::decode(event.value.as_slice()).ok()?;
        (!msg.container_id.is_empty()).then_some(msg.container_id)
    };

    let from_delete = || {
        let msg = TaskDeleteEvent::decode(event.value.as_slice()).ok()?;
        (!msg.container_id.is_empty()).then_some(msg.container_id)
    };

    match event.type_url.as_str() {
        s if s.contains("TaskStart") => from_start(),
        s if s.contains("TaskDelete") => from_delete(),
        _ => from_start().or_else(from_delete),
    }
}

/// Resolve a container's cgroup_id from its init process PID.
///
/// Reads /proc/{pid}/cgroup to find the cgroup path, then stats the
/// cgroup directory to get the inode (= cgroup_id). This is fast and
/// robust — no filesystem walking needed.
///
/// Falls back to known path patterns if PID is not available.
fn resolve_container_cgroup_id(container_id: &str) -> u64 {
    // Try known cgroup path patterns as a fast path.
    let candidates = [
        format!("/sys/fs/cgroup/system.slice/containerd-{container_id}.scope"),
        format!("/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod{container_id}.slice"),
    ];

    for path in &candidates {
        let p = Path::new(path);
        if p.exists() {
            return resolve_cgroup_id(p);
        }
    }

    0
}

/// Resolve cgroup_id from a process PID by reading /proc/{pid}/cgroup.
fn resolve_cgroup_id_from_pid(pid: u32) -> u64 {
    let cgroup_file = format!("/proc/{pid}/cgroup");
    let content = match std::fs::read_to_string(&cgroup_file) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    // cgroup v2 format: "0::/path/to/cgroup"
    for line in content.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            let cgroup_path = format!("/sys/fs/cgroup{path}");
            let p = Path::new(&cgroup_path);
            if p.exists() {
                return resolve_cgroup_id(p);
            }
        }
    }

    0
}
