//! Container watcher — enumerates existing container cgroups and watches
//! for new containers via containerd's event stream.
//!
//! Zone assignment is label-driven: containers with a `rauha.dev/zone`
//! annotation in their OCI spec are assigned to the named zone. Containers
//! without the label are treated as global (no enforcement).

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
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
                tracing::info!("containerd event stream ended cleanly");
                return;
            }
            Err(e) => {
                tracing::warn!(
                    %e,
                    backoff_secs = backoff.as_secs(),
                    "containerd event watch failed — reconnecting"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
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
    // The event payload is containerd.events.TaskStart { container_id, pid }.
    // Decode the container_id from the protobuf Any.
    let container_id = match extract_container_id(event) {
        Some(id) => id,
        None => return,
    };

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

    // Resolve cgroup_id. containerd creates cgroups at known paths.
    let cgroup_id = resolve_container_cgroup_id(&container_id);
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

/// Extract container_id from a containerd TaskStart/TaskDelete protobuf Any.
///
/// The payload is `containerd.events.TaskStart { container_id: string, pid: uint32 }`
/// or `containerd.events.TaskDelete { container_id: string, ... }`.
/// Both have container_id as the first string field (field 1).
fn extract_container_id(event: &prost_types::Any) -> Option<String> {
    // Minimal protobuf decode: field 1 (tag=0x0a), length-delimited string.
    let data = &event.value;
    if data.len() < 3 || data[0] != 0x0a {
        return None;
    }
    let len = data[1] as usize;
    if data.len() < 2 + len {
        return None;
    }
    String::from_utf8(data[2..2 + len].to_vec()).ok()
}

/// Resolve a container's cgroup_id by checking known cgroup paths.
fn resolve_container_cgroup_id(container_id: &str) -> u64 {
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

    // Walk common roots as fallback.
    for root in ["/sys/fs/cgroup/system.slice", "/sys/fs/cgroup/kubepods.slice"] {
        let root_path = Path::new(root);
        if let Some(id) = find_cgroup_by_container_id(root_path, container_id) {
            return id;
        }
    }

    0
}

/// Recursively search for a cgroup directory containing the container_id.
fn find_cgroup_by_container_id(dir: &Path, container_id: &str) -> Option<u64> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path.file_name()?.to_str()?;
        if name.contains(container_id) {
            return Some(resolve_cgroup_id(&path));
        }
        if let Some(id) = find_cgroup_by_container_id(&path, container_id) {
            return Some(id);
        }
    }
    None
}
