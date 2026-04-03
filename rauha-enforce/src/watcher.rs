//! Container watcher — enumerates existing container cgroups and assigns zones.
//!
//! Zone assignment is label-driven: containers with a `rauha.dev/zone`
//! annotation in their OCI spec are assigned to the named zone. Containers
//! without the label are treated as global (no enforcement).

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rauha_common::zone::ZonePolicy;

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
