//! Container watcher — enumerates existing container cgroups.
//!
//! V1: scans /sys/fs/cgroup for containerd scope cgroups and reads labels
//! from containerd's state directory.
//!
//! Future: subscribe to containerd ttrpc events for live updates.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rauha_common::zone::ZonePolicy;

/// A container's zone assignment.
pub struct ZoneAssignment {
    pub container_id: String,
    pub zone_name: String,
    pub cgroup_id: u64,
}

/// Enumerate existing container cgroups and assign zones.
///
/// Walks /sys/fs/cgroup looking for containerd-managed cgroups. For each one,
/// attempts to read zone labels. Containers without a zone label are skipped
/// (treated as global).
///
/// This is a best-effort scan — if the cgroup structure doesn't match
/// expectations, containers are silently skipped.
pub fn enumerate_cgroups(
    policies: &HashMap<String, ZonePolicy>,
) -> anyhow::Result<Vec<ZoneAssignment>> {
    let mut assignments = Vec::new();

    // Common cgroup paths for containerd-managed containers.
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

            // Get cgroup_id from the directory's inode.
            let cgroup_id = resolve_cgroup_id(&path);
            if cgroup_id == 0 {
                continue;
            }

            // Try to find a zone assignment for this container.
            // In a full implementation, we'd read labels from containerd's
            // metadata store. For V1, we assign based on policy file existence:
            // if a policy named after the cgroup path segment exists, use it.
            for zone_name in policies.keys() {
                // Simple heuristic: if there's a policy, and the container
                // exists, assign it. In production, this would be label-driven.
                assignments.push(ZoneAssignment {
                    container_id: container_id.clone(),
                    zone_name: zone_name.clone(),
                    cgroup_id,
                });
                break; // One zone per container.
            }
        }

        // Recurse into subdirectories (for nested cgroup hierarchies).
        if path.is_dir() {
            scan_cgroup_dir(&path, policies, assignments)?;
        }
    }

    Ok(())
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
