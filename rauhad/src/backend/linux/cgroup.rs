//! cgroup v2 management for zone isolation.
//!
//! Each zone gets a cgroup at `/sys/fs/cgroup/rauha.slice/zone-{name}/`.
//! Resource limits are applied by writing to cgroup control files.
//! The cgroup_id (inode number) identifies the zone in BPF maps.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::{ResourcePolicy, ZoneStats};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const RAUHA_SLICE: &str = "rauha.slice";

pub struct CgroupManager {
    /// Path to the rauha slice: /sys/fs/cgroup/rauha.slice
    slice_path: PathBuf,
}

impl CgroupManager {
    /// Create a new CgroupManager, ensuring the rauha.slice exists.
    pub fn new() -> Result<Self> {
        let slice_path = PathBuf::from(CGROUP_ROOT).join(RAUHA_SLICE);

        // Verify cgroup v2 is mounted.
        if !Path::new(CGROUP_ROOT).join("cgroup.controllers").exists() {
            return Err(RauhaError::CgroupError {
                message: "cgroup v2 not available".into(),
                hint: "mount cgroup2 at /sys/fs/cgroup or boot with systemd.unified_cgroup_hierarchy=1".into(),
            });
        }

        // Create our slice if it doesn't exist.
        if !slice_path.exists() {
            fs::create_dir_all(&slice_path).map_err(|e| RauhaError::CgroupError {
                message: format!("failed to create {}: {e}", slice_path.display()),
                hint: "run rauhad as root".into(),
            })?;
        }

        // Enable controllers for child cgroups (zones).
        // Without this, zone cgroups can't use cpu.weight, memory.max, etc.
        let subtree_control = slice_path.join("cgroup.subtree_control");
        if let Err(e) = fs::write(&subtree_control, "+cpu +memory +pids +io") {
            tracing::warn!(
                %e,
                "failed to enable cgroup controllers in rauha.slice — \
                 resource limits may not work. Check that parent cgroup has \
                 controllers delegated."
            );
        }

        Ok(Self { slice_path })
    }

    /// Create a cgroup for a zone. Returns the cgroup_id (inode number).
    pub fn create_zone_cgroup(&self, zone_name: &str) -> Result<u64> {
        let path = self.zone_path(zone_name);

        if path.exists() {
            return Err(RauhaError::CgroupError {
                message: format!("cgroup already exists: {}", path.display()),
                hint: format!("run: rmdir {}", path.display()),
            });
        }

        fs::create_dir(&path).map_err(|e| RauhaError::CgroupError {
            message: format!("failed to create cgroup {}: {e}", path.display()),
            hint: "run rauhad as root".into(),
        })?;

        self.cgroup_id(&path)
    }

    /// Destroy a zone's cgroup. The cgroup must be empty (no processes).
    pub fn destroy_zone_cgroup(&self, zone_name: &str) -> Result<()> {
        let path = self.zone_path(zone_name);

        if !path.exists() {
            return Ok(()); // Already gone, idempotent.
        }

        fs::remove_dir(&path).map_err(|e| RauhaError::CgroupError {
            message: format!("failed to remove cgroup {}: {e}", path.display()),
            hint: "ensure no processes remain in the zone (check cgroup.procs)".into(),
        })?;

        Ok(())
    }

    /// Apply resource limits to a zone's cgroup.
    pub fn apply_resources(&self, zone_name: &str, resources: &ResourcePolicy) -> Result<()> {
        let path = self.zone_path(zone_name);

        if !path.exists() {
            return Err(RauhaError::CgroupError {
                message: format!("cgroup does not exist: {}", path.display()),
                hint: "create the zone first".into(),
            });
        }

        // cpu.weight: 1-10000, default 100. cgroup v2 uses "weight" not "shares".
        // Convert cpu_shares (sysfs convention: 2-262144, default 1024) to weight (1-10000).
        let weight = shares_to_weight(resources.cpu_shares);
        write_cgroup_file(&path, "cpu.weight", &weight.to_string())?;

        // memory.max: bytes or "max" for unlimited.
        if resources.memory_limit == 0 || resources.memory_limit == u64::MAX {
            write_cgroup_file(&path, "memory.max", "max")?;
        } else {
            write_cgroup_file(&path, "memory.max", &resources.memory_limit.to_string())?;
        }

        // pids.max: count or "max".
        if resources.pids_max == 0 || resources.pids_max == u64::MAX {
            write_cgroup_file(&path, "pids.max", "max")?;
        } else {
            write_cgroup_file(&path, "pids.max", &resources.pids_max.to_string())?;
        }

        // io.weight: 1-10000, default 100.
        let io_weight = resources.io_weight.clamp(1, 10000);
        write_cgroup_file(&path, "io.weight", &format!("default {io_weight}"))?;

        Ok(())
    }

    /// Read runtime stats from a zone's cgroup.
    pub fn read_stats(&self, zone_name: &str, zone_id: uuid::Uuid) -> Result<ZoneStats> {
        let path = self.zone_path(zone_name);

        if !path.exists() {
            return Err(RauhaError::CgroupError {
                message: format!("cgroup does not exist: {}", path.display()),
                hint: "create the zone first".into(),
            });
        }

        let memory_current = read_cgroup_u64(&path, "memory.current").unwrap_or(0);
        let memory_limit = read_cgroup_u64(&path, "memory.max").unwrap_or(0);
        let pids_current = read_cgroup_u64(&path, "pids.current").unwrap_or(0);
        let cpu_usage = read_cpu_usage(&path).unwrap_or(0.0);

        Ok(ZoneStats {
            zone_id,
            container_count: 0, // Filled by caller.
            cpu_usage_percent: cpu_usage,
            memory_usage_bytes: memory_current,
            memory_limit_bytes: memory_limit,
            network_rx_bytes: 0, // Requires netns stats — Phase 2.10.
            network_tx_bytes: 0,
            pids_current,
        })
    }

    /// Get the cgroup_id (inode number) for a zone's cgroup.
    pub fn cgroup_id_for_zone(&self, zone_name: &str) -> Result<u64> {
        let path = self.zone_path(zone_name);
        self.cgroup_id(&path)
    }

    /// Check if a zone's cgroup exists.
    pub fn zone_cgroup_exists(&self, zone_name: &str) -> bool {
        self.zone_path(zone_name).exists()
    }

    fn zone_path(&self, zone_name: &str) -> PathBuf {
        self.slice_path.join(format!("zone-{zone_name}"))
    }

    fn cgroup_id(&self, path: &Path) -> Result<u64> {
        let meta = fs::metadata(path).map_err(|e| RauhaError::CgroupError {
            message: format!("failed to stat {}: {e}", path.display()),
            hint: "check cgroup filesystem is mounted".into(),
        })?;
        // On cgroupfs, st_ino is the cgroup_id used by bpf_get_current_cgroup_id().
        Ok(meta.ino())
    }
}

/// Convert Docker-style cpu_shares (2-262144, default 1024) to cgroup v2 weight (1-10000, default 100).
fn shares_to_weight(shares: u64) -> u64 {
    if shares == 0 {
        return 100; // default
    }
    // Linear mapping: shares/1024 * 100, clamped to [1, 10000].
    let weight = (shares * 100) / 1024;
    weight.clamp(1, 10000)
}

fn write_cgroup_file(cgroup_path: &Path, filename: &str, value: &str) -> Result<()> {
    let file_path = cgroup_path.join(filename);
    fs::write(&file_path, value).map_err(|e| RauhaError::CgroupError {
        message: format!("failed to write {} to {}: {e}", value, file_path.display()),
        hint: format!("check that {} controller is enabled in the parent cgroup", filename.split('.').next().unwrap_or("unknown")),
    })?;
    Ok(())
}

fn read_cgroup_u64(cgroup_path: &Path, filename: &str) -> Option<u64> {
    let content = fs::read_to_string(cgroup_path.join(filename)).ok()?;
    let trimmed = content.trim();
    if trimmed == "max" {
        return Some(u64::MAX);
    }
    trimmed.parse().ok()
}

/// Read cumulative CPU usage from cgroup cpu.stat.
///
/// Returns cumulative CPU seconds (NOT a percentage). The field is named
/// `cpu_usage_percent` in the proto for historical reasons but contains
/// cumulative seconds. Callers computing real utilization need two samples
/// and the elapsed wall time: `(sample2 - sample1) / elapsed * 100`.
fn read_cpu_usage(cgroup_path: &Path) -> Option<f64> {
    let content = fs::read_to_string(cgroup_path.join("cpu.stat")).ok()?;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("usage_usec ") {
            let usec: u64 = value.trim().parse().ok()?;
            return Some(usec as f64 / 1_000_000.0);
        }
    }
    Some(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shares_to_weight() {
        assert_eq!(shares_to_weight(1024), 100); // default
        assert_eq!(shares_to_weight(512), 50);
        assert_eq!(shares_to_weight(2048), 200);
        assert_eq!(shares_to_weight(0), 100); // zero → default
        assert_eq!(shares_to_weight(1), 1); // minimum clamp
    }
}
