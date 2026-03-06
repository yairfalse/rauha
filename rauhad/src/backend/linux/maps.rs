//! Typed wrappers for BPF map operations.
//!
//! Translates domain concepts (zones, policies, inodes) into BPF map
//! key/value pairs. All BPF map access goes through MapManager.

use aya::maps::HashMap as AyaHashMap;
use aya::Bpf;

use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::{ZonePolicy, ZoneType};
use rauha_ebpf_common::*;

pub struct MapManager;

impl MapManager {
    /// Register a cgroup as belonging to a zone.
    pub fn add_zone_member(
        bpf: &mut Bpf,
        cgroup_id: u64,
        zone_id: u32,
        zone_type: ZoneType,
    ) -> Result<()> {
        let mut flags = 0u32;
        match zone_type {
            ZoneType::Global => flags |= ZONE_FLAG_GLOBAL,
            ZoneType::Privileged => flags |= ZONE_FLAG_PRIVILEGED,
            ZoneType::NonGlobal => {}
        }

        let info = ZoneInfoKernel { zone_id, flags };

        let mut map: AyaHashMap<_, u64, ZoneInfoKernel> =
            AyaHashMap::try_from(bpf.map_mut("ZONE_MEMBERSHIP").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "ZONE_MEMBERSHIP map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open ZONE_MEMBERSHIP map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        map.insert(cgroup_id, info, 0).map_err(|e| RauhaError::EbpfError {
            message: format!("failed to insert zone membership: {e}"),
            hint: "map may be full (check MAX_CGROUPS)".into(),
        })?;

        tracing::debug!(cgroup_id, zone_id, "added zone member to BPF map");
        Ok(())
    }

    /// Remove a cgroup from zone membership.
    pub fn remove_zone_member(bpf: &mut Bpf, cgroup_id: u64) -> Result<()> {
        let mut map: AyaHashMap<_, u64, ZoneInfoKernel> =
            AyaHashMap::try_from(bpf.map_mut("ZONE_MEMBERSHIP").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "ZONE_MEMBERSHIP map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open ZONE_MEMBERSHIP map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        map.remove(&cgroup_id).map_err(|e| RauhaError::EbpfError {
            message: format!("failed to remove zone membership: {e}"),
            hint: "entry may not exist".into(),
        })?;

        Ok(())
    }

    /// Set the enforcement policy for a zone in the BPF map.
    pub fn set_zone_policy(bpf: &mut Bpf, zone_id: u32, policy: &ZonePolicy) -> Result<()> {
        let kernel_policy = policy_to_kernel(policy);

        let mut map: AyaHashMap<_, u32, ZonePolicyKernel> =
            AyaHashMap::try_from(bpf.map_mut("ZONE_POLICY").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "ZONE_POLICY map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open ZONE_POLICY map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        map.insert(zone_id, kernel_policy, 0).map_err(|e| RauhaError::EbpfError {
            message: format!("failed to insert zone policy: {e}"),
            hint: "map may be full (check MAX_ZONES)".into(),
        })?;

        tracing::debug!(zone_id, caps_mask = kernel_policy.caps_mask, "set zone policy in BPF map");
        Ok(())
    }

    /// Remove a zone's policy from BPF maps.
    pub fn remove_zone_policy(bpf: &mut Bpf, zone_id: u32) -> Result<()> {
        let mut map: AyaHashMap<_, u32, ZonePolicyKernel> =
            AyaHashMap::try_from(bpf.map_mut("ZONE_POLICY").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "ZONE_POLICY map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open ZONE_POLICY map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        let _ = map.remove(&zone_id); // Ignore error if already removed.
        Ok(())
    }

    /// Track an inode as belonging to a zone.
    pub fn set_inode_zone(bpf: &mut Bpf, inode: u64, zone_id: u32) -> Result<()> {
        let mut map: AyaHashMap<_, u64, u32> =
            AyaHashMap::try_from(bpf.map_mut("INODE_ZONE_MAP").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "INODE_ZONE_MAP map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open INODE_ZONE_MAP map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        map.insert(inode, zone_id, 0).map_err(|e| RauhaError::EbpfError {
            message: format!("failed to insert inode zone mapping: {e}"),
            hint: "map may be full (check MAX_INODES)".into(),
        })?;

        Ok(())
    }

    /// Remove an inode from zone tracking.
    pub fn remove_inode_zone(bpf: &mut Bpf, inode: u64) -> Result<()> {
        let mut map: AyaHashMap<_, u64, u32> =
            AyaHashMap::try_from(bpf.map_mut("INODE_ZONE_MAP").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "INODE_ZONE_MAP map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open INODE_ZONE_MAP map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        let _ = map.remove(&inode);
        Ok(())
    }

    /// Allow cross-zone communication between two zones.
    pub fn allow_zone_comm(bpf: &mut Bpf, src_zone: u32, dst_zone: u32) -> Result<()> {
        let key = ZoneCommKey { src_zone, dst_zone };

        let mut map: AyaHashMap<_, ZoneCommKey, u8> =
            AyaHashMap::try_from(bpf.map_mut("ZONE_ALLOWED_COMMS").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "ZONE_ALLOWED_COMMS map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open ZONE_ALLOWED_COMMS map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        map.insert(key, 1u8, 0).map_err(|e| RauhaError::EbpfError {
            message: format!("failed to allow zone comm {src_zone} -> {dst_zone}: {e}"),
            hint: "map may be full".into(),
        })?;

        tracing::debug!(src_zone, dst_zone, "allowed cross-zone communication");
        Ok(())
    }

    /// Deny cross-zone communication between two zones.
    pub fn deny_zone_comm(bpf: &mut Bpf, src_zone: u32, dst_zone: u32) -> Result<()> {
        let key = ZoneCommKey { src_zone, dst_zone };

        let mut map: AyaHashMap<_, ZoneCommKey, u8> =
            AyaHashMap::try_from(bpf.map_mut("ZONE_ALLOWED_COMMS").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "ZONE_ALLOWED_COMMS map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open ZONE_ALLOWED_COMMS map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        let _ = map.remove(&key);
        Ok(())
    }

    /// Atomically update a zone's policy (hot reload).
    /// BPF HashMap::insert is atomic — the kernel sees either the old or new value, never partial.
    pub fn hot_reload_policy(bpf: &mut Bpf, zone_id: u32, policy: &ZonePolicy) -> Result<()> {
        Self::set_zone_policy(bpf, zone_id, policy)?;
        tracing::info!(zone_id, "hot-reloaded zone policy in BPF map");
        Ok(())
    }
}

/// Convert userspace ZonePolicy to kernel-side ZonePolicyKernel.
fn policy_to_kernel(policy: &ZonePolicy) -> ZonePolicyKernel {
    let caps_mask = caps_to_mask(&policy.capabilities.allowed);

    let mut flags = 0u32;
    // Allow ptrace if SYS_PTRACE capability is granted.
    if policy.capabilities.allowed.iter().any(|c| {
        let upper = c.to_uppercase();
        upper == "CAP_SYS_PTRACE" || upper == "SYS_PTRACE"
    }) {
        flags |= POLICY_FLAG_ALLOW_PTRACE;
    }

    if policy.network.mode == rauha_common::zone::NetworkMode::Host {
        flags |= POLICY_FLAG_ALLOW_HOST_NET;
    }

    ZonePolicyKernel {
        caps_mask,
        flags,
        _pad: 0,
    }
}
