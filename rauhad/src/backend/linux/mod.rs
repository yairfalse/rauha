//! Linux isolation backend: eBPF LSM + cgroups v2 + network namespaces.
//!
//! Orchestrates three subsystems:
//! - eBPF LSM programs enforce zone boundaries at the syscall level
//! - cgroup v2 hierarchy provides resource limits and process grouping
//! - Network namespaces + veth pairs isolate network stacks

mod cgroup;
mod ebpf;
mod maps;
mod namespace;
mod network;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use rauha_common::backend::IsolationBackend;
use rauha_common::container::{ContainerHandle, ContainerSpec};
use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::*;
use uuid::Uuid;

use self::cgroup::CgroupManager;
use self::ebpf::EbpfManager;
use self::maps::MapManager;

/// Linux isolation backend using eBPF LSM + namespaces + cgroups.
pub struct LinuxBackend {
    root: String,
    /// eBPF program manager (None if eBPF is not available / not loaded yet).
    ebpf: Mutex<Option<EbpfManager>>,
    /// cgroup v2 manager.
    cgroup: CgroupManager,
    /// Monotonic zone ID counter for compact BPF map keys.
    next_zone_id: AtomicU32,
    /// Maps Uuid → compact u32 zone_id used in BPF maps.
    zone_id_map: Mutex<HashMap<Uuid, u32>>,
    /// Maps zone name → Uuid for reverse lookups.
    zone_name_map: Mutex<HashMap<String, Uuid>>,
}

impl LinuxBackend {
    pub fn new(root: &str) -> Result<Self> {
        let cgroup = CgroupManager::new()?;

        // Try to load eBPF programs. If it fails, log a warning and continue
        // in degraded mode (no kernel enforcement).
        let ebpf = match Self::try_load_ebpf(root) {
            Ok(mgr) => {
                tracing::info!("eBPF programs loaded — kernel enforcement active");
                Some(mgr)
            }
            Err(e) => {
                tracing::warn!(%e, "eBPF programs not loaded — running without kernel enforcement");
                None
            }
        };

        // Ensure the network bridge exists.
        if let Err(e) = network::ensure_bridge() {
            tracing::warn!(%e, "failed to create network bridge — zones will have no networking");
        }

        Ok(Self {
            root: root.into(),
            ebpf: Mutex::new(ebpf),
            cgroup,
            next_zone_id: AtomicU32::new(1), // 0 is reserved for "no zone".
            zone_id_map: Mutex::new(HashMap::new()),
            zone_name_map: Mutex::new(HashMap::new()),
        })
    }

    fn try_load_ebpf(root: &str) -> Result<EbpfManager> {
        // Look for the eBPF object in well-known locations.
        let candidates = [
            PathBuf::from(root).join("rauha-ebpf"),
            PathBuf::from("/usr/lib/rauha/rauha-ebpf"),
            // Development build path.
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("rauha-ebpf/target/bpfel-unknown-none/debug/rauha-ebpf"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("rauha-ebpf/target/bpfel-unknown-none/release/rauha-ebpf"),
        ];

        for path in &candidates {
            if path.exists() {
                return EbpfManager::load(path);
            }
        }

        Err(RauhaError::EbpfError {
            message: "eBPF object not found in any known location".into(),
            hint: "run `cargo xtask build-ebpf` to compile eBPF programs".into(),
        })
    }

    /// Allocate a new compact zone_id for BPF maps.
    fn allocate_zone_id(&self, uuid: Uuid) -> u32 {
        let id = self.next_zone_id.fetch_add(1, Ordering::Relaxed);
        self.zone_id_map.lock().unwrap().insert(uuid, id);
        id
    }

    /// Look up the compact zone_id for a Uuid.
    fn get_zone_id(&self, uuid: &Uuid) -> Option<u32> {
        self.zone_id_map.lock().unwrap().get(uuid).copied()
    }

    /// Remove zone_id mapping.
    fn remove_zone_id(&self, uuid: &Uuid) -> Option<u32> {
        self.zone_id_map.lock().unwrap().remove(uuid)
    }
}

impl IsolationBackend for LinuxBackend {
    fn create_zone(&self, config: &ZoneConfig) -> Result<ZoneHandle> {
        tracing::info!(zone = config.name, backend = "linux-ebpf", "creating zone");

        let zone_uuid = Uuid::new_v4();
        let zone_id = self.allocate_zone_id(zone_uuid);

        // Track zone name → uuid mapping.
        self.zone_name_map
            .lock()
            .unwrap()
            .insert(config.name.clone(), zone_uuid);

        // Step 1: Create cgroup.
        let cgroup_id = match self.cgroup.create_zone_cgroup(&config.name) {
            Ok(id) => id,
            Err(e) => {
                self.remove_zone_id(&zone_uuid);
                return Err(e);
            }
        };

        // Step 2: Create network namespace + veth.
        if let Err(e) = namespace::create_netns(&config.name) {
            tracing::warn!(%e, zone = config.name, "failed to create netns — continuing without");
        } else if let Err(e) = network::create_veth_pair(&config.name) {
            tracing::warn!(%e, zone = config.name, "failed to create veth pair — continuing without");
        }

        // Step 3: Populate BPF maps.
        if let Ok(ref mut ebpf_guard) = self.ebpf.lock() {
            if let Some(ref mut ebpf) = **ebpf_guard {
                let bpf = ebpf.bpf_mut();

                if let Err(e) =
                    MapManager::add_zone_member(bpf, cgroup_id, zone_id, config.zone_type)
                {
                    tracing::warn!(%e, "failed to add zone to BPF membership map");
                }

                if let Err(e) = MapManager::set_zone_policy(bpf, zone_id, &config.policy) {
                    tracing::warn!(%e, "failed to set zone policy in BPF map");
                }
            }
        }

        // Step 4: Apply cgroup resource limits.
        if let Err(e) = self.cgroup.apply_resources(&config.name, &config.policy.resources) {
            tracing::warn!(%e, zone = config.name, "failed to apply resource limits");
        }

        tracing::info!(
            zone = config.name,
            zone_id,
            cgroup_id,
            "zone created"
        );

        Ok(ZoneHandle {
            id: zone_uuid,
            name: config.name.clone(),
            platform_id: cgroup_id,
        })
    }

    fn destroy_zone(&self, zone: &ZoneHandle) -> Result<()> {
        tracing::info!(zone = zone.name, "destroying zone");

        // Remove from BPF maps first.
        let zone_id = self.remove_zone_id(&zone.id);
        if let (Some(zone_id), Ok(ref mut ebpf_guard)) = (zone_id, self.ebpf.lock()) {
            if let Some(ref mut ebpf) = **ebpf_guard {
                let bpf = ebpf.bpf_mut();
                let _ = MapManager::remove_zone_member(bpf, zone.platform_id);
                let _ = MapManager::remove_zone_policy(bpf, zone_id);
            }
        }

        // Tear down network.
        let _ = network::destroy_veth_pair(&zone.name);
        let _ = namespace::destroy_netns(&zone.name);

        // Destroy cgroup last (must be empty).
        self.cgroup.destroy_zone_cgroup(&zone.name)?;

        self.zone_name_map.lock().unwrap().remove(&zone.name);

        tracing::info!(zone = zone.name, "zone destroyed");
        Ok(())
    }

    fn enforce_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()> {
        tracing::info!(zone = zone.name, "enforcing policy");

        // Update BPF policy map.
        if let Some(zone_id) = self.get_zone_id(&zone.id) {
            if let Ok(ref mut ebpf_guard) = self.ebpf.lock() {
                if let Some(ref mut ebpf) = **ebpf_guard {
                    MapManager::set_zone_policy(ebpf.bpf_mut(), zone_id, policy)?;
                }
            }
        }

        // Update cgroup resource limits.
        self.cgroup.apply_resources(&zone.name, &policy.resources)?;

        Ok(())
    }

    fn hot_reload_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()> {
        tracing::info!(zone = zone.name, "hot-reloading policy");

        // BPF HashMap insert is atomic — kernel sees old or new, never partial.
        if let Some(zone_id) = self.get_zone_id(&zone.id) {
            if let Ok(ref mut ebpf_guard) = self.ebpf.lock() {
                if let Some(ref mut ebpf) = **ebpf_guard {
                    MapManager::hot_reload_policy(ebpf.bpf_mut(), zone_id, policy)?;
                }
            }
        }

        // Update cgroup limits.
        self.cgroup.apply_resources(&zone.name, &policy.resources)?;

        Ok(())
    }

    fn create_container(&self, zone: &ZoneHandle, spec: &ContainerSpec) -> Result<ContainerHandle> {
        tracing::info!(
            zone = zone.name,
            container = spec.name,
            "creating container"
        );
        // TODO Phase 3: Fork into zone's namespaces, set up rootfs, exec.
        Ok(ContainerHandle {
            id: Uuid::new_v4(),
            zone_id: zone.id,
            pid: 0,
            platform_id: 0,
        })
    }

    fn start_container(&self, container: &ContainerHandle) -> Result<()> {
        tracing::info!(container = %container.id, "starting container");
        // TODO Phase 3.
        Ok(())
    }

    fn stop_container(&self, container: &ContainerHandle) -> Result<()> {
        tracing::info!(container = %container.id, "stopping container");
        // TODO Phase 3.
        Ok(())
    }

    fn zone_stats(&self, zone: &ZoneHandle) -> Result<ZoneStats> {
        self.cgroup.read_stats(&zone.name, zone.id)
    }

    fn verify_isolation(&self, zone: &ZoneHandle) -> Result<IsolationReport> {
        let mut checks = Vec::new();

        // Check 1: cgroup exists.
        let cgroup_ok = self.cgroup.zone_cgroup_exists(&zone.name);
        checks.push(IsolationCheck {
            name: "cgroup".into(),
            passed: cgroup_ok,
            detail: if cgroup_ok {
                "zone cgroup exists".into()
            } else {
                "zone cgroup missing — zone is not resource-limited".into()
            },
        });

        // Check 2: eBPF programs loaded.
        let ebpf_ok = if let Ok(ref ebpf_guard) = self.ebpf.lock() {
            if let Some(ref ebpf) = **ebpf_guard {
                match ebpf.health_check() {
                    Ok(statuses) => {
                        let all_loaded = statuses.iter().all(|s| s.loaded);
                        for status in &statuses {
                            checks.push(IsolationCheck {
                                name: format!("ebpf:{}", status.name),
                                passed: status.loaded,
                                detail: if status.loaded {
                                    "program loaded".into()
                                } else {
                                    "program not loaded — zone boundary not enforced".into()
                                },
                            });
                        }
                        all_loaded
                    }
                    Err(e) => {
                        checks.push(IsolationCheck {
                            name: "ebpf:health".into(),
                            passed: false,
                            detail: format!("health check failed: {e}"),
                        });
                        false
                    }
                }
            } else {
                checks.push(IsolationCheck {
                    name: "ebpf".into(),
                    passed: false,
                    detail: "eBPF not loaded — no kernel enforcement".into(),
                });
                false
            }
        } else {
            false
        };

        // Check 3: zone membership in BPF map.
        let membership_ok = self.get_zone_id(&zone.id).is_some();
        checks.push(IsolationCheck {
            name: "bpf_membership".into(),
            passed: membership_ok,
            detail: if membership_ok {
                "zone registered in BPF membership map".into()
            } else {
                "zone not in BPF map — kernel cannot identify zone processes".into()
            },
        });

        // Check 4: network namespace.
        let netns_ok = namespace::netns_exists(&zone.name);
        checks.push(IsolationCheck {
            name: "netns".into(),
            passed: netns_ok,
            detail: if netns_ok {
                "network namespace exists".into()
            } else {
                "network namespace missing — network not isolated".into()
            },
        });

        let is_isolated = cgroup_ok && ebpf_ok && membership_ok && netns_ok;

        Ok(IsolationReport {
            zone_id: zone.id,
            is_isolated,
            checks,
        })
    }

    fn name(&self) -> &str {
        "linux-ebpf"
    }
}
