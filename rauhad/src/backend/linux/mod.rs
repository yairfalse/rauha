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
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use rauha_common::backend::IsolationBackend;
use rauha_common::container::{ContainerHandle, ContainerSpec};
use rauha_common::error::{RauhaError, Result};
use rauha_common::shim::{self, ShimRequest, ShimResponse};
use rauha_common::zone::*;
use uuid::Uuid;

use self::cgroup::CgroupManager;
use self::ebpf::EbpfManager;
use self::maps::MapManager;

/// Connection to a zone's shim process via Unix socket.
struct ShimConnection {
    socket_path: PathBuf,
}

impl ShimConnection {
    fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Send a request to the shim and receive a response.
    fn send_request(&self, request: &ShimRequest) -> Result<ShimResponse> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|e| {
            RauhaError::ShimError {
                zone: self.socket_path.display().to_string(),
                message: format!("failed to connect to shim: {e}"),
            }
        })?;

        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .ok();

        shim::encode_to(&mut stream, request).map_err(|e| RauhaError::ShimError {
            zone: self.socket_path.display().to_string(),
            message: format!("failed to send request: {e}"),
        })?;

        shim::decode_from::<ShimResponse>(&mut stream).map_err(|e| RauhaError::ShimError {
            zone: self.socket_path.display().to_string(),
            message: format!("failed to read response: {e}"),
        })
    }
}

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
    /// Shim connections per zone.
    shim_connections: Mutex<HashMap<String, ShimConnection>>,
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
            shim_connections: Mutex::new(HashMap::new()),
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

    /// Get the socket path for a zone's shim.
    fn shim_socket_path(zone_name: &str) -> PathBuf {
        PathBuf::from(format!("/run/rauha/shim-{zone_name}.sock"))
    }

    /// Ensure a shim process is running for a zone, spawning one if needed.
    fn ensure_shim(&self, zone_name: &str) -> Result<()> {
        let socket_path = Self::shim_socket_path(zone_name);

        // Check if shim is already connected and responsive.
        {
            let conns = self.shim_connections.lock().unwrap();
            if let Some(conn) = conns.get(zone_name) {
                // Try a quick health check.
                if conn
                    .send_request(&ShimRequest::GetState {
                        id: "__ping__".into(),
                    })
                    .is_ok()
                {
                    return Ok(());
                }
            }
        }

        // If socket exists but shim is dead, remove the stale socket.
        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }

        // Spawn shim process.
        let rootfs_root = PathBuf::from(&self.root).join("zones").join(zone_name);
        std::fs::create_dir_all(&rootfs_root).map_err(|e| RauhaError::ShimError {
            zone: zone_name.into(),
            message: format!("failed to create zone dir: {e}"),
        })?;

        // Ensure /run/rauha exists.
        std::fs::create_dir_all("/run/rauha").ok();

        let shim_bin = find_shim_binary()?;

        Command::new(&shim_bin)
            .arg("--zone-name")
            .arg(zone_name)
            .arg("--socket")
            .arg(&socket_path)
            .arg("--rootfs-root")
            .arg(&rootfs_root)
            .spawn()
            .map_err(|e| RauhaError::ShimError {
                zone: zone_name.into(),
                message: format!("failed to spawn shim: {e}"),
            })?;

        // Wait for socket to appear.
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        if !socket_path.exists() {
            return Err(RauhaError::ShimError {
                zone: zone_name.into(),
                message: "shim socket did not appear after spawn".into(),
            });
        }

        // Register connection.
        let conn = ShimConnection::new(socket_path);
        self.shim_connections
            .lock()
            .unwrap()
            .insert(zone_name.to_string(), conn);

        tracing::info!(zone = zone_name, "shim spawned");
        Ok(())
    }

    /// Send a request to a zone's shim.
    fn shim_request(&self, zone_name: &str, request: &ShimRequest) -> Result<ShimResponse> {
        let conns = self.shim_connections.lock().unwrap();
        let conn = conns.get(zone_name).ok_or_else(|| RauhaError::ShimError {
            zone: zone_name.into(),
            message: "no shim connection".into(),
        })?;
        conn.send_request(request)
    }
}

/// Find the rauha-shim binary.
fn find_shim_binary() -> Result<PathBuf> {
    let candidates = [
        // Same directory as the running binary.
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("rauha-shim"))),
        // System path.
        Some(PathBuf::from("/usr/local/bin/rauha-shim")),
        Some(PathBuf::from("/usr/bin/rauha-shim")),
    ];

    for candidate in candidates.iter().flatten() {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    Err(RauhaError::ShimError {
        zone: String::new(),
        message: "rauha-shim binary not found".into(),
    })
}

impl IsolationBackend for LinuxBackend {
    fn recover_zone(&self, zone: &ZoneHandle, zone_type: ZoneType, policy: &ZonePolicy) -> Result<()> {
        tracing::info!(zone = zone.name, "recovering zone state from metadata");

        // Allocate a compact zone_id (these are ephemeral, not persisted).
        let zone_id = self.allocate_zone_id(zone.id);
        self.zone_name_map
            .lock()
            .unwrap()
            .insert(zone.name.clone(), zone.id);

        // Re-create cgroup if missing (idempotent).
        let cgroup_id = if self.cgroup.zone_cgroup_exists(&zone.name) {
            self.cgroup.cgroup_id_for_zone(&zone.name)?
        } else {
            self.cgroup.create_zone_cgroup(&zone.name)?
        };

        // Re-apply resource limits.
        if let Err(e) = self.cgroup.apply_resources(&zone.name, &policy.resources) {
            tracing::warn!(%e, zone = zone.name, "failed to re-apply resource limits during recovery");
        }

        // Re-create netns if missing (idempotent).
        if !namespace::netns_exists(&zone.name) {
            if let Err(e) = namespace::create_netns(&zone.name) {
                tracing::warn!(%e, zone = zone.name, "failed to re-create netns during recovery");
            }
        }

        // Re-populate BPF maps.
        if let Ok(ref mut ebpf_guard) = self.ebpf.lock() {
            if let Some(ref mut ebpf) = **ebpf_guard {
                let bpf = ebpf.bpf_mut();
                if let Err(e) = MapManager::add_zone_member(bpf, cgroup_id, zone_id, zone_type) {
                    tracing::warn!(%e, zone = zone.name, "failed to re-add zone to BPF map during recovery");
                }
                if let Err(e) = MapManager::set_zone_policy(bpf, zone_id, policy) {
                    tracing::warn!(%e, zone = zone.name, "failed to re-set zone policy during recovery");
                }
            }
        }

        tracing::info!(zone = zone.name, zone_id, cgroup_id, "zone recovered");
        Ok(())
    }

    fn cleanup_orphans(&self, known_zones: &[ZoneHandle]) -> Result<()> {
        let known_names: std::collections::HashSet<&str> =
            known_zones.iter().map(|z| z.name.as_str()).collect();

        // Clean up orphaned cgroups under rauha.slice/.
        let slice_path = std::path::Path::new("/sys/fs/cgroup/rauha.slice");
        if slice_path.exists() {
            if let Ok(entries) = std::fs::read_dir(slice_path) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if let Some(zone_name) = name_str.strip_prefix("zone-") {
                        if !known_names.contains(zone_name) {
                            tracing::warn!(cgroup = %name_str, "cleaning up orphaned cgroup");
                            let _ = self.cgroup.destroy_zone_cgroup(zone_name);
                        }
                    }
                }
            }
        }

        // Clean up orphaned network namespaces.
        let netns_dir = std::path::Path::new("/var/run/netns");
        if netns_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(netns_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if let Some(zone_name) = name_str.strip_prefix("rauha-") {
                        if !known_names.contains(zone_name) {
                            tracing::warn!(netns = %name_str, "cleaning up orphaned netns");
                            let _ = namespace::destroy_netns(zone_name);
                        }
                    }
                }
            }
        }

        Ok(())
    }

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

        // Shut down shim if running.
        {
            let mut conns = self.shim_connections.lock().unwrap();
            if let Some(conn) = conns.remove(&zone.name) {
                let _ = conn.send_request(&ShimRequest::Shutdown);
            }
        }

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

        // Clean up shim socket.
        let socket_path = Self::shim_socket_path(&zone.name);
        let _ = std::fs::remove_file(&socket_path);

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

        // Ensure shim is running for this zone.
        self.ensure_shim(&zone.name)?;

        let container_id = Uuid::new_v4();

        // Prepare rootfs for this container.
        // If overlay_layers is available, mount overlayfs (O(1) creation).
        // Otherwise, fall back to copying the base rootfs.
        let container_dir = PathBuf::from(&self.root)
            .join("zones")
            .join(&zone.name)
            .join("containers")
            .join(container_id.to_string());

        let rootfs_dir = if let Some(ref overlay_layers) = spec.overlay_layers {
            let snapshotter = rauha_oci::snapshotter::OverlayfsSnapshotter::new(
                &PathBuf::from(&self.root).join("zones").join(&zone.name),
            );
            snapshotter.mount_overlay(
                &container_id.to_string(),
                overlay_layers,
                &container_dir,
            )?
        } else if let Some(ref base_rootfs) = spec.rootfs_path {
            let rootfs_dir = container_dir.join("rootfs");
            copy_dir_recursive(base_rootfs, &rootfs_dir)?;
            rootfs_dir
        } else {
            let rootfs_dir = container_dir.join("rootfs");
            std::fs::create_dir_all(&rootfs_dir).map_err(|e| RauhaError::RootfsError {
                message: format!("failed to create rootfs dir: {e}"),
            })?;
            rootfs_dir
        };

        // Generate OCI runtime spec.
        let spec_json = serde_json::to_string(
            &oci_spec::runtime::SpecBuilder::default()
                .version("1.0.2")
                .root(
                    oci_spec::runtime::RootBuilder::default()
                        .path(rootfs_dir.to_string_lossy().as_ref())
                        .readonly(false)
                        .build()
                        .unwrap(),
                )
                .process(
                    oci_spec::runtime::ProcessBuilder::default()
                        .args(if spec.command.is_empty() {
                            vec!["/bin/sh".to_string()]
                        } else {
                            spec.command.clone()
                        })
                        .env(
                            spec.env
                                .iter()
                                .map(|(k, v)| format!("{k}={v}"))
                                .chain(std::iter::once(
                                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
                                ))
                                .collect::<Vec<_>>(),
                        )
                        .cwd(spec.working_dir.as_deref().unwrap_or("/"))
                        .terminal(false)
                        .build()
                        .unwrap(),
                )
                .hostname(spec.name.clone())
                .build()
                .unwrap(),
        )
        .map_err(|e| RauhaError::BackendError(format!("failed to serialize spec: {e}")))?;

        // Send CreateContainer to shim.
        let response = self.shim_request(
            &zone.name,
            &ShimRequest::CreateContainer {
                id: container_id.to_string(),
                spec_json,
            },
        )?;

        match response {
            ShimResponse::Created { pid } | ShimResponse::Ok => Ok(ContainerHandle {
                id: container_id,
                zone_id: zone.id,
                pid: match response {
                    ShimResponse::Created { pid } => pid,
                    _ => 0,
                },
                platform_id: 0,
            }),
            ShimResponse::Error { message } => Err(RauhaError::ShimError {
                zone: zone.name.clone(),
                message,
            }),
            _ => Err(RauhaError::ShimError {
                zone: zone.name.clone(),
                message: "unexpected shim response".into(),
            }),
        }
    }

    fn start_container(&self, container: &ContainerHandle) -> Result<()> {
        tracing::info!(container = %container.id, "starting container");

        // Look up zone name for this container.
        let zone_name = self
            .zone_name_map
            .lock()
            .unwrap()
            .iter()
            .find(|(_, uuid)| **uuid == container.zone_id)
            .map(|(name, _)| name.clone())
            .ok_or_else(|| RauhaError::ShimError {
                zone: container.zone_id.to_string(),
                message: "zone not found for container".into(),
            })?;

        let response = self.shim_request(
            &zone_name,
            &ShimRequest::StartContainer {
                id: container.id.to_string(),
            },
        )?;

        match response {
            ShimResponse::Created { .. } | ShimResponse::Ok => Ok(()),
            ShimResponse::Error { message } => Err(RauhaError::ContainerExecError {
                container: container.id.to_string(),
                message,
            }),
            _ => Err(RauhaError::ShimError {
                zone: zone_name,
                message: "unexpected shim response".into(),
            }),
        }
    }

    fn stop_container(&self, container: &ContainerHandle) -> Result<()> {
        tracing::info!(container = %container.id, "stopping container");

        let zone_name = self
            .zone_name_map
            .lock()
            .unwrap()
            .iter()
            .find(|(_, uuid)| **uuid == container.zone_id)
            .map(|(name, _)| name.clone())
            .ok_or_else(|| RauhaError::ShimError {
                zone: container.zone_id.to_string(),
                message: "zone not found for container".into(),
            })?;

        // Send SIGTERM first.
        let response = self.shim_request(
            &zone_name,
            &ShimRequest::StopContainer {
                id: container.id.to_string(),
                signal: 15, // SIGTERM
            },
        )?;

        match response {
            ShimResponse::Ok => Ok(()),
            ShimResponse::Error { message } => {
                tracing::warn!(container = %container.id, %message, "SIGTERM failed, trying SIGKILL");
                // Try SIGKILL as fallback.
                let _ = self.shim_request(
                    &zone_name,
                    &ShimRequest::Signal {
                        id: container.id.to_string(),
                        signal: 9, // SIGKILL
                    },
                );
                Ok(())
            }
            _ => Ok(()),
        }
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
            model: IsolationModel::SyscallPolicy,
            is_isolated,
            checks,
        })
    }

    fn isolation_model(&self) -> IsolationModel {
        IsolationModel::SyscallPolicy
    }

    fn name(&self) -> &str {
        "linux-ebpf"
    }
}

/// Recursively copy a directory tree, preserving symlinks and file permissions.
///
/// Uses `symlink_metadata` to avoid following symlinks (OCI rootfs trees
/// commonly contain symlinks that must be preserved as-is).
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dst).map_err(|e| RauhaError::RootfsError {
        message: format!("failed to create dir {}: {e}", dst.display()),
    })?;

    for entry in std::fs::read_dir(src).map_err(|e| RauhaError::RootfsError {
        message: format!("failed to read dir {}: {e}", src.display()),
    })? {
        let entry = entry.map_err(|e| RauhaError::RootfsError {
            message: format!("failed to read entry: {e}"),
        })?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        // Use symlink_metadata to detect symlinks without following them.
        let meta = std::fs::symlink_metadata(&src_path).map_err(|e| RauhaError::RootfsError {
            message: format!("failed to stat {}: {e}", src_path.display()),
        })?;

        if meta.is_symlink() {
            let link_target =
                std::fs::read_link(&src_path).map_err(|e| RauhaError::RootfsError {
                    message: format!("failed to read symlink {}: {e}", src_path.display()),
                })?;
            std::os::unix::fs::symlink(&link_target, &dst_path).map_err(|e| {
                RauhaError::RootfsError {
                    message: format!(
                        "failed to create symlink {} → {}: {e}",
                        dst_path.display(),
                        link_target.display()
                    ),
                }
            })?;
        } else if meta.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path).map_err(|e| RauhaError::RootfsError {
                message: format!(
                    "failed to copy {} → {}: {e}",
                    src_path.display(),
                    dst_path.display()
                ),
            })?;
        }
    }

    // Preserve directory permissions.
    if let Ok(metadata) = std::fs::symlink_metadata(src) {
        let _ = std::fs::set_permissions(dst, metadata.permissions());
    }

    Ok(())
}
