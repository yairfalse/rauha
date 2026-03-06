use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A zone is the first-class isolation boundary. Every container belongs to exactly one zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    pub id: Uuid,
    pub name: String,
    pub zone_type: ZoneType,
    pub state: ZoneState,
    pub policy: ZonePolicy,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneType {
    /// The host system. Can see and manage all non-global zones.
    Global,
    /// Standard isolated zone.
    NonGlobal,
    /// Zone with elevated privileges (still isolated, but more capabilities).
    Privileged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneState {
    Creating,
    Ready,
    Running,
    Stopping,
    Stopped,
    Destroying,
}

/// Declarative policy defining what a zone can do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePolicy {
    pub capabilities: CapabilityPolicy,
    pub resources: ResourcePolicy,
    pub network: NetworkPolicy,
    pub filesystem: FilesystemPolicy,
    pub devices: DevicePolicy,
    pub syscalls: SyscallPolicy,
}

impl Default for ZonePolicy {
    fn default() -> Self {
        Self {
            capabilities: CapabilityPolicy::default(),
            resources: ResourcePolicy::default(),
            network: NetworkPolicy::default(),
            filesystem: FilesystemPolicy::default(),
            devices: DevicePolicy::default(),
            syscalls: SyscallPolicy::default(),
        }
    }
}

/// Allow-list only. Nothing not listed here is permitted.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CapabilityPolicy {
    pub allowed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePolicy {
    pub cpu_shares: u64,
    pub memory_limit: u64,
    pub io_weight: u16,
    pub pids_max: u64,
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            cpu_shares: 1024,
            memory_limit: 512 * 1024 * 1024, // 512Mi
            io_weight: 100,
            pids_max: 256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    Isolated,
    Bridged,
    Host,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub mode: NetworkMode,
    pub allowed_zones: Vec<String>,
    pub allowed_egress: Vec<String>,
    pub allowed_ingress: Vec<String>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Isolated,
            allowed_zones: Vec::new(),
            allowed_egress: Vec::new(),
            allowed_ingress: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    pub root: String,
    pub shared_layers: bool,
    pub writable_paths: Vec<String>,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            root: String::new(),
            shared_layers: true,
            writable_paths: vec!["/tmp".into(), "/var/log".into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DevicePolicy {
    pub allowed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyscallPolicy {
    pub deny: Vec<String>,
}

/// Configuration for creating a new zone.
#[derive(Debug, Clone)]
pub struct ZoneConfig {
    pub name: String,
    pub zone_type: ZoneType,
    pub policy: ZonePolicy,
}

/// Handle to a running zone, used by the isolation backend.
#[derive(Debug, Clone)]
pub struct ZoneHandle {
    pub id: Uuid,
    pub name: String,
    /// Platform-specific identifier (cgroup id on Linux, VM id on macOS).
    pub platform_id: u64,
}

/// Runtime statistics for a zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneStats {
    pub zone_id: Uuid,
    pub container_count: u32,
    pub cpu_usage_percent: f64,
    pub memory_usage_bytes: u64,
    pub memory_limit_bytes: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub pids_current: u64,
}

/// How the backend enforces isolation boundaries.
///
/// This matters: a caller interpreting enforcement events or evaluating
/// policy compliance must know whether isolation is per-syscall software
/// policy (Linux eBPF) or structural hardware boundary (macOS VM).
/// These are categorically different threat models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationModel {
    /// Per-syscall interception via eBPF LSM hooks. Enforcement is software
    /// policy — every file_open, kill, ptrace, exec is checked against zone
    /// membership maps. Relies on kernel BPF infrastructure being intact.
    /// Observability is granular (individual denied syscalls are visible).
    SyscallPolicy,
    /// Structural hardware boundary via hypervisor (VM). Isolation doesn't
    /// depend on intercepting individual syscalls — the VM boundary prevents
    /// cross-zone access structurally. Stronger isolation guarantee, but
    /// fewer per-operation observability hooks.
    HardwareBoundary,
}

/// Report from verifying zone isolation integrity.
///
/// The meaning of `is_isolated` depends on `model`:
/// - `SyscallPolicy`: all BPF programs loaded, maps consistent, cgroup exists
/// - `HardwareBoundary`: VM is running, sandbox profile applied
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationReport {
    pub zone_id: Uuid,
    pub model: IsolationModel,
    pub is_isolated: bool,
    pub checks: Vec<IsolationCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// TOML policy file format — deserialized from user-provided files.
#[derive(Debug, Deserialize)]
pub struct PolicyFile {
    pub zone: PolicyFileZone,
    pub capabilities: Option<PolicyFileCapabilities>,
    pub resources: Option<PolicyFileResources>,
    pub network: Option<PolicyFileNetwork>,
    pub filesystem: Option<PolicyFileFilesystem>,
    pub devices: Option<PolicyFileDevices>,
    pub syscalls: Option<PolicyFileSyscalls>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyFileZone {
    pub name: String,
    #[serde(rename = "type", default = "default_zone_type_str")]
    pub zone_type: String,
}

fn default_zone_type_str() -> String {
    "non-global".into()
}

#[derive(Debug, Deserialize)]
pub struct PolicyFileCapabilities {
    pub allowed: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyFileResources {
    pub cpu_shares: Option<u64>,
    pub memory_limit: Option<String>,
    pub io_weight: Option<u16>,
    pub pids_max: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyFileNetwork {
    pub mode: Option<String>,
    pub allowed_zones: Option<Vec<String>>,
    pub allowed_egress: Option<Vec<String>>,
    pub allowed_ingress: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyFileFilesystem {
    pub root: Option<String>,
    pub shared_layers: Option<bool>,
    pub writable_paths: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyFileDevices {
    pub allowed: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyFileSyscalls {
    pub deny: Vec<String>,
}

impl PolicyFile {
    /// Parse a TOML policy file into a ZonePolicy.
    pub fn to_zone_policy(&self, base_root: &str) -> crate::error::Result<ZonePolicy> {
        let zone_type = match self.zone.zone_type.as_str() {
            "non-global" => ZoneType::NonGlobal,
            "privileged" => ZoneType::Privileged,
            "global" => ZoneType::Global,
            other => {
                return Err(crate::error::RauhaError::InvalidPolicy(format!(
                    "unknown zone type: {other}"
                )))
            }
        };

        let _ = zone_type; // used by caller for zone creation

        let capabilities = self
            .capabilities
            .as_ref()
            .map(|c| CapabilityPolicy {
                allowed: c.allowed.clone(),
            })
            .unwrap_or_default();

        let resources = match &self.resources {
            Some(r) => {
                let memory_limit = r
                    .memory_limit
                    .as_deref()
                    .map(parse_memory_size)
                    .transpose()?
                    .unwrap_or(512 * 1024 * 1024);
                ResourcePolicy {
                    cpu_shares: r.cpu_shares.unwrap_or(1024),
                    memory_limit,
                    io_weight: r.io_weight.unwrap_or(100),
                    pids_max: r.pids_max.unwrap_or(256),
                }
            }
            None => ResourcePolicy::default(),
        };

        let network = self
            .network
            .as_ref()
            .map(|n| {
                let mode = match n.mode.as_deref() {
                    Some("isolated") | None => NetworkMode::Isolated,
                    Some("bridged") => NetworkMode::Bridged,
                    Some("host") => NetworkMode::Host,
                    Some(other) => {
                        return Err(crate::error::RauhaError::InvalidPolicy(format!(
                            "unknown network mode: {other}"
                        )))
                    }
                };
                Ok(NetworkPolicy {
                    mode,
                    allowed_zones: n.allowed_zones.clone().unwrap_or_default(),
                    allowed_egress: n.allowed_egress.clone().unwrap_or_default(),
                    allowed_ingress: n.allowed_ingress.clone().unwrap_or_default(),
                })
            })
            .transpose()?
            .unwrap_or_default();

        let filesystem = self
            .filesystem
            .as_ref()
            .map(|f| FilesystemPolicy {
                root: f
                    .root
                    .clone()
                    .unwrap_or_else(|| format!("{base_root}/zones/{}", self.zone.name)),
                shared_layers: f.shared_layers.unwrap_or(true),
                writable_paths: f
                    .writable_paths
                    .clone()
                    .unwrap_or_else(|| vec!["/tmp".into(), "/var/log".into()]),
            })
            .unwrap_or_else(|| FilesystemPolicy {
                root: format!("{base_root}/zones/{}", self.zone.name),
                ..Default::default()
            });

        let devices = self
            .devices
            .as_ref()
            .map(|d| DevicePolicy {
                allowed: d.allowed.clone(),
            })
            .unwrap_or_default();

        let syscalls = self
            .syscalls
            .as_ref()
            .map(|s| SyscallPolicy {
                deny: s.deny.clone(),
            })
            .unwrap_or_default();

        Ok(ZonePolicy {
            capabilities,
            resources,
            network,
            filesystem,
            devices,
            syscalls,
        })
    }
}

/// Parse human-readable memory sizes like "4Gi", "512Mi", "1G".
fn parse_memory_size(s: &str) -> crate::error::Result<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix("Gi") {
        n.parse::<u64>()
            .map(|v| v * 1024 * 1024 * 1024)
            .map_err(|e| crate::error::RauhaError::InvalidPolicy(format!("bad memory size: {e}")))
    } else if let Some(n) = s.strip_suffix("Mi") {
        n.parse::<u64>()
            .map(|v| v * 1024 * 1024)
            .map_err(|e| crate::error::RauhaError::InvalidPolicy(format!("bad memory size: {e}")))
    } else if let Some(n) = s.strip_suffix("Ki") {
        n.parse::<u64>()
            .map(|v| v * 1024)
            .map_err(|e| crate::error::RauhaError::InvalidPolicy(format!("bad memory size: {e}")))
    } else if let Some(n) = s.strip_suffix('G') {
        n.parse::<u64>()
            .map(|v| v * 1000 * 1000 * 1000)
            .map_err(|e| crate::error::RauhaError::InvalidPolicy(format!("bad memory size: {e}")))
    } else if let Some(n) = s.strip_suffix('M') {
        n.parse::<u64>()
            .map(|v| v * 1000 * 1000)
            .map_err(|e| crate::error::RauhaError::InvalidPolicy(format!("bad memory size: {e}")))
    } else {
        s.parse::<u64>()
            .map_err(|e| crate::error::RauhaError::InvalidPolicy(format!("bad memory size: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_memory_size() {
        assert_eq!(parse_memory_size("4Gi").unwrap(), 4 * 1024 * 1024 * 1024);
        assert_eq!(parse_memory_size("512Mi").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_memory_size("1G").unwrap(), 1_000_000_000);
        assert_eq!(parse_memory_size("1024").unwrap(), 1024);
    }

    #[test]
    fn test_default_policy() {
        let policy = ZonePolicy::default();
        assert!(policy.capabilities.allowed.is_empty());
        assert_eq!(policy.resources.cpu_shares, 1024);
        assert_eq!(policy.network.mode, NetworkMode::Isolated);
    }
}
