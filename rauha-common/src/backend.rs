use crate::container::{ContainerHandle, ContainerSpec};
use crate::error::Result;
use crate::zone::{IsolationReport, ZoneConfig, ZoneHandle, ZonePolicy, ZoneStats};

/// The core abstraction for platform-specific isolation.
///
/// Both Linux (eBPF + namespaces) and macOS (Virtualization.framework + sandbox)
/// backends implement this trait. `rauhad` uses `dyn IsolationBackend` to remain
/// platform-agnostic.
pub trait IsolationBackend: Send + Sync {
    /// Create a new isolation zone.
    fn create_zone(&self, config: &ZoneConfig) -> Result<ZoneHandle>;

    /// Destroy a zone and release all associated resources.
    fn destroy_zone(&self, zone: &ZoneHandle) -> Result<()>;

    /// Apply or replace the enforcement policy for a zone.
    fn enforce_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()>;

    /// Hot-reload a policy without restarting the zone or its containers.
    fn hot_reload_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()>;

    /// Create a container within a zone.
    fn create_container(&self, zone: &ZoneHandle, spec: &ContainerSpec) -> Result<ContainerHandle>;

    /// Start a previously created container.
    fn start_container(&self, container: &ContainerHandle) -> Result<()>;

    /// Stop a running container.
    fn stop_container(&self, container: &ContainerHandle) -> Result<()>;

    /// Get runtime statistics for a zone.
    fn zone_stats(&self, zone: &ZoneHandle) -> Result<ZoneStats>;

    /// Verify that zone isolation is intact.
    fn verify_isolation(&self, zone: &ZoneHandle) -> Result<IsolationReport>;

    /// The name of this backend (e.g., "linux-ebpf", "macos-virt").
    fn name(&self) -> &str;
}
