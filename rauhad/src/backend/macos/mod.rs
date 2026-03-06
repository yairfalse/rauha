use rauha_common::backend::IsolationBackend;
use rauha_common::container::{ContainerHandle, ContainerSpec};
use rauha_common::error::Result;
use rauha_common::zone::*;
use uuid::Uuid;

/// macOS isolation backend using Virtualization.framework + sandbox profiles.
///
/// Phase 1: stub implementation.
/// Phase 5 will add: lightweight VMs via Virtualization.framework,
/// sandbox profile generation, APFS clone snapshots, pf firewall rules.
pub struct MacosBackend {
    root: String,
}

impl MacosBackend {
    pub fn new(root: &str) -> Result<Self> {
        Ok(Self { root: root.into() })
    }
}

impl IsolationBackend for MacosBackend {
    fn create_zone(&self, config: &ZoneConfig) -> Result<ZoneHandle> {
        tracing::info!(zone = config.name, backend = "macos-virt", "creating zone");

        // TODO Phase 5: Create lightweight VM via Virtualization.framework,
        // generate sandbox profile, set up pf rules.

        Ok(ZoneHandle {
            id: Uuid::new_v4(),
            name: config.name.clone(),
            platform_id: 0, // Will be VM id
        })
    }

    fn destroy_zone(&self, zone: &ZoneHandle) -> Result<()> {
        tracing::info!(zone = zone.name, "destroying zone");
        Ok(())
    }

    fn enforce_policy(&self, zone: &ZoneHandle, _policy: &ZonePolicy) -> Result<()> {
        tracing::info!(zone = zone.name, "enforcing policy");
        Ok(())
    }

    fn hot_reload_policy(&self, zone: &ZoneHandle, _policy: &ZonePolicy) -> Result<()> {
        tracing::info!(zone = zone.name, "hot-reloading policy");
        Ok(())
    }

    fn create_container(&self, zone: &ZoneHandle, spec: &ContainerSpec) -> Result<ContainerHandle> {
        tracing::info!(
            zone = zone.name,
            container = spec.name,
            "creating container"
        );
        Ok(ContainerHandle {
            id: Uuid::new_v4(),
            zone_id: zone.id,
            pid: 0,
            platform_id: 0,
        })
    }

    fn start_container(&self, container: &ContainerHandle) -> Result<()> {
        tracing::info!(container = %container.id, "starting container");
        Ok(())
    }

    fn stop_container(&self, container: &ContainerHandle) -> Result<()> {
        tracing::info!(container = %container.id, "stopping container");
        Ok(())
    }

    fn zone_stats(&self, zone: &ZoneHandle) -> Result<ZoneStats> {
        Ok(ZoneStats {
            zone_id: zone.id,
            container_count: 0,
            cpu_usage_percent: 0.0,
            memory_usage_bytes: 0,
            memory_limit_bytes: 0,
            network_rx_bytes: 0,
            network_tx_bytes: 0,
            pids_current: 0,
        })
    }

    fn verify_isolation(&self, zone: &ZoneHandle) -> Result<IsolationReport> {
        Ok(IsolationReport {
            zone_id: zone.id,
            is_isolated: true,
            checks: vec![IsolationCheck {
                name: "stub".into(),
                passed: true,
                detail: "stub backend — no real isolation yet".into(),
            }],
        })
    }

    fn name(&self) -> &str {
        "macos-virt"
    }
}
