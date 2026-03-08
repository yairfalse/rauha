use chrono::Utc;
use rauha_common::backend::IsolationBackend;
use rauha_common::container::{Container, ContainerHandle, ContainerSpec, ContainerState};
use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::metadata::db::MetadataStore;

/// Manages zone lifecycle and container membership.
///
/// The registry is the source of truth for what zones exist and what containers
/// belong to them. It coordinates between the metadata store (persistence)
/// and the isolation backend (enforcement).
pub struct ZoneRegistry {
    metadata: Arc<MetadataStore>,
    backend: Arc<dyn IsolationBackend>,
    /// In-memory cache of zone handles for fast backend operations.
    handles: RwLock<HashMap<String, ZoneHandle>>,
    /// In-memory cache of container handles (needed for start/stop operations).
    container_handles: RwLock<HashMap<Uuid, ContainerHandle>>,
}

impl ZoneRegistry {
    pub fn new(metadata: Arc<MetadataStore>, backend: Arc<dyn IsolationBackend>) -> Self {
        Self {
            metadata,
            backend,
            handles: RwLock::new(HashMap::new()),
            container_handles: RwLock::new(HashMap::new()),
        }
    }

    /// Reconcile persisted metadata with kernel state on startup.
    ///
    /// redb is the source of truth. For each persisted zone, re-establish
    /// kernel state (cgroups, BPF maps, netns). Then clean up any orphaned
    /// kernel state that doesn't correspond to a known zone.
    ///
    /// This handles the crash recovery case: rauhad dies between writing
    /// to redb and updating kernel state, leaving them inconsistent.
    pub async fn reconcile(&self) -> Result<()> {
        let zones = self.metadata.list_zones()?;
        if zones.is_empty() {
            tracing::info!("no zones to reconcile");
            self.backend.cleanup_orphans(&[])?;
            return Ok(());
        }

        tracing::info!(count = zones.len(), "reconciling zones from metadata");

        let mut handles = Vec::new();
        for zone in &zones {
            let handle = ZoneHandle {
                id: zone.id,
                name: zone.name.clone(),
                platform_id: 0, // Will be set by recover_zone.
            };

            match self.backend.recover_zone(&handle, zone.zone_type, &zone.policy) {
                Ok(()) => {
                    handles.push(handle.clone());
                    self.handles.write().await.insert(zone.name.clone(), handle);
                    tracing::info!(zone = zone.name, "zone reconciled");
                }
                Err(e) => {
                    tracing::error!(zone = zone.name, %e, "failed to reconcile zone — zone will be unavailable");
                }
            }
        }

        // Clean up orphaned kernel state.
        if let Err(e) = self.backend.cleanup_orphans(&handles) {
            tracing::warn!(%e, "failed to clean up orphaned kernel state");
        }

        tracing::info!(recovered = handles.len(), total = zones.len(), "reconciliation complete");
        Ok(())
    }

    pub async fn create_zone(&self, name: &str, zone_type: ZoneType, policy: ZonePolicy) -> Result<Zone> {
        // Check for duplicates.
        if self.metadata.get_zone(name)?.is_some() {
            return Err(RauhaError::ZoneAlreadyExists(name.into()));
        }

        let config = ZoneConfig {
            name: name.into(),
            zone_type,
            policy: policy.clone(),
        };

        // Create in backend first (sets up isolation primitives).
        let handle = self.backend.create_zone(&config)?;

        // Apply the policy.
        self.backend.enforce_policy(&handle, &policy)?;

        let now = Utc::now();
        let zone = Zone {
            id: handle.id,
            name: name.into(),
            zone_type,
            state: ZoneState::Ready,
            policy,
            created_at: now,
            updated_at: now,
        };

        // Persist.
        self.metadata.put_zone(&zone)?;

        // Cache handle.
        self.handles.write().await.insert(name.into(), handle);

        tracing::info!(zone = name, "zone created");
        Ok(zone)
    }

    pub async fn delete_zone(&self, name: &str, force: bool) -> Result<()> {
        let zone = self
            .metadata
            .get_zone(name)?
            .ok_or_else(|| RauhaError::ZoneNotFound(name.into()))?;

        // Check for running containers unless force.
        let containers = self.metadata.list_containers(Some(&zone.id))?;
        if !containers.is_empty() && !force {
            return Err(RauhaError::ZoneNotEmpty {
                count: containers.len(),
            });
        }

        // Clean up containers if force.
        if force {
            for container in &containers {
                // Stop running containers.
                if container.state == ContainerState::Running {
                    if let Some(handle) = self.container_handles.write().await.remove(&container.id) {
                        let _ = self.backend.stop_container(&handle);
                    }
                }
                self.metadata.delete_container(&container.id)?;
            }
        }

        // Destroy in backend.
        if let Some(handle) = self.handles.write().await.remove(name) {
            self.backend.destroy_zone(&handle)?;
        }

        // Remove from metadata.
        self.metadata.delete_zone(name)?;

        tracing::info!(zone = name, "zone deleted");
        Ok(())
    }

    pub async fn get_zone(&self, name: &str) -> Result<Zone> {
        self.metadata
            .get_zone(name)?
            .ok_or_else(|| RauhaError::ZoneNotFound(name.into()))
    }

    pub fn list_zones(&self) -> Result<Vec<Zone>> {
        self.metadata.list_zones()
    }

    pub async fn apply_policy(&self, zone_name: &str, policy: ZonePolicy) -> Result<()> {
        let mut zone = self.get_zone(zone_name).await?;
        let handles = self.handles.read().await;
        let handle = handles
            .get(zone_name)
            .ok_or_else(|| RauhaError::ZoneNotFound(zone_name.into()))?;

        self.backend.hot_reload_policy(handle, &policy)?;

        zone.policy = policy;
        zone.updated_at = Utc::now();
        self.metadata.put_zone(&zone)?;

        tracing::info!(zone = zone_name, "policy updated");
        Ok(())
    }

    pub async fn create_container(
        &self,
        zone_name: &str,
        spec: ContainerSpec,
    ) -> Result<Container> {
        let zone = self.get_zone(zone_name).await?;
        let handles = self.handles.read().await;
        let handle = handles
            .get(zone_name)
            .ok_or_else(|| RauhaError::ZoneNotFound(zone_name.into()))?;

        let container_handle = self.backend.create_container(handle, &spec)?;

        let now = Utc::now();
        let container = Container {
            id: container_handle.id,
            name: spec.name,
            zone_id: zone.id,
            image: spec.image,
            state: ContainerState::Created,
            pid: Some(container_handle.pid),
            created_at: now,
            started_at: None,
            finished_at: None,
            exit_code: None,
        };

        self.metadata.put_container(&container)?;

        // Cache container handle for start/stop operations.
        self.container_handles
            .write()
            .await
            .insert(container_handle.id, container_handle);

        tracing::info!(container = %container.id, zone = zone_name, "container created");
        Ok(container)
    }

    /// Start a previously created container.
    pub async fn start_container(&self, container_id: &Uuid) -> Result<()> {
        let container = self
            .metadata
            .get_container(container_id)?
            .ok_or_else(|| RauhaError::ContainerNotFound(*container_id))?;

        let container_handle = self
            .container_handles
            .read()
            .await
            .get(container_id)
            .cloned()
            .ok_or_else(|| RauhaError::ContainerNotFound(*container_id))?;

        self.backend.start_container(&container_handle)?;

        // Update metadata.
        let mut updated = container;
        updated.state = ContainerState::Running;
        updated.started_at = Some(Utc::now());
        self.metadata.put_container(&updated)?;

        tracing::info!(container = %container_id, "container started");
        Ok(())
    }

    /// Stop a running container.
    pub async fn stop_container(&self, container_id: &Uuid, _timeout: u32) -> Result<()> {
        let container = self
            .metadata
            .get_container(container_id)?
            .ok_or_else(|| RauhaError::ContainerNotFound(*container_id))?;

        let container_handle = self
            .container_handles
            .read()
            .await
            .get(container_id)
            .cloned()
            .ok_or_else(|| RauhaError::ContainerNotFound(*container_id))?;

        self.backend.stop_container(&container_handle)?;

        // Update metadata.
        let mut updated = container;
        updated.state = ContainerState::Stopped;
        updated.finished_at = Some(Utc::now());
        self.metadata.put_container(&updated)?;

        tracing::info!(container = %container_id, "container stopped");
        Ok(())
    }

    /// Delete a container, stopping it first if needed.
    pub async fn delete_container(&self, container_id: &Uuid, force: bool) -> Result<()> {
        let container = self
            .metadata
            .get_container(container_id)?
            .ok_or_else(|| RauhaError::ContainerNotFound(*container_id))?;

        if container.state == ContainerState::Running {
            if force {
                self.stop_container(container_id, 10).await?;
            } else {
                return Err(RauhaError::BackendError(format!(
                    "container {} is running, use force to stop it first",
                    container_id
                )));
            }
        }

        self.container_handles.write().await.remove(container_id);
        self.metadata.delete_container(container_id)?;

        tracing::info!(container = %container_id, "container deleted");
        Ok(())
    }

    /// Get a container by ID.
    pub fn get_container(&self, container_id: &Uuid) -> Result<Container> {
        self.metadata
            .get_container(container_id)?
            .ok_or_else(|| RauhaError::ContainerNotFound(*container_id))
    }

    pub fn list_containers(&self, zone_name: Option<&str>) -> Result<Vec<Container>> {
        if let Some(name) = zone_name {
            let zone = self
                .metadata
                .get_zone(name)?
                .ok_or_else(|| RauhaError::ZoneNotFound(name.into()))?;
            self.metadata.list_containers(Some(&zone.id))
        } else {
            self.metadata.list_containers(None)
        }
    }

    pub async fn zone_stats(&self, zone_name: &str) -> Result<ZoneStats> {
        let handles = self.handles.read().await;
        let handle = handles
            .get(zone_name)
            .ok_or_else(|| RauhaError::ZoneNotFound(zone_name.into()))?;
        self.backend.zone_stats(handle)
    }

    pub async fn verify_isolation(&self, zone_name: &str) -> Result<IsolationReport> {
        let handles = self.handles.read().await;
        let handle = handles
            .get(zone_name)
            .ok_or_else(|| RauhaError::ZoneNotFound(zone_name.into()))?;
        self.backend.verify_isolation(handle)
    }
}
