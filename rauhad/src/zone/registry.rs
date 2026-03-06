use chrono::Utc;
use rauha_common::backend::IsolationBackend;
use rauha_common::container::{Container, ContainerSpec, ContainerState};
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
}

impl ZoneRegistry {
    pub fn new(metadata: Arc<MetadataStore>, backend: Arc<dyn IsolationBackend>) -> Self {
        Self {
            metadata,
            backend,
            handles: RwLock::new(HashMap::new()),
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
        tracing::info!(container = %container.id, zone = zone_name, "container created");
        Ok(container)
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
