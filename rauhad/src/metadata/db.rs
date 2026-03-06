use redb::{Database, ReadableTable, TableDefinition};
use rauha_common::container::Container;
use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::Zone;
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

const ZONES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("zones");
const CONTAINERS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("containers");

/// Persistent metadata store backed by redb.
///
/// Stores zone and container metadata with ACID transactions.
/// redb is pure Rust, zero C deps — aligns with Rauha's dependency philosophy.
pub struct MetadataStore {
    db: Arc<Database>,
}

impl MetadataStore {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path).map_err(|e| RauhaError::MetadataError(e.to_string()))?;

        // Ensure tables exist.
        let write_txn = db
            .begin_write()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        {
            let _ = write_txn
                .open_table(ZONES_TABLE)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            let _ = write_txn
                .open_table(CONTAINERS_TABLE)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;

        Ok(Self { db: Arc::new(db) })
    }

    // --- Zone operations ---

    pub fn put_zone(&self, zone: &Zone) -> Result<()> {
        let data =
            postcard::to_allocvec(zone).map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(ZONES_TABLE)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            table
                .insert(zone.name.as_str(), data.as_slice())
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        Ok(())
    }

    pub fn get_zone(&self, name: &str) -> Result<Option<Zone>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let table = read_txn
            .open_table(ZONES_TABLE)
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        match table.get(name) {
            Ok(Some(value)) => {
                let zone: Zone = postcard::from_bytes(value.value())
                    .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
                Ok(Some(zone))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(RauhaError::MetadataError(e.to_string())),
        }
    }

    pub fn delete_zone(&self, name: &str) -> Result<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(ZONES_TABLE)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            table
                .remove(name)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        Ok(())
    }

    pub fn list_zones(&self) -> Result<Vec<Zone>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let table = read_txn
            .open_table(ZONES_TABLE)
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let mut zones = Vec::new();
        for entry in table.iter().map_err(|e| RauhaError::MetadataError(e.to_string()))? {
            let (_, value) = entry.map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            let zone: Zone = postcard::from_bytes(value.value())
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            zones.push(zone);
        }
        Ok(zones)
    }

    // --- Container operations ---

    pub fn put_container(&self, container: &Container) -> Result<()> {
        let data = postcard::to_allocvec(container)
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let key = container.id.to_string();
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(CONTAINERS_TABLE)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            table
                .insert(key.as_str(), data.as_slice())
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        Ok(())
    }

    pub fn get_container(&self, id: &Uuid) -> Result<Option<Container>> {
        let key = id.to_string();
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let table = read_txn
            .open_table(CONTAINERS_TABLE)
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        match table.get(key.as_str()) {
            Ok(Some(value)) => {
                let container: Container = postcard::from_bytes(value.value())
                    .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
                Ok(Some(container))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(RauhaError::MetadataError(e.to_string())),
        }
    }

    pub fn delete_container(&self, id: &Uuid) -> Result<()> {
        let key = id.to_string();
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(CONTAINERS_TABLE)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            table
                .remove(key.as_str())
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        Ok(())
    }

    pub fn list_containers(&self, zone_id: Option<&Uuid>) -> Result<Vec<Container>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let table = read_txn
            .open_table(CONTAINERS_TABLE)
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let mut containers = Vec::new();
        for entry in table.iter().map_err(|e| RauhaError::MetadataError(e.to_string()))? {
            let (_, value) = entry.map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            let container: Container = postcard::from_bytes(value.value())
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            if let Some(zid) = zone_id {
                if &container.zone_id == zid {
                    containers.push(container);
                }
            } else {
                containers.push(container);
            }
        }
        Ok(containers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rauha_common::zone::*;
    use tempfile::NamedTempFile;

    fn test_db() -> MetadataStore {
        let tmp = NamedTempFile::new().unwrap();
        MetadataStore::open(tmp.path()).unwrap()
    }

    #[test]
    fn test_zone_crud() {
        let db = test_db();
        let zone = Zone {
            id: Uuid::new_v4(),
            name: "test-zone".into(),
            zone_type: ZoneType::NonGlobal,
            state: ZoneState::Ready,
            policy: ZonePolicy::default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        db.put_zone(&zone).unwrap();

        let loaded = db.get_zone("test-zone").unwrap().unwrap();
        assert_eq!(loaded.id, zone.id);
        assert_eq!(loaded.name, "test-zone");

        let zones = db.list_zones().unwrap();
        assert_eq!(zones.len(), 1);

        db.delete_zone("test-zone").unwrap();
        assert!(db.get_zone("test-zone").unwrap().is_none());
    }
}
