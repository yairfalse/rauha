use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rauha_common::error::RauhaError;

use crate::content::{ContentStore, Digest};
use crate::distribution::{DistributionClient, OciImageConfig, OciManifest};
use crate::reference::ImageReference;

/// Progress event during an image pull.
#[derive(Debug, Clone)]
pub struct PullProgress {
    pub status: String,
    pub layer: String,
    pub current: u64,
    pub total: u64,
    pub done: bool,
}

/// Information about a locally stored image.
#[derive(Debug, Clone)]
pub struct ImageInfo {
    pub reference: String,
    pub digest: String,
    pub layers: usize,
    pub size: u64,
}

/// Orchestrates image pull, storage, and rootfs preparation.
pub struct ImageService {
    content: Arc<ContentStore>,
    client: DistributionClient,
    root: PathBuf,
    /// Tracks images currently being extracted to prevent concurrent extraction races.
    extracting: Mutex<HashSet<String>>,
}

impl ImageService {
    pub fn new(content: Arc<ContentStore>, root: PathBuf) -> Self {
        let client = DistributionClient::new(content.clone());
        Self {
            content,
            client,
            root,
            extracting: Mutex::new(HashSet::new()),
        }
    }

    /// Pull an image from a registry, storing blobs in the content store.
    /// Returns progress events via the callback.
    pub async fn pull<F>(
        &self,
        reference_str: &str,
        mut on_progress: F,
    ) -> Result<OciManifest, RauhaError>
    where
        F: FnMut(PullProgress),
    {
        let reference = ImageReference::parse(reference_str).map_err(|e| {
            RauhaError::ImagePullError {
                reference: reference_str.into(),
                message: e,
            }
        })?;

        on_progress(PullProgress {
            status: "pulling manifest".into(),
            layer: String::new(),
            current: 0,
            total: 0,
            done: false,
        });

        let manifest = self.client.pull_manifest(&reference).await?;

        // Pull config blob.
        let config_digest =
            Digest::parse(&manifest.config.digest).ok_or_else(|| RauhaError::ImagePullError {
                reference: reference_str.into(),
                message: format!("invalid config digest: {}", manifest.config.digest),
            })?;

        on_progress(PullProgress {
            status: "pulling config".into(),
            layer: config_digest.to_string(),
            current: 0,
            total: manifest.config.size,
            done: false,
        });

        self.client
            .pull_blob(
                &reference.registry,
                &reference.repository,
                &config_digest,
                |_, _| {},
            )
            .await?;

        // Pull layer blobs.
        for (i, layer) in manifest.layers.iter().enumerate() {
            let layer_digest =
                Digest::parse(&layer.digest).ok_or_else(|| RauhaError::ImagePullError {
                    reference: reference_str.into(),
                    message: format!("invalid layer digest: {}", layer.digest),
                })?;

            let layer_num = format!("{}/{}", i + 1, manifest.layers.len());
            on_progress(PullProgress {
                status: format!("pulling layer {layer_num}"),
                layer: layer_digest.to_string(),
                current: 0,
                total: layer.size,
                done: false,
            });

            let status_prefix = format!("pulling layer {layer_num}");
            let manifest_size = layer.size;
            let mut last_reported_pct: i64 = -1;
            self.client
                .pull_blob(
                    &reference.registry,
                    &reference.repository,
                    &layer_digest,
                    |current, total| {
                        // Use manifest-declared size when CDN strips Content-Length.
                        let effective_total = if total > 0 { total } else { manifest_size };
                        if effective_total == 0 {
                            return;
                        }
                        let pct = (current * 100 / effective_total) as i64;
                        // Throttle: report every 5% or at 100%.
                        if pct >= last_reported_pct + 5 || (pct == 100 && last_reported_pct != 100) {
                            last_reported_pct = pct;
                            on_progress(PullProgress {
                                status: status_prefix.clone(),
                                layer: layer_digest.to_string(),
                                current,
                                total: effective_total,
                                done: false,
                            });
                        }
                    },
                )
                .await?;
        }

        on_progress(PullProgress {
            status: "pull complete".into(),
            layer: String::new(),
            current: 0,
            total: 0,
            done: true,
        });

        Ok(manifest)
    }

    /// Prepare a rootfs directory by unpacking all image layers sequentially.
    ///
    /// Phase 3 simplification: no overlayfs — all layers extracted into a single directory.
    pub fn prepare_rootfs(&self, reference_str: &str, target: &Path) -> Result<(), RauhaError> {
        let canonical = {
            let reference = ImageReference::parse(reference_str).map_err(|e| {
                RauhaError::ImagePullError {
                    reference: reference_str.into(),
                    message: e,
                }
            })?;
            reference.to_string_canonical()
        };

        // Load manifest from content store.
        let manifest_bytes =
            self.content
                .get_manifest(&canonical)
                .map_err(|e| RauhaError::ContentError {
                    message: format!("failed to read manifest: {e}"),
                })?
                .ok_or_else(|| RauhaError::ImagePullError {
                    reference: reference_str.into(),
                    message: "image not pulled — run `rauha image pull` first".into(),
                })?;

        let manifest: OciManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| RauhaError::ContentError {
                message: format!("corrupt manifest: {e}"),
            })?;

        std::fs::create_dir_all(target).map_err(|e| RauhaError::RootfsError {
            message: format!("failed to create rootfs dir: {e}"),
        })?;

        // Unpack layers in order.
        for layer in &manifest.layers {
            let digest =
                Digest::parse(&layer.digest).ok_or_else(|| RauhaError::RootfsError {
                    message: format!("invalid layer digest: {}", layer.digest),
                })?;

            let blob_path = self.content.blob_file_path(&digest);
            tracing::info!(layer = %digest, "unpacking layer");

            let file = std::fs::File::open(&blob_path).map_err(|e| RauhaError::RootfsError {
                message: format!("failed to open layer blob {digest}: {e}"),
            })?;

            let decoder = flate2::read::GzDecoder::new(file);
            let mut archive = tar::Archive::new(decoder);

            // Unpack with whiteout handling for OCI layer semantics.
            unpack_layer(&mut archive, target)?;
        }

        tracing::info!(rootfs = %target.display(), layers = manifest.layers.len(), "rootfs prepared");
        Ok(())
    }

    /// Prepare a shared base rootfs for an image, returning the path.
    ///
    /// Idempotent: uses a `.complete` marker file to distinguish fully extracted
    /// rootfs from partial/crashed extractions. Extraction happens into a temp
    /// directory and is atomically renamed into place.
    ///
    /// Thread-safe: a per-image lock prevents concurrent extractions of the
    /// same image from racing.
    pub fn prepare_base_rootfs(&self, reference_str: &str) -> Result<PathBuf, RauhaError> {
        let reference = ImageReference::parse(reference_str).map_err(|e| {
            RauhaError::ImagePullError {
                reference: reference_str.into(),
                message: e,
            }
        })?;

        let canonical = reference.to_string_canonical();
        let safe_name = canonical.replace(['/', ':'], "_");
        let image_dir = self.root.join("images").join(&safe_name);
        let rootfs_path = image_dir.join("rootfs");
        let marker = image_dir.join(".complete");

        // Fast path: already fully extracted.
        if marker.exists() {
            tracing::debug!(rootfs = %rootfs_path.display(), "base rootfs already prepared");
            return Ok(rootfs_path);
        }

        // Acquire per-image lock to prevent concurrent extraction races.
        // Spin-wait if another thread is already extracting this image.
        loop {
            {
                let mut extracting = self.extracting.lock().unwrap();
                if !extracting.contains(&safe_name) {
                    // Re-check marker after acquiring lock (another thread may have finished).
                    if marker.exists() {
                        return Ok(rootfs_path);
                    }
                    extracting.insert(safe_name.clone());
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // Extract into a temp directory, then atomically rename into place.
        // This prevents partial extractions from being treated as complete.
        let temp_rootfs = image_dir.join(".rootfs-extracting");
        if temp_rootfs.exists() {
            let _ = std::fs::remove_dir_all(&temp_rootfs);
        }

        tracing::info!(image = %canonical, rootfs = %rootfs_path.display(), "preparing base rootfs");
        let result = self.prepare_rootfs(reference_str, &temp_rootfs);

        // Always release the per-image lock, even on failure.
        self.extracting.lock().unwrap().remove(&safe_name);

        result?;

        // Atomic rename: if rootfs_path exists from a crashed run, remove it first.
        if rootfs_path.exists() {
            std::fs::remove_dir_all(&rootfs_path).map_err(|e| RauhaError::RootfsError {
                message: format!("failed to remove stale rootfs: {e}"),
            })?;
        }
        std::fs::rename(&temp_rootfs, &rootfs_path).map_err(|e| RauhaError::RootfsError {
            message: format!("failed to rename rootfs into place: {e}"),
        })?;

        // Write completion marker.
        std::fs::write(&marker, b"").map_err(|e| RauhaError::RootfsError {
            message: format!("failed to write completion marker: {e}"),
        })?;

        Ok(rootfs_path)
    }

    /// Get the image config (CMD, ENV, WORKDIR, etc.) from a pulled image.
    pub fn inspect(&self, reference_str: &str) -> Result<OciImageConfig, RauhaError> {
        let canonical = {
            let reference = ImageReference::parse(reference_str).map_err(|e| {
                RauhaError::ImagePullError {
                    reference: reference_str.into(),
                    message: e,
                }
            })?;
            reference.to_string_canonical()
        };

        let manifest_bytes =
            self.content
                .get_manifest(&canonical)
                .map_err(|e| RauhaError::ContentError {
                    message: format!("failed to read manifest: {e}"),
                })?
                .ok_or_else(|| RauhaError::ImagePullError {
                    reference: reference_str.into(),
                    message: "image not pulled".into(),
                })?;

        let manifest: OciManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| RauhaError::ContentError {
                message: format!("corrupt manifest: {e}"),
            })?;

        let config_digest =
            Digest::parse(&manifest.config.digest).ok_or_else(|| RauhaError::ContentError {
                message: format!("invalid config digest: {}", manifest.config.digest),
            })?;

        let config_bytes =
            self.content
                .get_blob(&config_digest)
                .map_err(|e| RauhaError::ContentError {
                    message: format!("failed to read config blob: {e}"),
                })?;

        serde_json::from_slice(&config_bytes).map_err(|e| RauhaError::ContentError {
            message: format!("corrupt image config: {e}"),
        })
    }

    /// List locally stored images (by scanning manifest references).
    pub fn list_images(&self) -> Result<Vec<ImageInfo>, RauhaError> {
        let manifests_dir = self.root.join("content").join("manifests");
        if !manifests_dir.exists() {
            return Ok(Vec::new());
        }

        let mut images = Vec::new();
        let entries = std::fs::read_dir(&manifests_dir).map_err(|e| RauhaError::ContentError {
            message: format!("failed to read manifests dir: {e}"),
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let digest_str =
                std::fs::read_to_string(&path).unwrap_or_default();
            let digest_str = digest_str.trim();

            // Recover reference from filename.
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown");

            // Try to load manifest for layer count / size.
            let (layers, size) = if let Some(digest) = Digest::parse(digest_str) {
                if let Ok(data) = self.content.get_blob(&digest) {
                    if let Ok(m) = serde_json::from_slice::<OciManifest>(&data) {
                        (m.layers.len(), m.layers.iter().map(|l| l.size).sum())
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, 0)
                }
            } else {
                (0, 0)
            };

            images.push(ImageInfo {
                reference: stem.to_string(),
                digest: digest_str.to_string(),
                layers,
                size,
            });
        }

        Ok(images)
    }

    /// Remove an image's manifest reference (blobs are kept for potential sharing).
    pub fn remove_image(&self, reference_str: &str) -> Result<(), RauhaError> {
        let canonical = {
            let reference = ImageReference::parse(reference_str).map_err(|e| {
                RauhaError::ImagePullError {
                    reference: reference_str.into(),
                    message: e,
                }
            })?;
            reference.to_string_canonical()
        };

        let safe = canonical.replace(['/', ':'], "_");
        let ref_path = self
            .root
            .join("content")
            .join("manifests")
            .join(format!("{safe}.json"));

        if ref_path.exists() {
            std::fs::remove_file(&ref_path).map_err(|e| RauhaError::ContentError {
                message: format!("failed to remove manifest ref: {e}"),
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::ContentStore;
    use crate::distribution::{OciDescriptor, OciManifest};
    use std::io::Write;

    /// Create a gzipped tar archive from a list of (path, content) pairs.
    fn make_tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut tar_data, flate2::Compression::fast());
            let mut builder = tar::Builder::new(enc);

            for (path, content) in files {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, *content).unwrap();
            }

            builder.finish().unwrap();
            let enc = builder.into_inner().unwrap();
            enc.finish().unwrap();
        }
        tar_data
    }

    /// Set up a content store with a fake manifest and layers.
    fn setup_content_store_with_image(
        dir: &std::path::Path,
    ) -> (Arc<ContentStore>, String) {
        let content_dir = dir.join("content");
        let store = Arc::new(ContentStore::new(&content_dir).unwrap());

        // Create a layer.
        let layer_data = make_tar_gz(&[
            ("hello.txt", b"hello world"),
            ("bin/test", b"#!/bin/sh\necho hi"),
        ]);
        let layer_digest = store.put_blob(&layer_data).unwrap();

        // Create image config.
        let config_json = br#"{"config":{"Cmd":["/bin/sh"],"Env":["PATH=/usr/bin"]}}"#;
        let config_digest = store.put_blob(config_json).unwrap();

        // Create manifest.
        let manifest = OciManifest {
            schema_version: 2,
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            config: OciDescriptor {
                media_type: "application/vnd.oci.image.config.v1+json".into(),
                digest: config_digest.as_str().to_string(),
                size: config_json.len() as u64,
            },
            layers: vec![OciDescriptor {
                media_type: "application/vnd.oci.image.rootfs.diff.tar.gzip".into(),
                digest: layer_digest.as_str().to_string(),
                size: layer_data.len() as u64,
            }],
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

        // Store manifest under canonical reference.
        let reference = "registry-1.docker.io/library/testimage:latest";
        store.put_manifest(reference, &manifest_bytes).unwrap();

        (store, reference.to_string())
    }

    #[test]
    fn inspect_returns_image_config() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let config = svc.inspect("testimage:latest").unwrap();

        let inner = config.config.unwrap();
        assert_eq!(inner.cmd.unwrap(), vec!["/bin/sh"]);
        assert_eq!(inner.env.unwrap(), vec!["PATH=/usr/bin"]);
    }

    #[test]
    fn inspect_missing_image_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let content_dir = dir.path().join("content");
        let store = Arc::new(ContentStore::new(&content_dir).unwrap());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let result = svc.inspect("nonexistent:latest");
        assert!(result.is_err());
    }

    #[test]
    fn prepare_rootfs_unpacks_layer() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let rootfs = dir.path().join("test-rootfs");
        svc.prepare_rootfs("testimage:latest", &rootfs).unwrap();

        // Verify files were unpacked.
        assert!(rootfs.join("hello.txt").exists());
        assert_eq!(
            std::fs::read_to_string(rootfs.join("hello.txt")).unwrap(),
            "hello world"
        );
        assert!(rootfs.join("bin/test").exists());
    }

    #[test]
    fn prepare_rootfs_missing_image_errors() {
        let dir = tempfile::tempdir().unwrap();
        let content_dir = dir.path().join("content");
        let store = Arc::new(ContentStore::new(&content_dir).unwrap());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let rootfs = dir.path().join("test-rootfs");
        let result = svc.prepare_rootfs("nonexistent:latest", &rootfs);
        assert!(result.is_err());
    }

    #[test]
    fn prepare_base_rootfs_extracts_and_returns_path() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let rootfs = svc.prepare_base_rootfs("testimage:latest").unwrap();

        // Verify path structure.
        assert!(rootfs.ends_with("rootfs"));
        assert!(rootfs.join("hello.txt").exists());
        assert_eq!(
            std::fs::read_to_string(rootfs.join("hello.txt")).unwrap(),
            "hello world"
        );
        // Verify completion marker was written.
        let marker = rootfs.parent().unwrap().join(".complete");
        assert!(marker.exists());
    }

    #[test]
    fn prepare_base_rootfs_idempotent_skips_reextraction() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());

        // First call extracts.
        let path1 = svc.prepare_base_rootfs("testimage:latest").unwrap();
        // Second call returns immediately (idempotent).
        let path2 = svc.prepare_base_rootfs("testimage:latest").unwrap();

        assert_eq!(path1, path2);
        assert!(path1.join("hello.txt").exists());
    }

    #[test]
    fn prepare_base_rootfs_recovers_from_partial_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());

        // Simulate a crashed extraction: create rootfs dir with content but no marker.
        let safe_name = "registry-1.docker.io_library_testimage_latest";
        let image_dir = dir.path().join("images").join(safe_name);
        let rootfs_dir = image_dir.join("rootfs");
        std::fs::create_dir_all(&rootfs_dir).unwrap();
        std::fs::write(rootfs_dir.join("stale-file"), b"leftover").unwrap();
        // No .complete marker — simulates crash mid-extraction.

        // Should re-extract despite non-empty dir.
        let path = svc.prepare_base_rootfs("testimage:latest").unwrap();
        assert!(path.join("hello.txt").exists());
        // Stale file should be gone (replaced by fresh extraction).
        assert!(!path.join("stale-file").exists());
    }

    #[test]
    fn list_images_empty() {
        let dir = tempfile::tempdir().unwrap();
        let content_dir = dir.path().join("content");
        let store = Arc::new(ContentStore::new(&content_dir).unwrap());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let images = svc.list_images().unwrap();
        assert!(images.is_empty());
    }

    #[test]
    fn list_images_returns_stored_image() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let images = svc.list_images().unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].layers, 1);
        assert!(images[0].size > 0);
    }

    #[test]
    fn remove_image_deletes_reference() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());

        // Verify image exists.
        assert!(svc.inspect("testimage:latest").is_ok());

        // Remove it.
        svc.remove_image("testimage:latest").unwrap();

        // Should no longer be inspectable.
        assert!(svc.inspect("testimage:latest").is_err());
    }

    #[test]
    fn whiteout_file_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let content_dir = dir.path().join("content");
        let store = Arc::new(ContentStore::new(&content_dir).unwrap());

        // Layer 1: create a file.
        let layer1 = make_tar_gz(&[("etc/config.txt", b"original")]);
        let layer1_digest = store.put_blob(&layer1).unwrap();

        // Layer 2: whiteout that file.
        let layer2 = make_tar_gz(&[("etc/.wh.config.txt", b"")]);
        let layer2_digest = store.put_blob(&layer2).unwrap();

        let config_json = br#"{"config":{"Cmd":["/bin/sh"]}}"#;
        let config_digest = store.put_blob(config_json).unwrap();

        let manifest = OciManifest {
            schema_version: 2,
            media_type: String::new(),
            config: OciDescriptor {
                media_type: String::new(),
                digest: config_digest.as_str().to_string(),
                size: config_json.len() as u64,
            },
            layers: vec![
                OciDescriptor {
                    media_type: String::new(),
                    digest: layer1_digest.as_str().to_string(),
                    size: layer1.len() as u64,
                },
                OciDescriptor {
                    media_type: String::new(),
                    digest: layer2_digest.as_str().to_string(),
                    size: layer2.len() as u64,
                },
            ],
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let reference = "registry-1.docker.io/library/whiteout-test:latest";
        store.put_manifest(reference, &manifest_bytes).unwrap();

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let rootfs = dir.path().join("rootfs");
        svc.prepare_rootfs("whiteout-test:latest", &rootfs).unwrap();

        // The file should have been deleted by the whiteout.
        assert!(!rootfs.join("etc/config.txt").exists());
    }

    #[test]
    fn multiple_layers_applied_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let content_dir = dir.path().join("content");
        let store = Arc::new(ContentStore::new(&content_dir).unwrap());

        // Layer 1: create a file.
        let layer1 = make_tar_gz(&[("data.txt", b"layer1")]);
        let layer1_digest = store.put_blob(&layer1).unwrap();

        // Layer 2: overwrite the file.
        let layer2 = make_tar_gz(&[("data.txt", b"layer2")]);
        let layer2_digest = store.put_blob(&layer2).unwrap();

        let config_json = br#"{"config":{"Cmd":["/bin/sh"]}}"#;
        let config_digest = store.put_blob(config_json).unwrap();

        let manifest = OciManifest {
            schema_version: 2,
            media_type: String::new(),
            config: OciDescriptor {
                media_type: String::new(),
                digest: config_digest.as_str().to_string(),
                size: config_json.len() as u64,
            },
            layers: vec![
                OciDescriptor {
                    media_type: String::new(),
                    digest: layer1_digest.as_str().to_string(),
                    size: layer1.len() as u64,
                },
                OciDescriptor {
                    media_type: String::new(),
                    digest: layer2_digest.as_str().to_string(),
                    size: layer2.len() as u64,
                },
            ],
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let reference = "registry-1.docker.io/library/layered:latest";
        store.put_manifest(reference, &manifest_bytes).unwrap();

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let rootfs = dir.path().join("rootfs");
        svc.prepare_rootfs("layered:latest", &rootfs).unwrap();

        // Layer 2 should have overwritten layer 1.
        assert_eq!(
            std::fs::read_to_string(rootfs.join("data.txt")).unwrap(),
            "layer2"
        );
    }
}

/// Unpack a tar layer into a target directory, handling OCI whiteout files.
fn unpack_layer(
    archive: &mut tar::Archive<flate2::read::GzDecoder<std::fs::File>>,
    target: &Path,
) -> Result<(), RauhaError> {
    for entry in archive.entries().map_err(|e| RauhaError::RootfsError {
        message: format!("failed to read tar entries: {e}"),
    })? {
        let mut entry = entry.map_err(|e| RauhaError::RootfsError {
            message: format!("corrupt tar entry: {e}"),
        })?;

        let path = entry.path().map_err(|e| RauhaError::RootfsError {
            message: format!("invalid tar entry path: {e}"),
        })?;
        let path = path.to_path_buf();

        // Check for OCI whiteout markers.
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name == ".wh..wh..opq" {
                // Opaque whiteout: remove all existing contents of the parent directory.
                if let Some(parent) = path.parent() {
                    let full_parent = target.join(parent);
                    if full_parent.exists() {
                        let _ = std::fs::remove_dir_all(&full_parent);
                        let _ = std::fs::create_dir_all(&full_parent);
                    }
                }
                continue;
            }
            if let Some(original) = name.strip_prefix(".wh.") {
                // File whiteout: delete the corresponding file.
                if let Some(parent) = path.parent() {
                    let to_delete = target.join(parent).join(original);
                    if to_delete.is_dir() {
                        let _ = std::fs::remove_dir_all(&to_delete);
                    } else {
                        let _ = std::fs::remove_file(&to_delete);
                    }
                }
                continue;
            }
        }

        // Validate path: prevent path traversal.
        let full_path = target.join(&path);
        if !full_path.starts_with(target) {
            continue;
        }

        entry.unpack_in(target).map_err(|e| RauhaError::RootfsError {
            message: format!("failed to unpack {}: {e}", path.display()),
        })?;
    }

    Ok(())
}
