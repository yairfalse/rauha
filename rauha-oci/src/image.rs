use std::path::{Path, PathBuf};
use std::sync::Arc;

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
}

impl ImageService {
    pub fn new(content: Arc<ContentStore>, root: PathBuf) -> Self {
        let client = DistributionClient::new(content.clone());
        Self {
            content,
            client,
            root,
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
            self.client
                .pull_blob(
                    &reference.registry,
                    &reference.repository,
                    &layer_digest,
                    |current, total| {
                        on_progress(PullProgress {
                            status: status_prefix.clone(),
                            layer: layer_digest.to_string(),
                            current,
                            total,
                            done: false,
                        });
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
