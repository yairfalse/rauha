//! APFS copy-on-write rootfs manager.
//!
//! On APFS, `std::fs::copy` uses `clonefile()` under the hood — creating
//! instant zero-copy clones. Multiple containers from the same image share
//! physical disk blocks until one of them writes. This gives us overlayfs-like
//! efficiency without kernel support.

use std::path::{Path, PathBuf};

use rauha_common::error::{RauhaError, Result};

pub struct ApfsManager {
    root: PathBuf,
}

impl ApfsManager {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    /// Clone a rootfs from source (extracted image layers) to the container-specific
    /// rootfs directory. On APFS this is instant and zero-copy.
    pub fn clone_rootfs(&self, source: &Path, target: &Path) -> Result<()> {
        if !source.exists() {
            return Err(RauhaError::RootfsError {
                message: format!("source rootfs not found: {}", source.display()),
            });
        }

        if target.exists() {
            // Already cloned — idempotent.
            return Ok(());
        }

        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| RauhaError::RootfsError {
                message: format!("failed to create parent dir: {e}"),
            })?;
        }

        // Try macOS clonefile(2) first for instant CoW copy.
        #[cfg(target_os = "macos")]
        {
            if try_clonefile(source, target) {
                tracing::debug!(
                    source = %source.display(),
                    target = %target.display(),
                    "APFS clonefile succeeded"
                );
                return Ok(());
            }
            tracing::debug!("clonefile not available, falling back to recursive copy");
        }

        // Fallback: recursive copy (still benefits from APFS CoW per-file).
        copy_dir_recursive(source, target).map_err(|e| RauhaError::RootfsError {
            message: format!("failed to clone rootfs: {e}"),
        })?;

        Ok(())
    }

    /// Remove a container's rootfs directory.
    pub fn remove_rootfs(&self, path: &Path) -> Result<()> {
        if path.exists() {
            std::fs::remove_dir_all(path).map_err(|e| RauhaError::RootfsError {
                message: format!("failed to remove rootfs at {}: {e}", path.display()),
            })?;
        }
        Ok(())
    }

    /// Path where container rootfs directories live.
    pub fn containers_dir(&self) -> PathBuf {
        self.root.join("containers")
    }

    /// Path for a specific container's rootfs.
    pub fn container_rootfs(&self, zone_name: &str, container_id: &str) -> PathBuf {
        self.root
            .join("containers")
            .join(zone_name)
            .join(container_id)
            .join("rootfs")
    }
}

/// Try to use macOS `clonefile(2)` for directory-level CoW clone.
#[cfg(target_os = "macos")]
fn try_clonefile(source: &Path, target: &Path) -> bool {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};
    use std::os::unix::ffi::OsStrExt;

    let src = match CString::new(source.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let dst = match CString::new(target.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => return false,
    };

    extern "C" {
        fn clonefile(src: *const c_char, dst: *const c_char, flags: u32) -> c_int;
    }

    let ret = unsafe { clonefile(src.as_ptr(), dst.as_ptr(), 0) };
    ret == 0
}

/// Recursively copy a directory tree. On APFS, each `std::fs::copy` call
/// uses `clonefile` for individual files.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_symlink() {
            let link_target = std::fs::read_link(&src_path)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&link_target, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }

    // Preserve directory permissions.
    #[cfg(unix)]
    {
        let metadata = std::fs::metadata(src)?;
        std::fs::set_permissions(dst, metadata.permissions())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_rootfs_creates_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");

        // Create source tree.
        std::fs::create_dir_all(source.join("bin")).unwrap();
        std::fs::write(source.join("bin/sh"), "#!/bin/sh\n").unwrap();
        std::fs::write(source.join("hello.txt"), "hello").unwrap();

        let manager = ApfsManager::new(tmp.path());
        manager.clone_rootfs(&source, &target).unwrap();

        assert!(target.join("bin/sh").exists());
        assert_eq!(
            std::fs::read_to_string(target.join("hello.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn clone_rootfs_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");

        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&target).unwrap();

        let manager = ApfsManager::new(tmp.path());
        // Should not error when target already exists.
        manager.clone_rootfs(&source, &target).unwrap();
    }

    #[test]
    fn remove_rootfs_cleans_up() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        std::fs::create_dir_all(rootfs.join("bin")).unwrap();
        std::fs::write(rootfs.join("bin/sh"), "test").unwrap();

        let manager = ApfsManager::new(tmp.path());
        manager.remove_rootfs(&rootfs).unwrap();
        assert!(!rootfs.exists());
    }

    #[test]
    fn remove_rootfs_nonexistent_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let manager = ApfsManager::new(tmp.path());
        manager.remove_rootfs(&tmp.path().join("nope")).unwrap();
    }
}
