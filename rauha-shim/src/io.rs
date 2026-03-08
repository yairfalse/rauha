// Phase 3 minimal I/O: container stdout/stderr are redirected to log files
// under /run/rauha/containers/{id}/.
//
// Phase 4 will add:
// - PTY allocation for interactive containers
// - Streaming attach via the shim socket
// - Log rotation and size limits

use std::path::Path;

/// Get the stdout log path for a container.
pub fn stdout_log_path(container_id: &str) -> std::path::PathBuf {
    Path::new("/run/rauha/containers")
        .join(container_id)
        .join("stdout.log")
}

/// Get the stderr log path for a container.
pub fn stderr_log_path(container_id: &str) -> std::path::PathBuf {
    Path::new("/run/rauha/containers")
        .join(container_id)
        .join("stderr.log")
}
