use std::path::Path;

/// Fork a child process, set up rootfs, and run the container workload.
///
/// Flow:
/// 1. Create sync pipe
/// 2. fork()
/// 3. Child: block on pipe -> pivot_root -> execvp
/// 4. Parent: write child PID to zone cgroup -> signal pipe -> return PID
///
/// Note: This uses execvp (not shell exec) - no shell injection possible.
/// The child process image is replaced entirely by the container command.
#[cfg(target_os = "linux")]
pub fn fork_and_exec(
    zone_name: &str,
    container_id: &str,
    spec_json: &str,
    rootfs_root: &Path,
) -> anyhow::Result<u32> {
    use nix::unistd::{self, ForkResult};
    use std::ffi::CString;

    let spec: Spec = serde_json::from_str(spec_json)?;

    let process = spec
        .process()
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("spec missing process"))?;
    let args = process
        .args()
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("spec missing process.args"))?;
    if args.is_empty() {
        anyhow::bail!("process.args is empty");
    }

    let rootfs = rootfs_root
        .join("containers")
        .join(container_id)
        .join("rootfs");

    if !rootfs.exists() {
        anyhow::bail!("rootfs not found: {}", rootfs.display());
    }

    // Set up stdio log directory.
    let log_dir = PathBuf::from("/run/rauha/containers").join(container_id);
    std::fs::create_dir_all(&log_dir)?;

    // Create sync pipe.
    let (pipe_rd, pipe_wr) = nix::unistd::pipe()?;

    // Prepare C strings before fork (allocation not async-signal-safe after fork).
    let c_args: Vec<CString> = args
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();

    let env_vars: Vec<CString> = process
        .env()
        .as_ref()
        .map(|vars| {
            vars.iter()
                .map(|e| CString::new(e.as_str()).unwrap())
                .collect()
        })
        .unwrap_or_default();

    let cwd = process
        .cwd()
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/".to_string());

    let cwd_cstr = CString::new(cwd.as_str())?;

    let hostname = spec.hostname().cloned();

    // Fork.
    match unsafe { unistd::fork() }? {
        ForkResult::Child => {
            // Close write end of pipe.
            let _ = nix::unistd::close(pipe_wr);

            // Block until parent confirms cgroup enrollment.
            let mut buf = [0u8; 1];
            let _ = nix::unistd::read(pipe_rd, &mut buf);
            let _ = nix::unistd::close(pipe_rd);

            // New session.
            let _ = nix::unistd::setsid();

            // Redirect stdout/stderr to log files.
            redirect_stdio(&log_dir);

            // pivot_root into the container rootfs.
            if let Err(e) = do_pivot_root(&rootfs) {
                eprintln!("pivot_root failed: {e}");
                std::process::exit(1);
            }

            // Set hostname.
            if let Some(ref h) = hostname {
                let _ = nix::unistd::sethostname(h);
            }

            // Set environment.
            // Clear inherited env, set only what the spec says.
            for (key, _) in std::env::vars() {
                std::env::remove_var(&key);
            }
            for var in &env_vars {
                let s = var.to_string_lossy();
                if let Some((k, v)) = s.split_once('=') {
                    std::env::set_var(k, v);
                }
            }

            // chdir.
            let _ = nix::unistd::chdir(cwd_cstr.as_c_str());

            // Replace process with container command (execvp, no shell involved).
            let err = nix::unistd::execvp(&c_args[0], &c_args);
            eprintln!("execvp failed: {err:?}");
            std::process::exit(127);
        }
        ForkResult::Parent { child } => {
            // Close read end.
            let _ = nix::unistd::close(pipe_rd);

            let child_pid = child.as_raw() as u32;

            // Enroll child in zone cgroup.
            let cgroup_path = format!(
                "/sys/fs/cgroup/rauha.slice/zone-{zone_name}/cgroup.procs"
            );
            if let Err(e) = std::fs::write(&cgroup_path, child_pid.to_string()) {
                tracing::warn!(%e, cgroup = cgroup_path, "failed to enroll child in cgroup");
            }

            // Signal child to proceed (unblock from sync pipe).
            let _ = nix::unistd::write(pipe_wr, &[1u8]);
            let _ = nix::unistd::close(pipe_wr);

            tracing::info!(pid = child_pid, container = container_id, "child forked");
            Ok(child_pid)
        }
    }
}

/// Non-Linux stub.
#[cfg(not(target_os = "linux"))]
pub fn fork_and_exec(
    _zone_name: &str,
    _container_id: &str,
    _spec_json: &str,
    _rootfs_root: &Path,
) -> anyhow::Result<u32> {
    anyhow::bail!("fork_and_exec is only supported on Linux")
}

/// Send a signal to a process.
pub fn send_signal(pid: u32, signal: i32) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::signal::{self, Signal};
        use nix::unistd::Pid;

        let sig = Signal::try_from(signal)?;
        signal::kill(Pid::from_raw(pid as i32), sig)?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, signal);
        anyhow::bail!("signal not supported on this platform")
    }
}

/// Try to reap a child process (non-blocking). Returns exit code if exited.
pub fn try_wait(pid: u32) -> Option<i32> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
        use nix::unistd::Pid;

        match waitpid(Pid::from_raw(pid as i32), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => Some(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => Some(128 + sig as i32),
            _ => None,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// Perform pivot_root to change the container's root filesystem.
#[cfg(target_os = "linux")]
fn do_pivot_root(new_root: &Path) -> anyhow::Result<()> {
    use nix::mount::{mount, umount2, MntFlags, MsFlags};

    // Bind-mount new_root onto itself (required by pivot_root).
    mount(
        Some(new_root),
        new_root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )?;

    let old_root = new_root.join(".pivot_old");
    std::fs::create_dir_all(&old_root)?;

    nix::unistd::pivot_root(new_root, &old_root)?;
    nix::unistd::chdir("/")?;

    // Unmount old root.
    umount2("/.pivot_old", MntFlags::MNT_DETACH)?;
    std::fs::remove_dir("/.pivot_old").ok();

    Ok(())
}

/// Redirect stdout and stderr to log files.
#[cfg(target_os = "linux")]
fn redirect_stdio(log_dir: &Path) {
    use std::os::unix::io::AsRawFd;

    let stdout_path = log_dir.join("stdout.log");
    let stderr_path = log_dir.join("stderr.log");

    if let Ok(f) = std::fs::File::create(&stdout_path) {
        let _ = nix::unistd::dup2(f.as_raw_fd(), 1);
    }
    if let Ok(f) = std::fs::File::create(&stderr_path) {
        let _ = nix::unistd::dup2(f.as_raw_fd(), 2);
    }
}
