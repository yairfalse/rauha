use std::path::Path;

/// Fork a child process, set up rootfs, and run the container workload.
///
/// Flow (two-phase handshake):
/// 1. Create two sync pipes (setup: child->parent, go: parent->child)
/// 2. fork()
/// 3. Child: privileged setup (unshare/mount/pivot_root) -> signal "setup done"
///    -> block on "go" -> execvp the workload
/// 4. Parent: wait for "setup done" -> enroll child PID in zone cgroup
///    -> signal "go" -> return PID
///
/// The privileged bootstrap runs *before* cgroup enrollment, so the eBPF
/// `capable` hook does not judge rauha's own CAP_SYS_ADMIN setup against the
/// workload's policy. The untrusted workload (`execvp`) is started only after
/// enrollment is confirmed, so the TOCTOU enforcement boundary still holds:
/// no image code ever runs outside the zone. Enrollment failure is fatal —
/// the workload is never started unenforced (fail closed).
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
    use nix::unistd::ForkResult;
    use oci_spec::runtime::Spec;
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    let spec: Spec = serde_json::from_str(spec_json)?;
    let readonly_root = spec
        .root()
        .as_ref()
        .and_then(|root| root.readonly())
        .unwrap_or(false);

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

    // Check both overlayfs (merged/) and legacy (rootfs/) paths.
    let container_dir = rootfs_root.join("containers").join(container_id);
    let rootfs = {
        let merged = container_dir.join("merged");
        let legacy = container_dir.join("rootfs");
        if merged.exists() {
            merged
        } else if legacy.exists() {
            legacy
        } else {
            anyhow::bail!(
                "rootfs not found: checked {} and {}",
                merged.display(),
                legacy.display()
            );
        }
    };

    // Set up stdio log directory.
    let log_dir = PathBuf::from("/run/rauha/containers").join(container_id);
    std::fs::create_dir_all(&log_dir)?;

    // Two sync pipes for the two-phase handshake. OwnedFd closes on drop.
    //   setup pipe: child -> parent ("privileged setup done, safe to enroll")
    //   go pipe:    parent -> child ("enrolled, proceed to exec the workload")
    let (setup_rd, setup_wr) = nix::unistd::pipe()?;
    let (go_rd, go_wr) = nix::unistd::pipe()?;

    // Prepare C strings before fork (allocation not async-signal-safe after fork).
    let c_args = cstring_vec(args, "process.args")?;

    let env_vars = process
        .env()
        .as_ref()
        .map(|vars| cstring_vec(vars, "process.env"))
        .transpose()?
        .unwrap_or_default();

    let cwd = process.cwd().to_string_lossy().to_string();
    let cwd_cstr = CString::new(cwd.as_str())?;

    let hostname = spec.hostname().clone();
    let mut unshare_flags = nix::sched::CloneFlags::CLONE_NEWNS;
    let mut netns = None;
    let mut new_pid_namespace = false;
    if let Some(linux) = spec.linux().as_ref() {
        if let Some(namespaces) = linux.namespaces().as_ref() {
            for namespace in namespaces {
                match namespace.typ() {
                    oci_spec::runtime::LinuxNamespaceType::Uts => {
                        unshare_flags |= nix::sched::CloneFlags::CLONE_NEWUTS;
                    }
                    oci_spec::runtime::LinuxNamespaceType::Ipc => {
                        unshare_flags |= nix::sched::CloneFlags::CLONE_NEWIPC;
                    }
                    oci_spec::runtime::LinuxNamespaceType::Network => {
                        let path = namespace.path().as_ref().ok_or_else(|| {
                            anyhow::anyhow!("network namespace requires an existing path")
                        })?;
                        netns = Some(std::fs::File::open(path)?);
                    }
                    oci_spec::runtime::LinuxNamespaceType::Pid => {
                        new_pid_namespace = true;
                    }
                    _ => {}
                }
            }
        }
    }
    if hostname.is_some() && !unshare_flags.contains(nix::sched::CloneFlags::CLONE_NEWUTS) {
        anyhow::bail!("hostname requires a private UTS namespace");
    }
    let process_security = ProcessSecurity::from_process(process)?;
    let cap_last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
        .trim()
        .parse::<u32>()?
        .min(63);

    // Pre-allocate log file paths as CStrings for signal-safe use after fork.
    let stdout_log =
        std::ffi::CString::new(log_dir.join("stdout.log").to_string_lossy().as_bytes())
            .unwrap_or_default();
    let stderr_log =
        std::ffi::CString::new(log_dir.join("stderr.log").to_string_lossy().as_bytes())
            .unwrap_or_default();

    // Pre-allocate pivot_root paths as CStrings BEFORE fork — the child path
    // must not allocate (fork-safety invariant).
    let rootfs_cstr = CString::new(rootfs.as_os_str().as_bytes()).unwrap_or_default();
    let pivot_old_cstr =
        CString::new(rootfs.join(".pivot_old").as_os_str().as_bytes()).unwrap_or_default();

    // Convert OwnedFds to raw fds for use across fork.
    // We manage lifetime manually after fork (each side closes the ends it
    // does not use, by dropping the corresponding OwnedFd).
    let setup_rd_raw = setup_rd.as_raw_fd();
    let setup_wr_raw = setup_wr.as_raw_fd();
    let go_rd_raw = go_rd.as_raw_fd();
    let go_wr_raw = go_wr.as_raw_fd();

    // clone3 creates the workload bootstrap directly as PID 1 when requested;
    // unshare(CLONE_NEWPID) would affect only later children and leave the
    // workload itself in the host PID namespace.
    let clone_flags = if new_pid_namespace {
        libc::CLONE_NEWPID as u64
    } else {
        0
    };
    match clone_process(clone_flags)? {
        ForkResult::Child => {
            // Close the pipe ends this process does not use.
            drop(setup_rd);
            drop(go_wr);

            // New session.
            let _ = nix::unistd::setsid();

            // Redirect stdout/stderr to log files. Must happen before pivot_root
            // while /run/rauha/... is still reachable on the host filesystem.
            // Uses raw open() with pre-allocated CStrings — async-signal-safe.
            redirect_stdio_raw(&stdout_log, &stderr_log);

            // --- Privileged container bootstrap, BEFORE cgroup enrollment ---
            // The child is not yet a zone member here, so the eBPF `capable`
            // hook sees no zone (lookup_caller_zone -> None -> allow) and does
            // not judge these CAP_SYS_ADMIN operations against the workload's
            // policy. No image code runs in this window — only this fixed,
            // trusted setup sequence, after which we block until enrolled.

            // Enter a new mount namespace and make all mounts private.
            // pivot_root requires: (1) own mount namespace, (2) private root mount.
            // Without MS_PRIVATE|MS_REC, inherited shared mounts cause EINVAL.
            // Error reporting in the child must be async-signal-safe: static
            // byte messages + libc::write, never format!/alloc. The specific
            // errno is dropped; the failing operation is still identifiable.
            if let Some(netns) = netns.as_ref() {
                if nix::sched::setns(netns, nix::sched::CloneFlags::CLONE_NEWNET).is_err() {
                    unsafe {
                        let msg = b"rauha-shim: setns(CLONE_NEWNET) failed\n";
                        let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                        libc::_exit(1);
                    }
                }
            }
            drop(netns);

            if nix::sched::unshare(unshare_flags).is_err() {
                unsafe {
                    let msg = b"rauha-shim: namespace unshare failed\n";
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(1);
                }
            }
            // Make all mounts private — required for pivot_root to work.
            if nix::mount::mount(
                None::<&str>,
                "/",
                None::<&str>,
                nix::mount::MsFlags::MS_PRIVATE | nix::mount::MsFlags::MS_REC,
                None::<&str>,
            )
            .is_err()
            {
                unsafe {
                    let msg = b"rauha-shim: mount(MS_PRIVATE) failed\n";
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(1);
                }
            }

            // pivot_root into the container rootfs.
            if let Err(msg) = do_pivot_root(&rootfs_cstr, &pivot_old_cstr) {
                unsafe {
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(1);
                }
            }

            unsafe {
                libc::mkdir(c"/proc".as_ptr(), 0o555);
            }
            if nix::mount::mount(
                Some("proc"),
                "/proc",
                Some("proc"),
                nix::mount::MsFlags::MS_NOSUID
                    | nix::mount::MsFlags::MS_NODEV
                    | nix::mount::MsFlags::MS_NOEXEC,
                None::<&str>,
            )
            .is_err()
            {
                unsafe {
                    let msg = b"rauha-shim: procfs mount failed\n";
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(1);
                }
            }

            if readonly_root
                && nix::mount::mount(
                    None::<&str>,
                    "/",
                    None::<&str>,
                    nix::mount::MsFlags::MS_BIND
                        | nix::mount::MsFlags::MS_REMOUNT
                        | nix::mount::MsFlags::MS_RDONLY,
                    None::<&str>,
                )
                .is_err()
            {
                unsafe {
                    let msg = b"rauha-shim: read-only rootfs remount failed\n";
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(1);
                }
            }

            // Set hostname.
            if let Some(ref h) = hostname {
                let _ = nix::unistd::sethostname(h);
            }

            // Drop privilege while still outside the zone cgroup. This is the
            // final trusted bootstrap step; after enrollment the BPF capable()
            // allow-list applies and must not be needed to remove privileges.
            if apply_process_security(process_security, cap_last_cap).is_err() {
                unsafe {
                    let msg = b"rauha-shim: failed to apply process security\n";
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(1);
                }
            }

            // Signal the parent that privileged setup is complete and it is
            // safe to enroll us in the zone cgroup.
            let _ = nix::unistd::write(unsafe { BorrowedFd::borrow_raw(setup_wr_raw) }, &[1u8]);
            drop(setup_wr);

            // Block until the parent confirms cgroup enrollment. From here on
            // the process is inside the enforcement boundary, so the workload
            // exec below is fully subject to zone policy.
            let mut buf = [0u8; 1];
            let n = nix::unistd::read(go_rd_raw, &mut buf);
            drop(go_rd);
            // The "go" pipe closing without a byte means the parent could not
            // enroll us — refuse to run the workload unenforced (fail closed).
            if !matches!(n, Ok(1)) {
                let msg = b"cgroup enrollment failed; refusing to start workload unenforced\n";
                unsafe {
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(125);
                }
            }

            if new_pid_namespace {
                supervise_workload(&c_args, &env_vars, cwd_cstr.as_c_str());
            } else {
                exec_workload(&c_args, &env_vars, cwd_cstr.as_c_str());
            }
        }
        ForkResult::Parent { child } => {
            // Close the pipe ends this process does not use.
            drop(setup_wr);
            drop(go_rd);

            let child_pid = child.as_raw() as u32;
            let child_p = nix::unistd::Pid::from_raw(child_pid as i32);

            // Wait for the child to finish privileged setup before enrolling it,
            // so its CAP_SYS_ADMIN bootstrap is not judged against zone policy.
            // A read of 1 byte means setup succeeded; EOF (0) means the child
            // died during setup (it already wrote its own error to stderr).
            let mut buf = [0u8; 1];
            let setup_ok = matches!(nix::unistd::read(setup_rd_raw, &mut buf), Ok(1));
            drop(setup_rd);
            if !setup_ok {
                drop(go_wr);
                let _ = nix::sys::wait::waitpid(child_p, None);
                anyhow::bail!(
                    "container {container_id} failed during pre-enrollment setup \
                     (see container stderr)"
                );
            }

            // Enroll child in zone cgroup. This MUST succeed: a workload running
            // outside the cgroup gets no eBPF enforcement. On failure, kill the
            // child and report the error rather than signaling "go" — fail closed.
            let cgroup_path = format!("/sys/fs/cgroup/rauha.slice/zone-{zone_name}/cgroup.procs");
            if let Err(e) = std::fs::write(&cgroup_path, child_pid.to_string()) {
                let _ = nix::sys::signal::kill(child_p, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(child_p, None);
                drop(go_wr);
                anyhow::bail!(
                    "failed to enroll container {container_id} in zone cgroup \
                     {cgroup_path}: {e}; refusing to start workload unenforced"
                );
            }

            // Signal the child to proceed to exec — it is now inside the boundary.
            let signaled = nix::unistd::write(unsafe { BorrowedFd::borrow_raw(go_wr_raw) }, &[1u8]);
            drop(go_wr);
            // A failed/short write (e.g. EPIPE) means the child went away between
            // "setup done" and "go" — it will never exec the workload. Reap it
            // and report failure rather than claiming a container started.
            if !matches!(signaled, Ok(1)) {
                let _ = nix::sys::wait::waitpid(child_p, None);
                anyhow::bail!(
                    "container {container_id} exited before workload exec \
                     (enrollment signal not delivered)"
                );
            }

            tracing::info!(pid = child_pid, container = container_id, "child forked");
            Ok(child_pid)
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProcessSecurity {
    bounding: u64,
    effective: u64,
    inheritable: u64,
    permitted: u64,
    ambient: u64,
    no_new_privileges: bool,
}

#[cfg(target_os = "linux")]
impl ProcessSecurity {
    pub(crate) fn from_process(process: &oci_spec::runtime::Process) -> anyhow::Result<Self> {
        let capabilities = process
            .capabilities()
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("process.capabilities is required"))?;

        Ok(Self {
            bounding: capability_mask(capabilities.bounding().as_ref())?,
            effective: capability_mask(capabilities.effective().as_ref())?,
            inheritable: capability_mask(capabilities.inheritable().as_ref())?,
            permitted: capability_mask(capabilities.permitted().as_ref())?,
            ambient: capability_mask(capabilities.ambient().as_ref())?,
            no_new_privileges: process.no_new_privileges().unwrap_or(false),
        })
    }
}

#[cfg(target_os = "linux")]
fn capability_mask(capabilities: Option<&oci_spec::runtime::Capabilities>) -> anyhow::Result<u64> {
    capabilities
        .into_iter()
        .flatten()
        .try_fold(0u64, |mask, capability| {
            let name = capability.to_string();
            let bit = rauha_common::zone::linux_capability_bit(&name)
                .ok_or_else(|| anyhow::anyhow!("unsupported OCI capability: {name}"))?;
            Ok(mask | (1u64 << bit))
        })
}

#[cfg(target_os = "linux")]
pub(crate) fn apply_process_security(
    security: ProcessSecurity,
    cap_last_cap: u32,
) -> anyhow::Result<()> {
    #[repr(C)]
    struct UserCapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct UserCapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    for capability in 0..=cap_last_cap {
        if security.bounding & (1u64 << capability) == 0 {
            let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }

    let header = UserCapHeader {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let data = [
        UserCapData {
            effective: security.effective as u32,
            permitted: security.permitted as u32,
            inheritable: security.inheritable as u32,
        },
        UserCapData {
            effective: (security.effective >> 32) as u32,
            permitted: (security.permitted >> 32) as u32,
            inheritable: (security.inheritable >> 32) as u32,
        },
    ];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let rc = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    for capability in 0..=cap_last_cap {
        if security.ambient & (1u64 << capability) != 0 {
            let rc = unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_RAISE,
                    capability,
                    0,
                    0,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }

    if security.no_new_privileges {
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

/// fork(2)-equivalent clone3 with optional namespace flags.
///
/// clone3 uses the caller's copied stack when CLONE_VM is absent, so no child
/// stack allocation is required. Rauha's supported Linux kernels already need
/// clone3-era features for the security backend.
#[cfg(target_os = "linux")]
pub(crate) fn clone_process(flags: u64) -> nix::Result<nix::unistd::ForkResult> {
    #[repr(C)]
    #[derive(Default)]
    struct CloneArgs {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
        set_tid: u64,
        set_tid_size: u64,
        cgroup: u64,
    }

    let args = CloneArgs {
        flags,
        exit_signal: libc::SIGCHLD as u64,
        ..Default::default()
    };
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if pid < 0 {
        Err(nix::errno::Errno::last())
    } else if pid == 0 {
        Ok(nix::unistd::ForkResult::Child)
    } else {
        Ok(nix::unistd::ForkResult::Parent {
            child: nix::unistd::Pid::from_raw(pid as i32),
        })
    }
}

#[cfg(target_os = "linux")]
fn exec_workload(args: &[std::ffi::CString], env: &[std::ffi::CString], cwd: &std::ffi::CStr) -> ! {
    unsafe {
        libc::clearenv();
        for var in env {
            libc::putenv(var.as_ptr() as *mut libc::c_char);
        }
    }
    let _ = nix::unistd::chdir(cwd);
    let _ = nix::unistd::execvp(&args[0], args);
    unsafe {
        let msg = b"rauha-shim: execvp failed\n";
        let _ = libc::write(2, msg.as_ptr() as _, msg.len());
        libc::_exit(127);
    }
}

#[cfg(target_os = "linux")]
static INIT_CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

#[cfg(target_os = "linux")]
extern "C" fn forward_init_signal(signal: libc::c_int) {
    let child = INIT_CHILD_PID.load(std::sync::atomic::Ordering::Relaxed);
    if child > 0 {
        unsafe {
            libc::kill(child, signal);
        }
    }
}

/// Minimal PID 1: forward lifecycle signals and reap the actual workload.
#[cfg(target_os = "linux")]
fn supervise_workload(
    args: &[std::ffi::CString],
    env: &[std::ffi::CString],
    cwd: &std::ffi::CStr,
) -> ! {
    const FORWARDED_SIGNALS: &[libc::c_int] = &[
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGWINCH,
        libc::SIGCONT,
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
    ];

    let mut blocked = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigemptyset(&mut blocked);
        for &signal in FORWARDED_SIGNALS {
            libc::sigaddset(&mut blocked, signal);
            let mut action = std::mem::zeroed::<libc::sigaction>();
            action.sa_sigaction = forward_init_signal as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(signal, &action, std::ptr::null_mut());
        }
        libc::sigprocmask(libc::SIG_BLOCK, &blocked, &mut previous);
    }

    match clone_process(0) {
        Ok(nix::unistd::ForkResult::Child) => {
            unsafe {
                libc::sigprocmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
            }
            exec_workload(args, env, cwd);
        }
        Ok(nix::unistd::ForkResult::Parent { child }) => unsafe {
            INIT_CHILD_PID.store(child.as_raw(), std::sync::atomic::Ordering::Relaxed);
            libc::sigprocmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
            let mut main_exit = None;
            loop {
                let mut status = 0;
                let waited = libc::waitpid(-1, &mut status, 0);
                if waited > 0 {
                    if waited == child.as_raw() {
                        main_exit = wait_status_exit_code(status);
                        // Container lifetime follows its main workload. Stop
                        // descendants, then reap them before PID 1 exits.
                        libc::kill(-1, libc::SIGKILL);
                    }
                    continue;
                }
                if waited < 0 {
                    match nix::errno::Errno::last() {
                        nix::errno::Errno::EINTR => continue,
                        nix::errno::Errno::ECHILD => libc::_exit(main_exit.unwrap_or(125)),
                        _ => libc::_exit(125),
                    }
                }
            }
        },
        Err(_) => unsafe {
            let msg = b"rauha-shim: PID 1 failed to start workload\n";
            let _ = libc::write(2, msg.as_ptr() as _, msg.len());
            libc::_exit(125);
        },
    }
}

#[cfg(target_os = "linux")]
fn wait_status_exit_code(status: libc::c_int) -> Option<libc::c_int> {
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Some(128 + libc::WTERMSIG(status))
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn cstring_vec(values: &[String], field: &str) -> anyhow::Result<Vec<std::ffi::CString>> {
    values
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            std::ffi::CString::new(value.as_str())
                .map_err(|_| anyhow::anyhow!("{field}[{idx}] contains an interior NUL byte"))
        })
        .collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{cstring_vec, wait_status_exit_code, ProcessSecurity};
    use oci_spec::runtime::{Capabilities, LinuxCapabilitiesBuilder, ProcessBuilder};

    #[test]
    fn rejects_interior_nul_in_process_args() {
        let err = cstring_vec(&["/bin/sh\0bad".to_string()], "process.args")
            .expect_err("interior NUL must be rejected");

        assert!(err.to_string().contains("process.args[0]"));
    }

    #[test]
    fn empty_oci_capabilities_mean_zero_process_capabilities() {
        let capabilities = LinuxCapabilitiesBuilder::default()
            .bounding(Capabilities::default())
            .effective(Capabilities::default())
            .inheritable(Capabilities::default())
            .permitted(Capabilities::default())
            .ambient(Capabilities::default())
            .build()
            .unwrap();
        let process = ProcessBuilder::default()
            .capabilities(capabilities)
            .no_new_privileges(true)
            .build()
            .unwrap();

        assert_eq!(
            ProcessSecurity::from_process(&process).unwrap(),
            ProcessSecurity {
                no_new_privileges: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn wait_status_preserves_main_exit_code() {
        assert_eq!(wait_status_exit_code(7 << 8), Some(7));
        assert_eq!(
            wait_status_exit_code(libc::SIGTERM),
            Some(128 + libc::SIGTERM)
        );
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
///
/// Runs in the post-fork child, so it must be async-signal-safe: no heap
/// allocation. Paths are pre-allocated `CStr`s; directory create/remove use
/// `libc` directly (not `std::fs`); errors are returned as static `&str`
/// messages for the caller to `libc::write` + `_exit`.
#[cfg(target_os = "linux")]
fn do_pivot_root(
    new_root: &std::ffi::CStr,
    old_root: &std::ffi::CStr,
) -> Result<(), &'static [u8]> {
    use nix::mount::{mount, umount2, MntFlags, MsFlags};

    // Bind-mount new_root onto itself (required by pivot_root).
    mount(
        Some(new_root),
        new_root,
        None::<&std::ffi::CStr>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&std::ffi::CStr>,
    )
    .map_err(|_| &b"rauha-shim: bind-mount rootfs failed\n"[..])?;

    // Create the pivot-old mountpoint (ignore EEXIST). libc::mkdir is
    // async-signal-safe; std::fs would allocate.
    unsafe {
        libc::mkdir(old_root.as_ptr(), 0o755);
    }

    nix::unistd::pivot_root(new_root, old_root)
        .map_err(|_| &b"rauha-shim: pivot_root failed\n"[..])?;
    nix::unistd::chdir(c"/").map_err(|_| &b"rauha-shim: chdir(/) failed\n"[..])?;

    // Unmount old root.
    umount2(c"/.pivot_old", MntFlags::MNT_DETACH)
        .map_err(|_| &b"rauha-shim: umount old root failed\n"[..])?;
    unsafe {
        libc::rmdir(c"/.pivot_old".as_ptr());
    }

    Ok(())
}

/// Redirect stdout and stderr to log files.
#[cfg(target_os = "linux")]
/// Redirect stdout/stderr to log files using raw open() syscall.
///
/// Async-signal-safe: uses pre-allocated CStrings and libc::open directly.
/// No Rust allocation, no File::create, no global locks.
fn redirect_stdio_raw(stdout_path: &std::ffi::CStr, stderr_path: &std::ffi::CStr) {
    unsafe {
        let fd = libc::open(
            stdout_path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd >= 0 {
            libc::dup2(fd, 1);
            libc::close(fd);
        }

        let fd = libc::open(
            stderr_path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd >= 0 {
            libc::dup2(fd, 2);
            libc::close(fd);
        }
    }
}
