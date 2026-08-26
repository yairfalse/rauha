#[cfg(any(target_os = "linux", test))]
use std::ffi::OsString;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Stdio;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const CRUN: &str = "/usr/bin/crun";

/// A foreground crun process supervised by the zone shim.
pub struct RuntimeProcess {
    child: Child,
    runtime_root: PathBuf,
    id: String,
    cleaned: bool,
}

impl RuntimeProcess {
    pub fn signal(&self, signal: i32) -> anyhow::Result<()> {
        let output = runtime_command(&self.runtime_root)
            .arg("kill")
            .arg(&self.id)
            .arg(signal.to_string())
            .output()?;
        if output.status.success() {
            Ok(())
        } else {
            anyhow::bail!(
                "crun kill failed for {}: {}",
                self.id,
                String::from_utf8_lossy(&output.stderr).trim()
            )
        }
    }

    /// Return the workload exit code once crun exits and clean its runtime state.
    pub fn try_wait(&mut self) -> Option<i32> {
        let status = self.child.try_wait().ok()??;
        self.delete();
        Some(status.code().unwrap_or(125))
    }

    pub fn stop_and_delete(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.signal(9);
        }
        self.delete();

        let deadline = Instant::now() + Duration::from_secs(5);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn delete(&mut self) {
        if self.cleaned {
            return;
        }
        let _ = runtime_command(&self.runtime_root)
            .args(["delete", "--force", &self.id])
            .status();
        self.cleaned = true;
    }
}

/// Start an OCI bundle with crun while the shim remains its foreground supervisor.
pub fn start_with_crun(
    container_id: &str,
    spec_json: &str,
    rootfs_root: &Path,
) -> anyhow::Result<(RuntimeProcess, u32)> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (container_id, spec_json, rootfs_root);
        anyhow::bail!("crun execution is only supported on Linux")
    }

    #[cfg(target_os = "linux")]
    {
        if !Path::new(CRUN).is_file() {
            anyhow::bail!("required OCI runtime is missing: {CRUN}");
        }

        let bundle = rootfs_root.join("containers").join(container_id);
        if !bundle.join("merged").is_dir() && !bundle.join("rootfs").is_dir() {
            anyhow::bail!("rootfs not found for container {container_id}");
        }

        let runtime_root = rootfs_root.join("runtime");
        std::fs::create_dir_all(&runtime_root)?;
        std::fs::write(bundle.join("config.json"), spec_json)?;

        let pid_file = bundle.join("init.pid");
        let _ = std::fs::remove_file(&pid_file);
        let log_dir = PathBuf::from("/run/rauha/containers").join(container_id);
        std::fs::create_dir_all(&log_dir)?;

        let mut command = runtime_command(&runtime_root);
        command
            .args(crun_run_args(&bundle, &pid_file, container_id))
            .stdin(Stdio::null())
            .stdout(Stdio::from(std::fs::File::create(
                log_dir.join("stdout.log"),
            )?))
            .stderr(Stdio::from(std::fs::File::create(
                log_dir.join("stderr.log"),
            )?));
        let mut child = command.spawn()?;

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(pid) = std::fs::read_to_string(&pid_file)
                .and_then(|pid| pid.trim().parse::<u32>().map_err(std::io::Error::other))
            {
                return Ok((
                    RuntimeProcess {
                        child,
                        runtime_root,
                        id: container_id.to_string(),
                        cleaned: false,
                    },
                    pid,
                ));
            }
            if let Some(status) = child.try_wait()? {
                let _ = runtime_command(&runtime_root)
                    .args(["delete", "--force", container_id])
                    .status();
                anyhow::bail!("crun exited before publishing the init PID: {status}");
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = runtime_command(&runtime_root)
                    .args(["delete", "--force", container_id])
                    .status();
                anyhow::bail!("crun did not publish the init PID within 30 seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn runtime_command(runtime_root: &Path) -> Command {
    let mut command = Command::new(CRUN);
    command
        .arg("--root")
        .arg(runtime_root)
        .arg("--cgroup-manager=disabled");
    command
}

#[cfg(any(target_os = "linux", test))]
fn crun_run_args(bundle: &Path, pid_file: &Path, container_id: &str) -> Vec<OsString> {
    vec![
        "run".into(),
        "--bundle".into(),
        bundle.as_os_str().into(),
        "--pid-file".into(),
        pid_file.as_os_str().into(),
        container_id.into(),
    ]
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
        version: 0x2008_0522,
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

/// fork(2)-equivalent clone3 used only by interactive exec.
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

#[cfg(test)]
mod tests {
    use super::crun_run_args;
    use std::path::Path;

    #[test]
    fn crun_runs_the_bundle_in_the_foreground_with_a_pid_file() {
        assert_eq!(
            crun_run_args(Path::new("/bundle"), Path::new("/bundle/init.pid"), "c1"),
            Vec::<std::ffi::OsString>::from(
                [
                    "run",
                    "--bundle",
                    "/bundle",
                    "--pid-file",
                    "/bundle/init.pid",
                    "c1"
                ]
                .map(std::ffi::OsString::from)
            )
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn empty_oci_capabilities_mean_zero_process_capabilities() {
        use super::ProcessSecurity;
        use oci_spec::runtime::{Capabilities, LinuxCapabilitiesBuilder, ProcessBuilder};

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
}
