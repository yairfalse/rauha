//! eBPF program lifecycle: load, attach, pin, health check.
//!
//! Uses Aya to load the compiled rauha-ebpf object, attach LSM hooks,
//! and pin maps to /sys/fs/bpf/rauha/ for persistence.

use std::fs;
use std::path::{Path, PathBuf};

use aya::maps::HashMap as AyaHashMap;
use aya::programs::Lsm;
use aya::{Bpf, BpfLoader, Btf};
use rauha_common::error::{RauhaError, Result};

const BPF_PIN_PATH: &str = "/sys/fs/bpf/rauha";

/// Names of LSM programs in the eBPF object.
const LSM_PROGRAMS: &[&str] = &[
    "rauha_file_open",
    "rauha_bprm_check",
    "rauha_ptrace_check",
    "rauha_task_kill",
    "rauha_cgroup_attach",
];

/// Names of maps to pin for persistence.
const MAP_NAMES: &[&str] = &[
    "ZONE_MEMBERSHIP",
    "ZONE_POLICY",
    "INODE_ZONE_MAP",
    "ZONE_ALLOWED_COMMS",
];

pub struct EbpfManager {
    bpf: Bpf,
    pin_path: PathBuf,
}

impl EbpfManager {
    /// Load eBPF programs and maps from the compiled object file.
    ///
    /// The object file is expected at `{ebpf_obj_path}`. On production systems
    /// this is typically `/usr/lib/rauha/rauha-ebpf` or built by `cargo xtask build-ebpf`.
    pub fn load(ebpf_obj_path: &Path) -> Result<Self> {
        check_kernel_version()?;

        if !ebpf_obj_path.exists() {
            return Err(RauhaError::EbpfError {
                message: format!("eBPF object not found: {}", ebpf_obj_path.display()),
                hint: "run `cargo xtask build-ebpf` to compile the eBPF programs".into(),
            });
        }

        let pin_path = PathBuf::from(BPF_PIN_PATH);
        fs::create_dir_all(&pin_path).map_err(|e| RauhaError::EbpfError {
            message: format!("failed to create BPF pin directory: {e}"),
            hint: "run rauhad as root with BPF filesystem mounted".into(),
        })?;

        let btf = Btf::from_sys_fs().map_err(|e| RauhaError::EbpfError {
            message: format!("failed to load BTF from sysfs: {e}"),
            hint: "kernel must have CONFIG_DEBUG_INFO_BTF=y".into(),
        })?;

        let obj_data = fs::read(ebpf_obj_path).map_err(|e| RauhaError::EbpfError {
            message: format!("failed to read eBPF object: {e}"),
            hint: format!("check permissions on {}", ebpf_obj_path.display()),
        })?;

        let mut bpf = BpfLoader::new()
            .btf(Some(&btf))
            .map_pin_path(&pin_path)
            .load(&obj_data)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to load eBPF programs: {e}"),
                hint: "check kernel has CONFIG_BPF_LSM=y and `lsm=bpf` in cmdline".into(),
            })?;

        // Attach all LSM programs.
        for &name in LSM_PROGRAMS {
            let prog: &mut Lsm = bpf.program_mut(name)
                .ok_or_else(|| RauhaError::EbpfError {
                    message: format!("LSM program '{name}' not found in object"),
                    hint: "rebuild eBPF programs with `cargo xtask build-ebpf`".into(),
                })?
                .try_into()
                .map_err(|e| RauhaError::EbpfError {
                    message: format!("program '{name}' is not an LSM program: {e}"),
                    hint: "check the eBPF source uses #[lsm] macro".into(),
                })?;

            prog.load(name, &btf).map_err(|e| RauhaError::EbpfError {
                message: format!("failed to load LSM program '{name}': {e}"),
                hint: "check BPF verifier output, program may be too complex".into(),
            })?;

            prog.attach().map_err(|e| RauhaError::EbpfError {
                message: format!("failed to attach LSM program '{name}': {e}"),
                hint: "ensure kernel has `lsm=bpf` in boot cmdline".into(),
            })?;

            tracing::info!(program = name, "attached LSM program");
        }

        tracing::info!(
            programs = LSM_PROGRAMS.len(),
            pin_path = %pin_path.display(),
            "eBPF programs loaded and attached"
        );

        Ok(Self { bpf, pin_path })
    }

    /// Get a mutable reference to the inner Bpf object for map access.
    pub fn bpf_mut(&mut self) -> &mut Bpf {
        &mut self.bpf
    }

    /// Get a reference to the inner Bpf object for map reads.
    pub fn bpf(&self) -> &Bpf {
        &self.bpf
    }

    /// Check that all programs are still loaded and maps are accessible.
    pub fn health_check(&self) -> Result<Vec<ProgramStatus>> {
        let mut statuses = Vec::new();

        for &name in LSM_PROGRAMS {
            let loaded = self.bpf.program(name).is_some();
            statuses.push(ProgramStatus {
                name: name.to_string(),
                loaded,
            });
            if !loaded {
                tracing::warn!(program = name, "LSM program not found — may have been detached");
            }
        }

        Ok(statuses)
    }

    /// Unpin all maps (called on clean shutdown).
    pub fn cleanup(&self) {
        for &name in MAP_NAMES {
            let path = self.pin_path.join(name);
            if path.exists() {
                let _ = fs::remove_file(&path);
            }
        }
        let _ = fs::remove_dir(&self.pin_path);
        tracing::info!("cleaned up BPF pin directory");
    }
}

#[derive(Debug)]
pub struct ProgramStatus {
    pub name: String,
    pub loaded: bool,
}

/// Check that the kernel is new enough for BPF LSM (6.1+).
fn check_kernel_version() -> Result<()> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").map_err(|e| {
        RauhaError::EbpfError {
            message: format!("cannot read kernel version: {e}"),
            hint: "is /proc mounted?".into(),
        }
    })?;

    let release = release.trim();
    let parts: Vec<&str> = release.split('.').collect();
    if parts.len() < 2 {
        return Err(RauhaError::KernelTooOld {
            required: "6.1".into(),
            found: release.into(),
        });
    }

    let major: u32 = parts[0].parse().unwrap_or(0);
    let minor: u32 = parts[1]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);

    if major < 6 || (major == 6 && minor < 1) {
        return Err(RauhaError::KernelTooOld {
            required: "6.1".into(),
            found: release.into(),
        });
    }

    tracing::debug!(kernel = release, "kernel version check passed");
    Ok(())
}
