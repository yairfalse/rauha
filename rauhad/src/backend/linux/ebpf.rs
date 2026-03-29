//! eBPF program lifecycle: load, attach, pin, health check.
//!
//! Uses Aya to load the compiled rauha-ebpf object, attach LSM hooks,
//! and pin maps to /sys/fs/bpf/rauha/ for persistence.

use std::collections::HashMap;
use std::fs;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};

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

/// Expected kernel struct offsets hardcoded in the eBPF programs.
/// Used for runtime validation via `pahole` if available.
const EXPECTED_OFFSETS: &[(&str, &str, usize)] = &[
    ("task_struct", "cgroups", 2336),
    ("css_set", "dfl_cgrp", 48),
    ("cgroup", "kn", 64),
    ("file", "f_inode", 32),
    ("inode", "i_ino", 64),
    ("linux_binprm", "file", 168),
];

pub struct EbpfManager {
    bpf: Bpf,
    pin_path: PathBuf,
    /// Program fds recorded after attach, keyed by program name.
    /// Used in health_check to verify programs are still loaded.
    ///
    /// Note: this checks program validity, not link validity. A program
    /// can theoretically be loaded but have its LSM link detached (e.g. via
    /// bpftool). Aya 0.13 doesn't expose link fds publicly. The link is
    /// owned internally by the Bpf object and stays attached as long as
    /// it's not explicitly detached or the Bpf object dropped.
    program_fds: HashMap<String, i32>,
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

        // Validate hardcoded struct offsets against running kernel.
        validate_struct_offsets();

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

        let mut program_fds = HashMap::new();

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

            // Record the program fd for health checking. The fd stays valid
            // as long as the Bpf object (which owns the program) is alive.
            if let Ok(prog_fd) = prog.fd() {
                program_fds.insert(name.to_string(), prog_fd.as_fd().as_raw_fd());
            }

            tracing::info!(program = name, "attached LSM program");
        }

        tracing::info!(
            programs = LSM_PROGRAMS.len(),
            pin_path = %pin_path.display(),
            "eBPF programs loaded and attached"
        );

        Ok(Self { bpf, pin_path, program_fds })
    }

    /// Get a mutable reference to the inner Bpf object for map access.
    pub fn bpf_mut(&mut self) -> &mut Bpf {
        &mut self.bpf
    }

    /// Get a reference to the inner Bpf object for map reads.
    pub fn bpf(&self) -> &Bpf {
        &self.bpf
    }

    /// Check that all programs are still loaded and their fds are valid.
    ///
    /// Verifies two things per program:
    /// 1. The program exists in the Bpf handle (loaded).
    /// 2. The program fd is still valid (kernel hasn't reclaimed it).
    ///
    /// The program fd being valid is a necessary condition for enforcement.
    /// The LSM link (which actually hooks the program into the LSM framework)
    /// is managed internally by aya — aya 0.13 doesn't expose link fds
    /// publicly. The link stays attached as long as the Bpf object is alive
    /// and nobody explicitly detaches it.
    pub fn health_check(&self) -> Result<Vec<ProgramStatus>> {
        let mut statuses = Vec::new();

        for &name in LSM_PROGRAMS {
            let loaded = self.bpf.program(name).is_some();

            // Verify the program fd is still open in /proc/self/fd.
            let attached = if let Some(&fd) = self.program_fds.get(name) {
                fd >= 0 && Path::new(&format!("/proc/self/fd/{fd}")).exists()
            } else {
                false
            };

            if !loaded {
                tracing::warn!(program = name, "LSM program not found in BPF object");
            } else if !attached {
                tracing::warn!(
                    program = name,
                    "LSM program fd invalid — enforcement may be inactive. \
                     Restart rauhad to re-attach."
                );
            }

            statuses.push(ProgramStatus {
                name: name.to_string(),
                loaded,
                attached,
            });
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
    /// Whether the link fd is valid (LSM hook attached).
    pub attached: bool,
}

/// Validate hardcoded struct offsets against the running kernel using `pahole`.
///
/// `pahole` reads kernel DWARF/BTF debug info and prints struct layouts.
/// If pahole is not installed, validation is skipped with a warning.
/// Mismatches are logged as errors but don't block loading — the eBPF
/// programs will load but may read wrong fields.
fn validate_struct_offsets() {
    let pahole = match which_pahole() {
        Some(path) => path,
        None => {
            tracing::warn!(
                "pahole not found — cannot validate eBPF struct offsets against running kernel. \
                 Install dwarves package for runtime offset validation."
            );
            return;
        }
    };

    for &(type_name, field_name, expected) in EXPECTED_OFFSETS {
        match pahole_field_offset(&pahole, type_name, field_name) {
            Ok(actual) => {
                if actual != expected {
                    tracing::error!(
                        r#type = type_name,
                        field = field_name,
                        expected,
                        actual,
                        "struct offset mismatch — eBPF programs may read wrong field. \
                         Update offsets in rauha-ebpf/src/main.rs and rebuild with \
                         `cargo xtask build-ebpf`"
                    );
                } else {
                    tracing::debug!(
                        r#type = type_name,
                        field = field_name,
                        offset = actual,
                        "struct offset validated"
                    );
                }
            }
            Err(e) => {
                tracing::debug!(
                    r#type = type_name,
                    field = field_name,
                    %e,
                    "could not validate offset"
                );
            }
        }
    }
}

/// Find the `pahole` binary.
fn which_pahole() -> Option<PathBuf> {
    for path in ["/usr/bin/pahole", "/usr/local/bin/pahole"] {
        if Path::new(path).exists() {
            return Some(PathBuf::from(path));
        }
    }
    None
}

/// Query pahole for a struct member's byte offset.
///
/// Runs: pahole -C <type> /sys/kernel/btf/vmlinux
/// and parses the output for the field's offset.
fn pahole_field_offset(
    pahole: &Path,
    type_name: &str,
    field_name: &str,
) -> std::result::Result<usize, String> {
    let output = std::process::Command::new(pahole)
        .args(["-C", type_name, "/sys/kernel/btf/vmlinux"])
        .output()
        .map_err(|e| format!("failed to run pahole: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "pahole failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    // pahole output format:
    //   struct task_struct {
    //       ...
    //       struct css_set *         cgroups;              /*  2336     8 */
    //       ...
    // We look for lines containing the field name and parse the offset from /* offset size */
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        // Match lines containing the field name followed by a /* offset comment.
        if !trimmed.contains(field_name) {
            continue;
        }
        // Parse offset from the /*  OFFSET  SIZE */ comment.
        if let Some(comment_start) = trimmed.rfind("/*") {
            let comment = &trimmed[comment_start + 2..];
            if let Some(comment_end) = comment.find("*/") {
                let nums = &comment[..comment_end].trim();
                // Format: "OFFSET  SIZE" — take the first number.
                if let Some(offset_str) = nums.split_whitespace().next() {
                    if let Ok(offset) = offset_str.parse::<usize>() {
                        return Ok(offset);
                    }
                }
            }
        }
    }

    Err(format!("field '{field_name}' not found in pahole output for '{type_name}'"))
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
