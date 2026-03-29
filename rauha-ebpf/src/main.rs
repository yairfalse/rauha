#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{lsm, map},
    maps::HashMap,
    programs::LsmContext,
};
use rauha_ebpf_common::{ZoneCommKey, ZoneInfoKernel, ZonePolicyKernel, MAX_CGROUPS, MAX_INODES, MAX_ZONES};

mod file_guard;
mod exec_guard;
mod ptrace_guard;
mod signal_guard;
mod cgroup_lock;

/// Maps cgroup_id → ZoneInfoKernel. Tells us which zone a process belongs to.
#[map]
static ZONE_MEMBERSHIP: HashMap<u64, ZoneInfoKernel> = HashMap::with_max_entries(MAX_CGROUPS, 0);

/// Maps zone_id → ZonePolicyKernel. The enforcement policy for each zone.
#[map]
static ZONE_POLICY: HashMap<u32, ZonePolicyKernel> = HashMap::with_max_entries(MAX_ZONES, 0);

/// Maps inode → zone_id. Tracks which zone owns which files.
#[map]
static INODE_ZONE_MAP: HashMap<u64, u32> = HashMap::with_max_entries(MAX_INODES, 0);

/// Maps (src_zone, dst_zone) → u8. If entry exists, cross-zone communication is allowed.
#[map]
static ZONE_ALLOWED_COMMS: HashMap<ZoneCommKey, u8> = HashMap::with_max_entries(MAX_ZONES, 0);

/// Look up the caller's zone from their cgroup_id.
/// Returns None if the process is not in any zone (global/unzoned).
#[inline(always)]
fn lookup_caller_zone(ctx: &LsmContext) -> Option<ZoneInfoKernel> {
    let cgroup_id = unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() };
    unsafe { ZONE_MEMBERSHIP.get(&cgroup_id).copied() }
}

/// Read a u64 from kernel memory at `base + offset`.
///
/// Uses `bpf_probe_read_kernel` — the correct BPF helper for reading
/// kernel memory. Unlike raw pointer dereference (`read_volatile`), this
/// helper is recognized by the BPF verifier and handles fault recovery.
/// When BTF is loaded (via BpfLoader::btf()), the verifier can validate
/// these accesses against kernel type information.
///
/// Works for both pointer fields (which are u64 on 64-bit) and u64 scalars.
#[inline(always)]
unsafe fn read_kernel_u64(base: u64, offset: usize) -> Result<u64, i64> {
    let addr = (base + offset as u64) as *const u64;
    aya_ebpf::helpers::bpf_probe_read_kernel(addr).map_err(|e| e as i64)
}

/// Kernel struct field offsets for cgroup ID resolution.
///
/// These offsets are for the `task_struct -> css_set -> cgroup -> kernfs_node`
/// chain on kernel 6.1+. The BPF program is loaded with BTF from
/// /sys/kernel/btf/vmlinux, which allows the verifier to validate these
/// accesses. If offsets shift between kernel versions, update these constants
/// and rebuild with `cargo xtask build-ebpf`.
mod offsets {
    // task_struct->cgroups: offset to `struct css_set *cgroups` pointer.
    // Stable across 6.1–6.12. Verify with: pahole -C task_struct | grep cgroups
    pub const TASK_CGROUPS: usize = 2336;

    // css_set->dfl_cgrp: offset to `struct cgroup *dfl_cgrp` (the default
    // cgroup v2 cgroup for this css_set).
    pub const CSS_SET_DFL_CGRP: usize = 48;

    // cgroup->kn: offset to `struct kernfs_node *kn`.
    pub const CGROUP_KN: usize = 64;

    // kernfs_node->id: the kernfs node ID which is the cgroup_id used by
    // bpf_get_current_cgroup_id() and our ZONE_MEMBERSHIP map.
    pub const KERNFS_NODE_ID: usize = 0;

    // struct file->f_inode: pointer to the file's inode.
    pub const FILE_F_INODE: usize = 32;

    // struct inode->i_ino: the inode number.
    pub const INODE_I_INO: usize = 64;

    // struct linux_binprm->file: pointer to the file being exec'd.
    pub const BPRM_FILE: usize = 168;
}

/// Read a target task's cgroup_id by walking the task_struct pointer chain.
///
/// Traverses: task_struct->cgroups->dfl_cgrp->kn->id
///
/// Every dereference uses `bpf_probe_read_kernel` for verifier safety.
/// Returns the cgroup_id that can be looked up in ZONE_MEMBERSHIP.
#[inline(always)]
unsafe fn read_task_cgroup_id(task_ptr: u64) -> Result<u64, i64> {
    if task_ptr == 0 {
        return Err(-1);
    }

    let cgroups_ptr = read_kernel_u64(task_ptr, offsets::TASK_CGROUPS)?;
    if cgroups_ptr == 0 {
        return Err(-1);
    }

    let dfl_cgrp_ptr = read_kernel_u64(cgroups_ptr, offsets::CSS_SET_DFL_CGRP)?;
    if dfl_cgrp_ptr == 0 {
        return Err(-1);
    }

    let kn_ptr = read_kernel_u64(dfl_cgrp_ptr, offsets::CGROUP_KN)?;
    if kn_ptr == 0 {
        return Err(-1);
    }

    read_kernel_u64(kn_ptr, offsets::KERNFS_NODE_ID)
}

/// Look up a target task's zone by walking its task_struct to get cgroup_id,
/// then looking up that cgroup_id in ZONE_MEMBERSHIP.
#[inline(always)]
unsafe fn lookup_task_zone(task_ptr: u64) -> Option<ZoneInfoKernel> {
    let cgroup_id = read_task_cgroup_id(task_ptr).ok()?;
    ZONE_MEMBERSHIP.get(&cgroup_id).copied()
}

/// Read inode number from a `struct file *` pointer.
///
/// Traverses: file->f_inode->i_ino
#[inline(always)]
unsafe fn read_file_ino(file_ptr: u64) -> Result<u64, i64> {
    if file_ptr == 0 {
        return Err(-1);
    }

    let inode_ptr = read_kernel_u64(file_ptr, offsets::FILE_F_INODE)?;
    if inode_ptr == 0 {
        return Err(-1);
    }

    read_kernel_u64(inode_ptr, offsets::INODE_I_INO)
}

/// Check if cross-zone access from src to dst is allowed.
#[inline(always)]
fn is_cross_zone_allowed(src_zone: u32, dst_zone: u32) -> bool {
    if src_zone == dst_zone {
        return true;
    }
    let key = ZoneCommKey {
        src_zone,
        dst_zone,
    };
    unsafe { ZONE_ALLOWED_COMMS.get(&key).is_some() }
}

// --- LSM hook entry points ---

#[lsm(hook = "file_open")]
pub fn rauha_file_open(ctx: LsmContext) -> i32 {
    file_guard::file_open(&ctx)
}

#[lsm(hook = "bprm_check_security")]
pub fn rauha_bprm_check(ctx: LsmContext) -> i32 {
    exec_guard::bprm_check_security(&ctx)
}

#[lsm(hook = "ptrace_access_check")]
pub fn rauha_ptrace_check(ctx: LsmContext) -> i32 {
    ptrace_guard::ptrace_access_check(&ctx)
}

#[lsm(hook = "task_kill")]
pub fn rauha_task_kill(ctx: LsmContext) -> i32 {
    signal_guard::task_kill(&ctx)
}

#[lsm(hook = "cgroup_attach_task")]
pub fn rauha_cgroup_attach(ctx: LsmContext) -> i32 {
    cgroup_lock::cgroup_attach_task(&ctx)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
