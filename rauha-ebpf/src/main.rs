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
