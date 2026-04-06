#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{lsm, map},
    maps::{Array, HashMap, PerCpuArray, ring_buf::RingBuf},
    programs::LsmContext,
};
use rauha_ebpf_common::{
    EnforcementCounters, EnforcementEvent, SelfTestResult, ZoneCommKey, ZoneInfoKernel,
    ZonePolicyKernel, DECISION_DENY, DECISION_ERROR, ENFORCEMENT_COUNTER_ENTRIES, MAX_CGROUPS,
    MAX_INODES, MAX_ZONES,
};

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

/// Startup self-test: compares cgroup_id from BPF helper vs offset chain.
/// Written once by file_open on first invocation. Userspace reads to verify offsets.
#[map]
static SELF_TEST: Array<SelfTestResult> = Array::with_max_entries(1, 0);

/// Per-hook enforcement decision counters (one entry per LSM program, per CPU).
/// Userspace sums across CPUs to get totals.
#[map]
static ENFORCEMENT_COUNTERS: PerCpuArray<EnforcementCounters> =
    PerCpuArray::with_max_entries(ENFORCEMENT_COUNTER_ENTRIES, 0);

/// Ring buffer for streaming enforcement events to userspace.
/// 1024 pages = 4MB. At 48 bytes/event, holds ~87K events before wrapping.
/// Sized to resist audit-evasion attacks (attacker floods denies to fill buffer).
#[map]
static ENFORCEMENT_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 4096, 0);

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

/// Kernel struct field offsets — patched at load time by userspace.
///
/// These globals are set via `BpfLoader::set_global()` before the programs
/// are loaded. Userspace reads the real offsets from the running kernel's
/// BTF (via pahole) and injects them here. The defaults are for Linux 6.1+
/// and are used as fallback if pahole is not available.
///
/// This eliminates the portability problem of hardcoded offsets: any kernel
/// with BTF + pahole will get correct offsets automatically.
#[no_mangle]
static TASK_CGROUPS_OFFSET: u64 = 2336;
#[no_mangle]
static CSS_SET_DFL_CGRP_OFFSET: u64 = 48;
#[no_mangle]
static CGROUP_KN_OFFSET: u64 = 64;
#[no_mangle]
static KERNFS_NODE_ID_OFFSET: u64 = 0;
#[no_mangle]
static FILE_F_INODE_OFFSET: u64 = 32;
#[no_mangle]
static INODE_I_INO_OFFSET: u64 = 64;
#[no_mangle]
static BPRM_FILE_OFFSET: u64 = 168;

/// Convenience accessors that read the global values.
mod offsets {
    #[inline(always)]
    pub fn task_cgroups() -> usize {
        unsafe { core::ptr::read_volatile(&super::TASK_CGROUPS_OFFSET) as usize }
    }
    #[inline(always)]
    pub fn css_set_dfl_cgrp() -> usize {
        unsafe { core::ptr::read_volatile(&super::CSS_SET_DFL_CGRP_OFFSET) as usize }
    }
    #[inline(always)]
    pub fn cgroup_kn() -> usize {
        unsafe { core::ptr::read_volatile(&super::CGROUP_KN_OFFSET) as usize }
    }
    #[inline(always)]
    pub fn kernfs_node_id() -> usize {
        unsafe { core::ptr::read_volatile(&super::KERNFS_NODE_ID_OFFSET) as usize }
    }
    #[inline(always)]
    pub fn file_f_inode() -> usize {
        unsafe { core::ptr::read_volatile(&super::FILE_F_INODE_OFFSET) as usize }
    }
    #[inline(always)]
    pub fn inode_i_ino() -> usize {
        unsafe { core::ptr::read_volatile(&super::INODE_I_INO_OFFSET) as usize }
    }
    #[inline(always)]
    pub fn bprm_file() -> usize {
        unsafe { core::ptr::read_volatile(&super::BPRM_FILE_OFFSET) as usize }
    }
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

    let cgroups_ptr = read_kernel_u64(task_ptr, offsets::task_cgroups())?;
    if cgroups_ptr == 0 {
        return Err(-1);
    }

    let dfl_cgrp_ptr = read_kernel_u64(cgroups_ptr, offsets::css_set_dfl_cgrp())?;
    if dfl_cgrp_ptr == 0 {
        return Err(-1);
    }

    let kn_ptr = read_kernel_u64(dfl_cgrp_ptr, offsets::cgroup_kn())?;
    if kn_ptr == 0 {
        return Err(-1);
    }

    read_kernel_u64(kn_ptr, offsets::kernfs_node_id())
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

    let inode_ptr = read_kernel_u64(file_ptr, offsets::file_f_inode())?;
    if inode_ptr == 0 {
        return Err(-1);
    }

    read_kernel_u64(inode_ptr, offsets::inode_i_ino())
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

/// Emit a deny enforcement event to the ring buffer.
///
/// Best-effort: if the ring buffer is full, the event is silently dropped.
/// Counters (count_decision) remain the source of truth for totals.
#[inline(always)]
fn emit_deny_event(hook: u8, caller_zone: u32, target_zone: u32, context: u64) {
    let pid = (unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() } >> 32) as u32;
    let ts = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    let event = EnforcementEvent {
        timestamp_ns: ts,
        pid,
        hook,
        decision: DECISION_DENY,
        _pad0: [0; 2],
        caller_zone,
        target_zone,
        context,
        _reserved: [0; 2],
    };

    if let Some(mut entry) = unsafe { ENFORCEMENT_EVENTS.reserve::<EnforcementEvent>(0) } {
        entry.write(event);
        entry.submit(0);
    }
}

/// Emit an error enforcement event to the ring buffer.
///
/// Called when a hook hits an error path (kernel read failure, null pointer, etc.)
/// and falls open. Makes the fail-open observable — operators can detect when
/// enforcement is degraded by monitoring error events.
#[inline(always)]
fn emit_error_event(hook: u8) {
    let pid = (unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() } >> 32) as u32;
    let ts = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    let event = EnforcementEvent {
        timestamp_ns: ts,
        pid,
        hook,
        decision: DECISION_ERROR,
        _pad0: [0; 2],
        caller_zone: 0,
        target_zone: 0,
        context: 0,
        _reserved: [0; 2],
    };

    if let Some(mut entry) = unsafe { ENFORCEMENT_EVENTS.reserve::<EnforcementEvent>(0) } {
        entry.write(event);
        entry.submit(0);
    }
}

/// Check if a cross-zone task operation (ptrace, signal) should be denied.
///
/// Shared logic for ptrace_guard and signal_guard — both hooks have the same
/// signature pattern: ctx.arg(0) is the target task_struct pointer.
///
/// `hook` identifies the caller for ring buffer event emission.
///
/// Returns 0 (allow) or -1 (deny).
#[inline(always)]
fn check_cross_zone_task_access(ctx: &LsmContext, hook: u8) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & rauha_ebpf_common::ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    let target_ptr: u64 = unsafe { ctx.arg(0) };
    if target_ptr == 0 {
        return Ok(0);
    }

    let target = match unsafe { lookup_task_zone(target_ptr) } {
        Some(info) => info,
        None => return Ok(0),
    };

    if is_cross_zone_allowed(caller.zone_id, target.zone_id) {
        return Ok(0);
    }

    emit_deny_event(hook, caller.zone_id, target.zone_id, 0);
    Ok(-1)
}

/// Run the one-shot self-test: write both cgroup_id derivation paths to SELF_TEST map.
///
/// Called from file_open on first invocation. Skips if already populated (nonzero).
/// The two values should be identical if the hardcoded offsets are correct.
#[inline(always)]
unsafe fn maybe_run_self_test() {
    // One-shot guard: skip if already written.
    if let Some(existing) = SELF_TEST.get(0) {
        if existing.helper_cgroup_id != 0 {
            return;
        }
    }

    let helper_id = aya_ebpf::helpers::bpf_get_current_cgroup_id();
    let task_ptr = aya_ebpf::helpers::bpf_get_current_task() as u64;
    let offset_id = read_task_cgroup_id(task_ptr).unwrap_or(0);

    let result = SelfTestResult {
        helper_cgroup_id: helper_id,
        offset_cgroup_id: offset_id,
    };

    // get_ptr_mut returns a mutable pointer to the array slot.
    if let Some(slot) = SELF_TEST.get_ptr_mut(0) {
        *slot = result;
    }
}

/// Increment enforcement counters for a hook decision.
///
/// `prog_idx`: program index constant (PROG_FILE_OPEN, etc.)
/// `allow`: true if the decision was to allow (return 0)
/// `is_error`: true if the hook hit an error path and fell through
#[inline(always)]
fn count_decision(prog_idx: u32, allow: bool, is_error: bool) {
    if let Some(counters) = unsafe { ENFORCEMENT_COUNTERS.get_ptr_mut(prog_idx) } {
        let c = unsafe { &mut *counters };
        if is_error {
            c.error += 1;
        } else if allow {
            c.allow += 1;
        } else {
            c.deny += 1;
        }
    }
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
