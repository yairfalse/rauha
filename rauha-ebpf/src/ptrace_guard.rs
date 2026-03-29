//! ptrace_access_check LSM hook — deny cross-zone ptrace.
//!
//! Prevents a process in one zone from ptracing a process in another zone.
//! This is critical for isolation: ptrace can read/write memory and registers.
//!
//! Also checks ZONE_POLICY: if the caller's zone policy has
//! POLICY_FLAG_ALLOW_PTRACE set (via CAP_SYS_PTRACE in policy), ptrace is
//! allowed even cross-zone. This matches the intent: zones with SYS_PTRACE
//! are explicitly granted debugging capability.

use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, lookup_task_zone, is_cross_zone_allowed, ZONE_POLICY};
use rauha_ebpf_common::{ZONE_FLAG_GLOBAL, POLICY_FLAG_ALLOW_PTRACE};

/// Called from the ptrace_access_check LSM hook.
///
/// LSM args: ptrace_access_check(struct task_struct *child, unsigned int mode)
///
/// Returns 0 to allow, -1 (EPERM) to deny.
pub fn ptrace_access_check(ctx: &LsmContext) -> i32 {
    match try_ptrace_check(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Fail open — deny-by-default would break the system.
    }
}

#[inline(always)]
fn try_ptrace_check(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0), // Not in a zone → global → allow.
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    // Check zone policy: if ALLOW_PTRACE is set, allow all ptrace from this zone.
    if let Some(policy) = unsafe { ZONE_POLICY.get(&caller.zone_id) } {
        if policy.flags & POLICY_FLAG_ALLOW_PTRACE != 0 {
            return Ok(0);
        }
    }

    // arg 0 is the target task_struct pointer.
    let child_ptr: u64 = unsafe { ctx.arg(0) };
    if child_ptr == 0 {
        return Ok(0);
    }

    // Walk target task's cgroup chain to determine its zone.
    let target = match unsafe { lookup_task_zone(child_ptr) } {
        Some(info) => info,
        None => return Ok(0), // Target not in any zone → allow.
    };

    // Same zone → allow.
    if caller.zone_id == target.zone_id {
        return Ok(0);
    }

    // Different zone → check allowed comms.
    if is_cross_zone_allowed(caller.zone_id, target.zone_id) {
        return Ok(0);
    }

    // Deny cross-zone ptrace.
    Ok(-1)
}
