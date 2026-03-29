//! task_kill LSM hook — deny cross-zone signals.
//!
//! Prevents a process in one zone from sending signals (kill, SIGTERM, etc.)
//! to processes in other zones.

use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, lookup_task_zone, is_cross_zone_allowed};
use rauha_ebpf_common::ZONE_FLAG_GLOBAL;

/// Called from the task_kill LSM hook.
///
/// LSM args: task_kill(struct task_struct *p, struct kernel_siginfo *info,
///                     int sig, const struct cred *cred)
///
/// Returns 0 to allow, -1 (EPERM) to deny.
pub fn task_kill(ctx: &LsmContext) -> i32 {
    match try_task_kill(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Fail open — deny-by-default would break signal delivery.
    }
}

#[inline(always)]
fn try_task_kill(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0), // Not in a zone → global → allow.
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    // arg 0 is the target task_struct pointer.
    let target_ptr: u64 = unsafe { ctx.arg(0) };
    if target_ptr == 0 {
        return Ok(0);
    }

    // Walk target task's cgroup chain to determine its zone.
    let target = match unsafe { lookup_task_zone(target_ptr) } {
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

    // Deny cross-zone signal.
    Ok(-1)
}
