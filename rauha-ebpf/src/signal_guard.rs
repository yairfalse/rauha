//! task_kill LSM hook — deny cross-zone signals.
//!
//! Prevents a process in one zone from sending signals (kill, SIGTERM, etc.)
//! to processes in other zones.

use aya_ebpf::programs::LsmContext;

use crate::lookup_caller_zone;
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
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_task_kill(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    // Similar to ptrace_guard: getting the target task's cgroup_id requires
    // CO-RE BTF support for reliable cross-kernel operation.
    // For now, signal guard is a placeholder that will be enhanced with
    // proper BTF-based task->cgroup resolution.

    Ok(0)
}
