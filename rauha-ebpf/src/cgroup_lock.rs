//! cgroup_attach_task LSM hook — prevent zone escape.
//!
//! Once a task is placed in a zone's cgroup, prevent it from being moved
//! to a different cgroup (which would effectively escape the zone).

use aya_ebpf::programs::LsmContext;

use crate::lookup_caller_zone;
use rauha_ebpf_common::ZONE_FLAG_GLOBAL;

/// Called from the cgroup_attach_task LSM hook.
///
/// LSM args: cgroup_attach_task(struct cgroup *dst_cgrp, struct task_struct *leader)
///
/// Returns 0 to allow, -1 (EPERM) to deny.
pub fn cgroup_attach_task(ctx: &LsmContext) -> i32 {
    match try_cgroup_attach(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_cgroup_attach(ctx: &LsmContext) -> Result<i32, i64> {
    // If the current process is in a zone, deny moving to a different cgroup.
    // This prevents zone escape by cgroup migration.
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0), // Not in a zone → allow cgroup operations.
    };

    // Global zones manage other zones — they can move tasks.
    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    // A non-global zoned process is trying to attach a task to a cgroup.
    // This could be a zone escape attempt. Deny it.
    //
    // The daemon (running in global zone) will be the one that assigns
    // processes to zone cgroups. Non-global zone processes should never
    // need to do cgroup operations.
    Ok(-1)
}
