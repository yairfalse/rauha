//! bprm_check_security LSM hook — deny cross-zone exec.
//!
//! Prevents a process in one zone from executing a binary that
//! belongs to a different zone.

use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, is_cross_zone_allowed, INODE_ZONE_MAP};
use rauha_ebpf_common::ZONE_FLAG_GLOBAL;

/// Called from the bprm_check_security LSM hook.
///
/// LSM args: bprm_check_security(struct linux_binprm *bprm)
/// We need bprm->file->f_inode->i_ino.
///
/// Returns 0 to allow, -1 (EPERM) to deny.
pub fn bprm_check_security(ctx: &LsmContext) -> i32 {
    match try_bprm_check(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_bprm_check(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    // struct linux_binprm { ... struct file *file; ... }
    // file is at offset 168 in linux_binprm (kernel 6.1+).
    let bprm_ptr: u64 = unsafe { ctx.arg(0) };
    if bprm_ptr == 0 {
        return Ok(0);
    }

    let file_ptr: u64 = unsafe {
        let ptr = (bprm_ptr + 168) as *const u64;
        core::ptr::read_volatile(ptr)
    };
    if file_ptr == 0 {
        return Ok(0);
    }

    // file->f_inode (offset 32) -> i_ino (offset 64)
    let inode_ptr: u64 = unsafe {
        let ptr = (file_ptr + 32) as *const u64;
        core::ptr::read_volatile(ptr)
    };
    if inode_ptr == 0 {
        return Ok(0);
    }

    let ino: u64 = unsafe {
        let ptr = (inode_ptr + 64) as *const u64;
        core::ptr::read_volatile(ptr)
    };

    let file_zone_id = match unsafe { INODE_ZONE_MAP.get(&ino) } {
        Some(&zone_id) => zone_id,
        None => return Ok(0),
    };

    if caller.zone_id == file_zone_id {
        return Ok(0);
    }

    if is_cross_zone_allowed(caller.zone_id, file_zone_id) {
        return Ok(0);
    }

    Ok(-1)
}
