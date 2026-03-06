//! file_open LSM hook — deny cross-zone file access.
//!
//! When a process opens a file, check if the file's inode belongs to a
//! different zone. If so, deny unless the zones are allowed to communicate.

use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, is_cross_zone_allowed, INODE_ZONE_MAP};
use rauha_ebpf_common::ZONE_FLAG_GLOBAL;

/// Called from the file_open LSM hook.
///
/// LSM args: file_open(struct file *file)
/// The file's inode is at file->f_inode->i_ino.
///
/// Returns 0 to allow, -1 (EPERM) to deny.
pub fn file_open(ctx: &LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // On error, allow — fail open to avoid breaking the system.
    }
}

#[inline(always)]
fn try_file_open(ctx: &LsmContext) -> Result<i32, i64> {
    // Get caller's zone.
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0), // Not in a zone → global → allow.
    };

    // Global zones can access everything.
    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    // Read the file's inode number from the LSM context.
    // file_open signature: int file_open(struct file *file)
    // struct file → f_inode → i_ino
    // file is at arg 0, f_inode is the first pointer field we care about.
    //
    // We read the inode from the file struct:
    // struct file { ... struct inode *f_inode; ... }
    // On most kernels, f_inode is at offset 32 in struct file.
    // struct inode { ... unsigned long i_ino; ... }
    // i_ino is at offset 64 in struct inode.
    let file_ptr: u64 = unsafe { ctx.arg(0) };
    if file_ptr == 0 {
        return Ok(0);
    }

    // Read f_inode pointer (offset 32 in struct file).
    let inode_ptr: u64 = unsafe {
        let ptr = (file_ptr + 32) as *const u64;
        core::ptr::read_volatile(ptr)
    };
    if inode_ptr == 0 {
        return Ok(0);
    }

    // Read i_ino (offset 64 in struct inode).
    let ino: u64 = unsafe {
        let ptr = (inode_ptr + 64) as *const u64;
        core::ptr::read_volatile(ptr)
    };

    // Look up which zone owns this inode.
    let file_zone_id = match unsafe { INODE_ZONE_MAP.get(&ino) } {
        Some(&zone_id) => zone_id,
        None => return Ok(0), // Untracked inode → allow.
    };

    // Same zone → allow.
    if caller.zone_id == file_zone_id {
        return Ok(0);
    }

    // Different zone → check allowed comms.
    if is_cross_zone_allowed(caller.zone_id, file_zone_id) {
        return Ok(0);
    }

    // Deny cross-zone file access.
    Ok(-1)
}
