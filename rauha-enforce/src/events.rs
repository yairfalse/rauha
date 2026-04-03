//! Ring buffer event reader for rauha-enforce.

use std::time::Duration;

use aya::maps::{MapData, RingBuf};
use rauha_ebpf_common::EnforcementEvent;
use tokio_util::sync::CancellationToken;

const HOOK_NAMES: [&str; 5] = [
    "file_open",
    "bprm_check",
    "ptrace_access_check",
    "task_kill",
    "cgroup_attach_task",
];

pub fn spawn_event_reader(ring_buf: RingBuf<MapData>, cancel: CancellationToken) {
    tokio::spawn(async move {
        let mut ring_buf = ring_buf;
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        tracing::info!("enforcement event reader started");

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("enforcement event reader stopped");
                    return;
                }
                _ = interval.tick() => {
                    while let Some(item) = ring_buf.next() {
                        if item.len() < std::mem::size_of::<EnforcementEvent>() {
                            continue;
                        }
                        let event: EnforcementEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const EnforcementEvent)
                        };
                        let hook = HOOK_NAMES.get(event.hook as usize).unwrap_or(&"unknown");
                        tracing::warn!(
                            hook = hook,
                            pid = event.pid,
                            caller_zone = event.caller_zone,
                            target_zone = event.target_zone,
                            context = event.context,
                            "DENY"
                        );
                    }
                }
            }
        }
    });
}
