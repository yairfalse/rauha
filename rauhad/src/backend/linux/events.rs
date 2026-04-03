//! Enforcement event reader — drains the BPF ring buffer in a background task.
//!
//! Deny events from all 5 LSM hooks are streamed here and logged via tracing.
//! Future: broadcast to gRPC WatchEvents subscribers.

use std::time::Duration;

use aya::maps::{MapData, RingBuf};
use rauha_ebpf_common::EnforcementEvent;

const HOOK_NAMES: [&str; 5] = [
    "file_open",
    "bprm_check",
    "ptrace_access_check",
    "task_kill",
    "cgroup_attach_task",
];

/// Start the ring buffer reader as a background tokio task.
///
/// Returns a JoinHandle. The task runs until `cancel` is triggered.
pub fn spawn_event_reader(
    ring_buf: RingBuf<MapData>,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_event_loop(ring_buf, cancel).await;
    })
}

async fn run_event_loop(
    mut ring_buf: RingBuf<MapData>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    tracing::info!("enforcement event reader started");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                // Drain remaining events before exiting.
                drain_events(&mut ring_buf);
                tracing::info!("enforcement event reader stopped");
                return;
            }
            _ = interval.tick() => {
                drain_events(&mut ring_buf);
            }
        }
    }
}

fn drain_events(ring_buf: &mut RingBuf<MapData>) {
    while let Some(item) = ring_buf.next() {
        if item.len() < std::mem::size_of::<EnforcementEvent>() {
            tracing::warn!(len = item.len(), "undersized enforcement event");
            continue;
        }

        // Safety: EnforcementEvent is #[repr(C)], Copy, and we checked the size.
        let event: EnforcementEvent =
            unsafe { std::ptr::read_unaligned(item.as_ptr() as *const EnforcementEvent) };

        log_event(&event);
    }
}

fn log_event(event: &EnforcementEvent) {
    let hook = HOOK_NAMES
        .get(event.hook as usize)
        .unwrap_or(&"unknown");

    tracing::warn!(
        hook = hook,
        pid = event.pid,
        caller_zone = event.caller_zone,
        target_zone = event.target_zone,
        context = event.context,
        timestamp_ns = event.timestamp_ns,
        "enforcement DENY"
    );
}
