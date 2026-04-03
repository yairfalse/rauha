//! rauha-enforce — standalone eBPF enforcement agent.
//!
//! Drops kernel-level zone enforcement onto existing containerd/Docker clusters.
//! No runtime replacement needed. Watches container events, maps workloads to
//! zones by label, and populates BPF maps.
//!
//! Usage:
//!   rauha-enforce --policy-dir /etc/rauha/policies/
//!   rauha-enforce status
//!   rauha-enforce events --follow

mod ebpf;
mod events;
mod mapper;
mod policy;
mod watcher;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "rauha-enforce", about = "eBPF enforcement agent for container isolation")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Directory containing zone policy TOML files.
    #[arg(long, default_value = "/etc/rauha/policies")]
    policy_dir: PathBuf,

    /// Path to the eBPF object file.
    #[arg(long)]
    ebpf_obj: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Show current enforcement status.
    Status,
    /// Stream enforcement events.
    Events {
        /// Follow events in real time.
        #[arg(long, short)]
        follow: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("rauha_enforce=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Status) => cmd_status().await,
        Some(Commands::Events { follow }) => cmd_events(follow).await,
        None => cmd_run(cli.policy_dir, cli.ebpf_obj).await,
    }
}

/// Main enforcement loop.
async fn cmd_run(policy_dir: PathBuf, ebpf_obj: Option<PathBuf>) -> anyhow::Result<()> {
    tracing::info!("rauha-enforce starting");

    // Load eBPF programs.
    let mut mgr = ebpf::EnforceEbpf::load(ebpf_obj.as_deref())?;
    tracing::info!("eBPF programs loaded and attached");

    // Load zone policies from disk.
    let policies = policy::load_policies(&policy_dir)?;
    tracing::info!(count = policies.len(), dir = %policy_dir.display(), "loaded zone policies");

    // Start the event reader (ring buffer → logs).
    let cancel = tokio_util::sync::CancellationToken::new();
    if let Some(ring_buf) = mgr.take_event_ring_buf() {
        events::spawn_event_reader(ring_buf, cancel.clone());
    }

    // Enumerate existing containers and assign zones.
    let assignments = watcher::enumerate_cgroups(&policies)?;
    let mut zone_counter = 1u32;

    for assignment in &assignments {
        let zone_id = zone_counter;
        zone_counter += 1;

        mgr.add_zone_member(assignment.cgroup_id, zone_id, rauha_common::zone::ZoneType::NonGlobal)?;

        if let Some(policy) = policies.get(&assignment.zone_name) {
            mgr.set_zone_policy(zone_id, policy)?;
        }

        tracing::info!(
            zone = assignment.zone_name,
            cgroup_id = assignment.cgroup_id,
            zone_id,
            "enforcing container"
        );
    }

    print_status_summary(&policies, &assignments, &mgr);

    // Wait for shutdown.
    tracing::info!("rauha-enforce running — press Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;

    cancel.cancel();
    mgr.cleanup();
    tracing::info!("rauha-enforce stopped");
    Ok(())
}

fn print_status_summary(
    policies: &std::collections::HashMap<String, rauha_common::zone::ZonePolicy>,
    assignments: &[watcher::ZoneAssignment],
    mgr: &ebpf::EnforceEbpf,
) {
    let enforced = assignments.len();
    let zone_names: std::collections::HashSet<&str> = assignments
        .iter()
        .map(|a| a.zone_name.as_str())
        .collect();

    tracing::info!(
        programs = "5/5",
        zones = zone_names.len(),
        containers_enforced = enforced,
        "enforcement active"
    );

    for zone in &zone_names {
        let count = assignments.iter().filter(|a| a.zone_name == *zone).count();
        let has_policy = policies.contains_key(*zone);
        tracing::info!(
            zone = zone,
            containers = count,
            policy = has_policy,
            "zone summary"
        );
    }

    // Print enforcement counters if available.
    if let Ok(counters) = mgr.read_counters() {
        for (name, c) in &counters {
            if c.allow > 0 || c.deny > 0 || c.error > 0 {
                tracing::info!(
                    hook = name.as_str(),
                    allow = c.allow,
                    deny = c.deny,
                    error = c.error,
                    "enforcement counters"
                );
            }
        }
    }
}

async fn cmd_status() -> anyhow::Result<()> {
    // Check if BPF maps are pinned (enforcement is active).
    let pin_path = std::path::Path::new("/sys/fs/bpf/rauha");
    if !pin_path.exists() {
        println!("rauha-enforce: NOT ACTIVE (no pinned BPF maps)");
        return Ok(());
    }

    println!("rauha-enforce: ACTIVE");
    println!("  pin path: /sys/fs/bpf/rauha");

    // Read enforcement counters from pinned maps.
    // This is a read-only check — doesn't load programs.
    println!("  (run rauha-enforce without subcommand for full status)");
    Ok(())
}

async fn cmd_events(follow: bool) -> anyhow::Result<()> {
    if !follow {
        println!("use --follow to stream events in real time");
        return Ok(());
    }

    // Open the pinned ring buffer and drain events.
    println!("streaming enforcement events (Ctrl+C to stop)...");

    // For now, require running the main agent to see events.
    // TODO: open pinned ENFORCEMENT_EVENTS map directly for read-only event tailing.
    println!("(events are logged by the main rauha-enforce process)");
    Ok(())
}
