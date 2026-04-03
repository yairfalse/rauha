use clap::Args;
use tokio_stream::StreamExt;

use super::connect;

mod pb {
    pub mod zone {
        tonic::include_proto!("rauha.zone.v1");
    }
}

#[derive(Args)]
pub struct TraceArgs {
    #[arg(long)]
    pub zone: String,
}

#[derive(Args)]
pub struct TopArgs {
    #[arg(long)]
    pub zone: Option<String>,
}

#[derive(Args)]
pub struct EventsArgs {
    /// Filter events by zone name.
    #[arg(long)]
    pub zone: Option<String>,
}

pub async fn handle_trace(args: TraceArgs) -> anyhow::Result<()> {
    println!(
        "Tracing zone {}... (not yet implemented)",
        args.zone
    );
    Ok(())
}

pub async fn handle_top(_args: TopArgs) -> anyhow::Result<()> {
    println!("Per-zone resource monitoring (not yet implemented)");
    Ok(())
}

pub async fn handle_events(args: EventsArgs) -> anyhow::Result<()> {
    let channel = connect().await?;
    let mut client =
        pb::zone::zone_service_client::ZoneServiceClient::new(channel);

    let request = pb::zone::WatchEventsRequest {
        zone_name: args.zone.unwrap_or_default(),
    };

    let mut stream = client.watch_events(request).await?.into_inner();

    eprintln!("streaming enforcement events (Ctrl+C to stop)...");
    eprintln!();

    while let Some(event) = stream.next().await {
        match event {
            Ok(e) => {
                println!(
                    "{}  {}  {}",
                    format_timestamp(&e.timestamp),
                    e.event_type,
                    e.message,
                );
            }
            Err(e) => {
                eprintln!("stream error: {e}");
                break;
            }
        }
    }

    Ok(())
}

fn format_timestamp(ts: &str) -> String {
    // Timestamp is nanoseconds from bpf_ktime_get_ns (monotonic).
    // Show as relative seconds for readability.
    if let Ok(ns) = ts.parse::<u64>() {
        let secs = ns / 1_000_000_000;
        let ms = (ns % 1_000_000_000) / 1_000_000;
        format!("{secs:>6}.{ms:03}")
    } else {
        ts.to_string()
    }
}
