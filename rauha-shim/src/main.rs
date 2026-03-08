mod container;
mod io;
mod state;

use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use clap::Parser;
use rauha_common::shim::{self, ShimRequest, ShimResponse};
use tracing_subscriber::EnvFilter;

use crate::state::ShimState;

#[derive(Parser)]
#[command(name = "rauha-shim", about = "Zone shim — one per zone, runs container processes")]
struct Args {
    /// Zone name.
    #[arg(long)]
    zone_name: String,

    /// Path to the shim Unix socket.
    #[arg(long)]
    socket: PathBuf,

    /// Root path for zone data (rootfs dirs, etc.).
    #[arg(long)]
    rootfs_root: PathBuf,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("rauha_shim=info".parse()?),
        )
        .init();

    let args = Args::parse();

    tracing::info!(
        zone = %args.zone_name,
        socket = %args.socket.display(),
        "rauha-shim starting"
    );

    // Remove stale socket if it exists.
    if args.socket.exists() {
        std::fs::remove_file(&args.socket)?;
    }

    // Ensure parent directory exists.
    if let Some(parent) = args.socket.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&args.socket)?;
    tracing::info!(socket = %args.socket.display(), "listening");

    let mut shim_state = ShimState::new(args.zone_name.clone(), args.rootfs_root.clone());

    // Main loop: accept connections, handle one request per connection.
    // rauhad opens a new connection for each request.
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                match shim::decode_from::<ShimRequest>(&mut stream) {
                    Ok(request) => {
                        let response = handle_request(&mut shim_state, request);
                        if let Err(e) = shim::encode_to(&mut stream, &response) {
                            tracing::error!(%e, "failed to send response");
                        }
                        // Check for shutdown.
                        if matches!(response, ShimResponse::Ok)
                            && shim_state.should_shutdown()
                        {
                            tracing::info!("shutting down");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(%e, "failed to decode request");
                    }
                }
            }
            Err(e) => {
                tracing::error!(%e, "accept error");
            }
        }

        // Reap finished child processes.
        shim_state.reap_children();
    }

    // Clean up socket.
    let _ = std::fs::remove_file(&args.socket);
    tracing::info!("shim exited");
    Ok(())
}

fn handle_request(state: &mut ShimState, request: ShimRequest) -> ShimResponse {
    match request {
        ShimRequest::CreateContainer { id, spec_json } => {
            tracing::info!(container = %id, "creating container");
            match state.create_container(&id, &spec_json) {
                Ok(pid) => ShimResponse::Created { pid },
                Err(e) => ShimResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        ShimRequest::StartContainer { id } => {
            tracing::info!(container = %id, "starting container");
            match state.start_container(&id) {
                Ok(pid) => ShimResponse::Created { pid },
                Err(e) => ShimResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        ShimRequest::StopContainer { id, signal } => {
            tracing::info!(container = %id, signal, "stopping container");
            match state.stop_container(&id, signal) {
                Ok(()) => ShimResponse::Ok,
                Err(e) => ShimResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        ShimRequest::Signal { id, signal } => match state.signal_container(&id, signal) {
            Ok(()) => ShimResponse::Ok,
            Err(e) => ShimResponse::Error {
                message: e.to_string(),
            },
        },
        ShimRequest::GetState { id } => match state.get_state(&id) {
            Some((pid, status)) => ShimResponse::State { pid, status },
            None => ShimResponse::Error {
                message: format!("container {id} not found"),
            },
        },
        ShimRequest::Shutdown => {
            state.request_shutdown();
            ShimResponse::Ok
        }
    }
}
