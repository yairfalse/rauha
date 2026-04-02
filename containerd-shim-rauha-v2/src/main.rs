//! containerd shim v2 for Rauha.
//!
//! Bridges containerd's Task ttrpc API to rauhad's gRPC API.
//!
//! Mapping:
//!   - Sandbox Create (pause container) → Rauha ZoneCreate
//!   - Container Create → Rauha ContainerCreate in the sandbox's zone
//!   - Start/Kill/Delete → corresponding Rauha gRPC calls
//!
//! The shim binary is named `containerd-shim-rauha-v2` and is discovered
//! by containerd via the runtime name `io.containerd.rauha.v2`.

mod rauha_client;
mod task;

use containerd_shim::asynchronous::run;

#[tokio::main]
async fn main() {
    run::<task::RauhaShim>("io.containerd.rauha.v2", None).await;
}
