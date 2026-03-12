mod backend;
mod metadata;
mod server;
mod zone;

use std::path::PathBuf;
use std::sync::Arc;

use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

use server::pb::zone::zone_service_server::ZoneServiceServer;
use server::pb::container::container_service_server::ContainerServiceServer;
use server::pb::image::image_service_server::ImageServiceServer;

const DEFAULT_ROOT: &str = if cfg!(target_os = "macos") {
    // ~/Library/Application Support/Rauha
    "/tmp/rauha" // Simplified for dev; production uses proper macOS path
} else {
    "/var/lib/rauha"
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("rauhad=info".parse()?))
        .init();

    let root = std::env::var("RAUHA_ROOT").unwrap_or_else(|_| DEFAULT_ROOT.into());
    let root_path = PathBuf::from(&root);

    // Ensure directories exist.
    std::fs::create_dir_all(root_path.join("metadata"))?;
    std::fs::create_dir_all(root_path.join("zones"))?;
    std::fs::create_dir_all(root_path.join("content"))?;

    tracing::info!(root = %root, "starting rauhad");

    // Open metadata store.
    let metadata = Arc::new(
        metadata::db::MetadataStore::open(&root_path.join("metadata").join("rauha.redb"))?,
    );

    // Create platform backend.
    let backend_box = backend::create_backend(&root)?;
    let backend: Arc<dyn rauha_common::backend::IsolationBackend> = Arc::from(backend_box);

    tracing::info!(backend = backend.name(), "isolation backend initialized");

    // Create image service.
    let content_store = Arc::new(
        rauha_oci::content::ContentStore::new(&root_path.join("content"))
            .expect("failed to initialize content store"),
    );
    let image_service = Arc::new(rauha_oci::image::ImageService::new(
        content_store,
        root_path.clone(),
    ));

    // Create zone registry.
    let registry = Arc::new(zone::registry::ZoneRegistry::new(
        metadata.clone(),
        backend,
        image_service.clone(),
    ));

    // Reconcile persisted metadata with kernel state.
    // Handles crash recovery: re-pushes zone policies to BPF maps,
    // re-creates missing cgroups/netns, cleans up orphaned kernel state.
    registry.reconcile().await?;

    // Set up gRPC services.
    let zone_svc = server::ZoneServiceImpl::new(registry.clone(), root.clone());
    let container_svc = server::ContainerServiceImpl::new(registry.clone());
    let image_svc = server::ImageServiceImpl::new(image_service);

    // Determine socket path.
    let socket_path = if cfg!(target_os = "macos") {
        root_path.join("rauhad.sock")
    } else {
        PathBuf::from("/run/rauha/rauhad.sock")
    };

    // For development, also listen on a TCP port.
    let addr = "[::1]:9876".parse()?;
    tracing::info!(%addr, "listening on gRPC (TCP)");
    tracing::info!(socket = %socket_path.display(), "socket path (Unix domain socket — not yet wired)");

    Server::builder()
        .add_service(ZoneServiceServer::new(zone_svc))
        .add_service(ContainerServiceServer::new(container_svc))
        .add_service(ImageServiceServer::new(image_svc))
        .serve(addr)
        .await?;

    Ok(())
}
