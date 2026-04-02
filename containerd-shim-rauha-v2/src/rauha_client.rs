//! Rauha gRPC client wrapper.
//!
//! Thin wrapper around the generated gRPC clients for zone, container, and
//! image services. Connects to rauhad at the configured endpoint.

use anyhow::{Context, Result};
use tonic::transport::Channel;

pub mod pb {
    pub mod zone {
        tonic::include_proto!("rauha.zone.v1");
    }
    pub mod container {
        tonic::include_proto!("rauha.container.v1");
    }
    pub mod image {
        tonic::include_proto!("rauha.image.v1");
    }
}

use pb::container::container_service_client::ContainerServiceClient;
use pb::image::image_service_client::ImageServiceClient;
use pb::zone::zone_service_client::ZoneServiceClient;

/// Client handle to rauhad's gRPC API.
#[derive(Clone)]
pub struct RauhaClient {
    pub zones: ZoneServiceClient<Channel>,
    pub containers: ContainerServiceClient<Channel>,
    pub images: ImageServiceClient<Channel>,
}

impl RauhaClient {
    pub async fn connect(endpoint: &str) -> Result<Self> {
        let channel = Channel::from_shared(endpoint.to_string())
            .context("invalid rauhad endpoint")?
            .connect()
            .await
            .context("failed to connect to rauhad")?;

        Ok(Self {
            zones: ZoneServiceClient::new(channel.clone()),
            containers: ContainerServiceClient::new(channel.clone()),
            images: ImageServiceClient::new(channel),
        })
    }

    /// Default endpoint from env or fallback.
    pub fn endpoint() -> String {
        std::env::var("RAUHA_ADDR")
            .unwrap_or_else(|_| "http://[::1]:9876".to_string())
    }
}
