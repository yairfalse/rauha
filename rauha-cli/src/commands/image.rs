use clap::Subcommand;

pub mod pb {
    pub mod image {
        tonic::include_proto!("rauha.image.v1");
    }
}

use pb::image::image_service_client::ImageServiceClient;

#[derive(Subcommand)]
pub enum ImageAction {
    /// Pull an image from a registry
    Pull { reference: String },
    /// List local images
    #[command(name = "ls")]
    List,
    /// Remove a local image
    Remove { reference: String },
    /// Show image details
    Inspect { reference: String },
}

pub async fn handle(action: ImageAction) -> anyhow::Result<()> {
    let channel = super::connect().await?;
    let mut client = ImageServiceClient::new(channel);

    match action {
        ImageAction::Pull { reference } => {
            println!("Pulling {reference}...");

            let mut stream = client
                .pull(pb::image::PullRequest {
                    reference: reference.clone(),
                })
                .await?
                .into_inner();

            use tokio_stream::StreamExt;
            while let Some(progress) = stream.next().await {
                match progress {
                    Ok(p) => {
                        if p.done {
                            println!("Pull complete: {reference}");
                        } else if p.total > 0 {
                            let pct = (p.current as f64 / p.total as f64 * 100.0) as u32;
                            println!("  {} {} ({pct}%)", p.status, p.layer);
                        } else {
                            println!("  {}", p.status);
                        }
                    }
                    Err(e) => {
                        eprintln!("Pull error: {e}");
                        return Err(e.into());
                    }
                }
            }
        }
        ImageAction::List => {
            let resp = client
                .list(pb::image::ListImagesRequest {})
                .await?
                .into_inner();

            if resp.images.is_empty() {
                println!("No images.");
            } else {
                println!("{:<50} {:<20} {:<10}", "REFERENCE", "DIGEST", "SIZE");
                for img in resp.images {
                    let tag = img.tags.first().cloned().unwrap_or_default();
                    let digest_short = if img.digest.len() > 19 {
                        format!("{}...", &img.digest[..19])
                    } else {
                        img.digest.clone()
                    };
                    let size_mb = img.size as f64 / 1_048_576.0;
                    println!("{:<50} {:<20} {:.1}MB", tag, digest_short, size_mb);
                }
            }
        }
        ImageAction::Remove { reference } => {
            client
                .remove(pb::image::RemoveImageRequest {
                    reference: reference.clone(),
                })
                .await?;
            println!("Removed: {reference}");
        }
        ImageAction::Inspect { reference } => {
            let resp = client
                .inspect(pb::image::InspectImageRequest {
                    reference: reference.clone(),
                })
                .await?
                .into_inner();

            println!("Reference: {reference}");
            if !resp.digest.is_empty() {
                println!("Digest:    {}", resp.digest);
            }
            println!("Size:      {} bytes", resp.size);
            if !resp.config_json.is_empty() {
                println!("Config:");
                println!("{}", resp.config_json);
            }
        }
    }
    Ok(())
}
