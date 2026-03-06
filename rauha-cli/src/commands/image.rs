use clap::Subcommand;

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
    match action {
        ImageAction::Pull { reference } => {
            println!("Pulling {}... (not yet implemented)", reference);
        }
        ImageAction::List => {
            println!("No images. (image service not yet implemented)");
        }
        ImageAction::Remove { reference } => {
            println!("Removing {}... (not yet implemented)", reference);
        }
        ImageAction::Inspect { reference } => {
            println!("Inspecting {}... (not yet implemented)", reference);
        }
    }
    Ok(())
}
