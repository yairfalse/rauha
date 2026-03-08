mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rauha", version, about = "Zones-like container runtime")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage isolation zones
    Zone {
        #[command(subcommand)]
        action: commands::zone::ZoneAction,
    },
    /// Run a container in a zone
    Run(commands::run::RunArgs),
    /// List containers
    Ps(commands::run::PsArgs),
    /// Stop a container
    Stop(commands::run::StopArgs),
    /// Delete a container
    Delete(commands::run::DeleteArgs),
    /// Manage images
    #[command(subcommand)]
    Image(commands::image::ImageAction),
    /// Manage zone policies
    Policy {
        #[command(subcommand)]
        action: commands::policy::PolicyAction,
    },
    /// Trace syscalls in a zone
    Trace(commands::trace::TraceArgs),
    /// Show per-zone resource usage
    Top(commands::trace::TopArgs),
    /// Stream zone events
    Events(commands::trace::EventsArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rauha=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Zone { action } => commands::zone::handle(action).await?,
        Commands::Run(args) => commands::run::handle_run(args).await?,
        Commands::Ps(args) => commands::run::handle_ps(args).await?,
        Commands::Stop(args) => commands::run::handle_stop(args).await?,
        Commands::Delete(args) => commands::run::handle_delete(args).await?,
        Commands::Image(action) => commands::image::handle(action).await?,
        Commands::Policy { action } => commands::policy::handle(action).await?,
        Commands::Trace(args) => commands::trace::handle_trace(args).await?,
        Commands::Top(args) => commands::trace::handle_top(args).await?,
        Commands::Events(args) => commands::trace::handle_events(args).await?,
    }

    Ok(())
}
