use clap::Args;

pub mod pb {
    pub mod container {
        tonic::include_proto!("rauha.container.v1");
    }
}

use pb::container::container_service_client::ContainerServiceClient;

#[derive(Args)]
pub struct RunArgs {
    /// Zone to run the container in
    #[arg(long)]
    pub zone: String,
    /// Container name
    #[arg(long)]
    pub name: Option<String>,
    /// Image reference (e.g. nginx:latest)
    pub image: String,
    /// Command to run (overrides image default)
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

#[derive(Args)]
pub struct PsArgs {
    /// Filter by zone
    #[arg(long)]
    pub zone: Option<String>,
}

#[derive(Args)]
pub struct StopArgs {
    /// Container ID
    pub container_id: String,
    /// Timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u32,
}

pub async fn handle_run(args: RunArgs) -> anyhow::Result<()> {
    let channel = super::connect().await?;
    let mut client = ContainerServiceClient::new(channel);

    let name = args
        .name
        .unwrap_or_else(|| format!("rauha-{}", &uuid::Uuid::new_v4().to_string()[..8]));

    let resp = client
        .create_container(pb::container::CreateContainerRequest {
            zone_name: args.zone.clone(),
            name: name.clone(),
            image: args.image.clone(),
            command: args.command,
            env: Default::default(),
            working_dir: String::new(),
        })
        .await?
        .into_inner();

    println!("{}", resp.container_id);

    // Start the container.
    client
        .start_container(pb::container::StartContainerRequest {
            container_id: resp.container_id.clone(),
        })
        .await?;

    Ok(())
}

pub async fn handle_ps(args: PsArgs) -> anyhow::Result<()> {
    let channel = super::connect().await?;
    let mut client = ContainerServiceClient::new(channel);

    let resp = client
        .list_containers(pb::container::ListContainersRequest {
            zone_name: args.zone.unwrap_or_default(),
        })
        .await?
        .into_inner();

    if resp.containers.is_empty() {
        println!("No containers running.");
    } else {
        println!(
            "{:<40} {:<15} {:<20} {:<12} {:<8}",
            "ID", "NAME", "IMAGE", "STATE", "PID"
        );
        for c in resp.containers {
            println!(
                "{:<40} {:<15} {:<20} {:<12} {:<8}",
                c.id, c.name, c.image, c.state, c.pid
            );
        }
    }

    Ok(())
}

pub async fn handle_stop(args: StopArgs) -> anyhow::Result<()> {
    let channel = super::connect().await?;
    let mut client = ContainerServiceClient::new(channel);

    client
        .stop_container(pb::container::StopContainerRequest {
            container_id: args.container_id.clone(),
            timeout_seconds: args.timeout,
        })
        .await?;

    println!("Stopped: {}", args.container_id);
    Ok(())
}
