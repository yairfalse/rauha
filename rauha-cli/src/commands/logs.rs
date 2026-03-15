use clap::Args;

pub mod pb {
    pub mod container {
        tonic::include_proto!("rauha.container.v1");
    }
}

use pb::container::container_service_client::ContainerServiceClient;

#[derive(Args)]
pub struct LogsArgs {
    /// Container ID
    pub container_id: String,
    /// Follow log output
    #[arg(short, long)]
    pub follow: bool,
    /// Number of lines to show from the end
    #[arg(long, default_value = "0")]
    pub tail: u32,
}

pub async fn handle_logs(args: LogsArgs) -> anyhow::Result<()> {
    let channel = super::connect().await?;
    let mut client = ContainerServiceClient::new(channel);

    let mut stream = client
        .container_logs(pb::container::ContainerLogsRequest {
            container_id: args.container_id,
            follow: args.follow,
            tail: args.tail,
        })
        .await?
        .into_inner();

    use tokio_stream::StreamExt;
    while let Some(entry) = stream.next().await {
        match entry {
            Ok(log) => {
                if log.source == "stderr" {
                    eprintln!("{}", log.line);
                } else {
                    println!("{}", log.line);
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                break;
            }
        }
    }

    Ok(())
}
