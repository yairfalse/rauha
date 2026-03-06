use clap::Subcommand;

pub mod pb {
    pub mod zone {
        tonic::include_proto!("rauha.zone.v1");
    }
}

use pb::zone::zone_service_client::ZoneServiceClient;

#[derive(Subcommand)]
pub enum PolicyAction {
    /// Apply a policy to a zone
    Apply {
        #[arg(long)]
        zone: String,
        /// Path to policy TOML file
        policy: String,
        /// Allow communication with another zone
        #[arg(long = "allow-zone")]
        allow_zone: Option<String>,
    },
    /// Show the current policy for a zone
    Show {
        #[arg(long)]
        zone: String,
    },
}

pub async fn handle(action: PolicyAction) -> anyhow::Result<()> {
    let channel = super::connect().await?;
    let mut client = ZoneServiceClient::new(channel);

    match action {
        PolicyAction::Apply {
            zone,
            policy,
            allow_zone: _,
        } => {
            let policy_toml = std::fs::read_to_string(&policy)?;
            client
                .apply_policy(pb::zone::ApplyPolicyRequest {
                    zone_name: zone.clone(),
                    policy_toml,
                })
                .await?;
            println!("Policy applied to zone: {}", zone);
        }
        PolicyAction::Show { zone } => {
            let resp = client
                .get_policy(pb::zone::GetPolicyRequest {
                    zone_name: zone.clone(),
                })
                .await?
                .into_inner();
            println!("{}", resp.policy_toml);
        }
    }

    Ok(())
}
