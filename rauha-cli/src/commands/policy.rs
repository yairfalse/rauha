use clap::Subcommand;

pub mod pb {
    pub mod zone {
        tonic::include_proto!("rauha.zone.v1");
    }
}

use pb::zone::zone_service_client::ZoneServiceClient;

use super::output::{self, OutputMode};

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

pub async fn handle(action: PolicyAction, out: OutputMode) -> anyhow::Result<()> {
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

            output::print(
                out,
                &output::PolicyApplied {
                    ok: true,
                    zone: zone.clone(),
                },
                || println!("Policy applied to zone: {}", zone),
            );
        }
        PolicyAction::Show { zone } => {
            let resp = client
                .get_policy(pb::zone::GetPolicyRequest {
                    zone_name: zone.clone(),
                })
                .await?
                .into_inner();

            output::print(
                out,
                &output::PolicyShow {
                    ok: true,
                    zone: zone.clone(),
                    policy_toml: resp.policy_toml.clone(),
                },
                || println!("{}", resp.policy_toml),
            );
        }
    }

    Ok(())
}
