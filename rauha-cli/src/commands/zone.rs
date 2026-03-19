use clap::Subcommand;

pub mod pb {
    pub mod zone {
        tonic::include_proto!("rauha.zone.v1");
    }
}

use pb::zone::zone_service_client::ZoneServiceClient;

use super::output::{self, OutputMode};

#[derive(Subcommand)]
pub enum ZoneAction {
    /// Create a new isolation zone
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "non-global")]
        r#type: String,
        #[arg(long)]
        policy: Option<String>,
    },
    /// List all zones
    List,
    /// Show detailed zone information
    Inspect {
        name: String,
    },
    /// Delete a zone
    Delete {
        name: String,
        #[arg(long)]
        force: bool,
    },
    /// Verify zone isolation integrity
    Verify {
        name: String,
    },
}

pub async fn handle(action: ZoneAction, out: OutputMode) -> anyhow::Result<()> {
    let channel = super::connect().await?;
    let mut client = ZoneServiceClient::new(channel);

    match action {
        ZoneAction::Create {
            name,
            r#type,
            policy,
        } => {
            let policy_toml = match policy {
                Some(path) => std::fs::read_to_string(&path)?,
                None => String::new(),
            };

            let resp = client
                .create_zone(pb::zone::CreateZoneRequest {
                    name: name.clone(),
                    zone_type: r#type,
                    policy_toml,
                })
                .await?
                .into_inner();

            output::print(
                out,
                &output::ZoneCreated {
                    ok: true,
                    name: resp.name.clone(),
                    id: resp.zone_id.clone(),
                },
                || println!("Zone created: {} (id: {})", resp.name, resp.zone_id),
            );
        }

        ZoneAction::List => {
            let resp = client
                .list_zones(pb::zone::ListZonesRequest {})
                .await?
                .into_inner();

            let zones: Vec<output::ZoneInfo> = resp
                .zones
                .iter()
                .map(|z| output::ZoneInfo {
                    name: z.name.clone(),
                    zone_type: z.zone_type.clone(),
                    state: z.state.clone(),
                    container_count: z.container_count,
                    created_at: z.created_at.clone(),
                })
                .collect();

            output::print(out, &output::ZoneList { ok: true, zones }, || {
                if resp.zones.is_empty() {
                    println!("No zones found.");
                } else {
                    println!(
                        "{:<20} {:<12} {:<12} {:<10} {}",
                        "NAME", "TYPE", "STATE", "CONTAINERS", "CREATED"
                    );
                    for z in &resp.zones {
                        println!(
                            "{:<20} {:<12} {:<12} {:<10} {}",
                            z.name, z.zone_type, z.state, z.container_count, z.created_at
                        );
                    }
                }
            });
        }

        ZoneAction::Inspect { name } => {
            let resp = client
                .get_zone(pb::zone::GetZoneRequest { name: name.clone() })
                .await?
                .into_inner();

            let z = resp.zone.ok_or_else(|| {
                anyhow::anyhow!("zone not found: {}", name)
            })?;

            {
                let policy_resp = client
                    .get_policy(pb::zone::GetPolicyRequest {
                        zone_name: name.clone(),
                    })
                    .await?
                    .into_inner();

                output::print(
                    out,
                    &output::ZoneInspect {
                        ok: true,
                        name: z.name.clone(),
                        id: z.id.clone(),
                        zone_type: z.zone_type.clone(),
                        state: z.state.clone(),
                        container_count: z.container_count,
                        created_at: z.created_at.clone(),
                        policy_toml: policy_resp.policy_toml.clone(),
                    },
                    || {
                        println!("Zone: {}", z.name);
                        println!("  ID:         {}", z.id);
                        println!("  Type:       {}", z.zone_type);
                        println!("  State:      {}", z.state);
                        println!("  Containers: {}", z.container_count);
                        println!("  Created:    {}", z.created_at);
                        println!("\nPolicy:\n{}", policy_resp.policy_toml);
                    },
                );
            }
        }

        ZoneAction::Delete { name, force } => {
            client
                .delete_zone(pb::zone::DeleteZoneRequest {
                    name: name.clone(),
                    force,
                })
                .await?;

            output::print(
                out,
                &output::ZoneDeleted {
                    ok: true,
                    name: name.clone(),
                },
                || println!("Zone deleted: {}", name),
            );
        }

        ZoneAction::Verify { name } => {
            let resp = client
                .verify_isolation(pb::zone::VerifyIsolationRequest {
                    zone_name: name.clone(),
                })
                .await?
                .into_inner();

            let checks: Vec<output::IsolationCheck> = resp
                .checks
                .iter()
                .map(|c| output::IsolationCheck {
                    name: c.name.clone(),
                    passed: c.passed,
                    detail: c.detail.clone(),
                })
                .collect();

            output::print(
                out,
                &output::ZoneVerification {
                    ok: true,
                    zone: name.clone(),
                    isolated: resp.is_isolated,
                    checks,
                },
                || {
                    println!(
                        "Zone {}: {}",
                        name,
                        if resp.is_isolated {
                            "ISOLATED"
                        } else {
                            "NOT ISOLATED"
                        }
                    );
                    for check in &resp.checks {
                        println!(
                            "  {} {} — {}",
                            if check.passed { "✓" } else { "✗" },
                            check.name,
                            check.detail,
                        );
                    }
                },
            );
        }
    }

    Ok(())
}
