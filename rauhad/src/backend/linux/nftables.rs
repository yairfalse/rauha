//! nftables rule management for zone networking.
//!
//! Handles two concerns:
//! 1. NAT masquerade — zones can reach the internet via the host
//! 2. Forward chain filtering — controls cross-zone and egress traffic
//!
//! nftables is the primary network enforcement layer. eBPF stays focused on
//! syscall policy (file_open, ptrace, etc). This separation keeps each
//! subsystem doing what it does best.

use std::io::Write;
use std::process::{Command, Stdio};

use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::{NetworkMode, NetworkPolicy};

const TABLE_NAME: &str = "rauha";
const TABLE_FAMILY: &str = "inet";

/// Ensure the rauha nftables table and NAT masquerade chain exist.
/// Called once during LinuxBackend::new().
pub fn ensure_nat(subnet_cidr: &str) -> Result<()> {
    // nft -f applies the complete batch as one kernel transaction. A syntax or
    // runtime failure therefore leaves the previous enforcement table intact.
    run_nft_script(&base_ruleset(subnet_cidr, table_exists()?))?;

    tracing::info!(
        subnet = subnet_cidr,
        "nftables NAT + forward chains created"
    );
    Ok(())
}

fn base_ruleset(subnet_cidr: &str, replace: bool) -> String {
    format!(
        "{delete}add table inet rauha\n\
         add chain inet rauha postrouting {{ type nat hook postrouting priority srcnat; }}\n\
         add rule inet rauha postrouting ip saddr {subnet_cidr} oifname != \"rauha0\" masquerade\n\
         add chain inet rauha forward {{ type filter hook forward priority filter; policy drop; }}\n\
         add rule inet rauha forward ct state established,related accept\n",
        delete = if replace {
            "delete table inet rauha\n"
        } else {
            ""
        }
    )
}

/// Remove the entire rauha nftables table.
/// Called during daemon shutdown.
pub fn cleanup_nat() -> Result<()> {
    if !table_exists()? {
        return Ok(());
    }

    run_nft(&["delete", "table", TABLE_FAMILY, TABLE_NAME])?;
    tracing::info!("nftables table removed");
    Ok(())
}

/// Apply nftables forward rules for a zone based on its NetworkPolicy.
///
/// Zone names are validated by `validate_zone_name` (alphanumeric + hyphen,
/// max 128 chars) which produces safe nftables chain identifiers.
pub fn apply_zone_rules(zone_name: &str, veth_name: &str, policy: &NetworkPolicy) -> Result<()> {
    // First remove any existing rules for this zone.
    let _ = remove_zone_rules(zone_name);

    let chain_name = zone_chain_name(zone_name);

    match policy.mode {
        NetworkMode::Isolated => {
            // Create a chain that drops everything.
            run_nft(&["add", "chain", TABLE_FAMILY, TABLE_NAME, &chain_name])?;
            run_nft(&["add", "rule", TABLE_FAMILY, TABLE_NAME, &chain_name, "drop"])?;

            // Jump to the zone chain for traffic from/to this veth.
            run_nft(&[
                "add",
                "rule",
                TABLE_FAMILY,
                TABLE_NAME,
                "forward",
                &format!("iifname \"{veth_name}\" jump {chain_name}"),
            ])?;
            run_nft(&[
                "add",
                "rule",
                TABLE_FAMILY,
                TABLE_NAME,
                "forward",
                &format!("oifname \"{veth_name}\" jump {chain_name}"),
            ])?;
        }
        NetworkMode::Bridged => {
            // Create zone chain.
            run_nft(&["add", "chain", TABLE_FAMILY, TABLE_NAME, &chain_name])?;

            // Allow established/related connections.
            run_nft(&[
                "add",
                "rule",
                TABLE_FAMILY,
                TABLE_NAME,
                &chain_name,
                "ct state established,related accept",
            ])?;

            // Allow cross-zone traffic to specific zones.
            // Uses veth interface names — no IP lookup needed.
            for allowed_zone in &policy.allowed_zones {
                let peer_veth = super::network::veth_host_name_for(allowed_zone);
                // Allow bidirectional traffic between veths.
                run_nft(&[
                    "add",
                    "rule",
                    TABLE_FAMILY,
                    TABLE_NAME,
                    &chain_name,
                    &format!("iifname \"{veth_name}\" oifname \"{peer_veth}\" accept"),
                ])?;
                run_nft(&[
                    "add",
                    "rule",
                    TABLE_FAMILY,
                    TABLE_NAME,
                    &chain_name,
                    &format!("iifname \"{peer_veth}\" oifname \"{veth_name}\" accept"),
                ])?;

                tracing::debug!(
                    zone = zone_name,
                    peer = allowed_zone.as_str(),
                    "allowed cross-zone traffic"
                );
            }

            // Allow specific egress destinations.
            for rule in egress_rules(veth_name, &policy.allowed_egress) {
                run_nft(&["add", "rule", TABLE_FAMILY, TABLE_NAME, &chain_name, &rule])?;
            }

            // Empty egress is deny-all. Default-drop also covers IPv6, while
            // explicit IPv4 destinations above use `ip daddr`.
            run_nft(&["add", "rule", TABLE_FAMILY, TABLE_NAME, &chain_name, "drop"])?;

            // Jump to the zone chain from forward.
            run_nft(&[
                "add",
                "rule",
                TABLE_FAMILY,
                TABLE_NAME,
                "forward",
                &format!("iifname \"{veth_name}\" jump {chain_name}"),
            ])?;
            run_nft(&[
                "add",
                "rule",
                TABLE_FAMILY,
                TABLE_NAME,
                "forward",
                &format!("oifname \"{veth_name}\" jump {chain_name}"),
            ])?;
        }
        NetworkMode::Host => {
            // Host mode: no filtering rules.
        }
    }

    tracing::info!(zone = zone_name, mode = ?policy.mode, "nftables rules applied");
    Ok(())
}

/// Remove all nftables rules for a zone.
pub fn remove_zone_rules(zone_name: &str) -> Result<()> {
    let chain_name = zone_chain_name(zone_name);

    // First, remove jump rules in the forward chain that reference this zone chain.
    let _ = remove_forward_chain_jumps(&chain_name);

    // Flush and delete the zone chain. Ignore errors — chain may not exist.
    let _ = run_nft(&["flush", "chain", TABLE_FAMILY, TABLE_NAME, &chain_name]);
    let _ = run_nft(&["delete", "chain", TABLE_FAMILY, TABLE_NAME, &chain_name]);

    Ok(())
}

pub fn zone_rules_exist(zone_name: &str, veth_name: &str, mode: NetworkMode) -> bool {
    if mode == NetworkMode::Host {
        return true;
    }
    let chain_name = zone_chain_name(zone_name);
    let chain_ok = Command::new("nft")
        .args(["list", "chain", TABLE_FAMILY, TABLE_NAME, &chain_name])
        .output()
        .is_ok_and(|output| output.status.success());
    let forward = Command::new("nft")
        .args(["list", "chain", TABLE_FAMILY, TABLE_NAME, "forward"])
        .output();
    chain_ok
        && forward.is_ok_and(|output| {
            if !output.status.success() {
                return false;
            }
            let rules = String::from_utf8_lossy(&output.stdout);
            rules.contains(&format!("iifname \"{veth_name}\" jump {chain_name}"))
                && rules.contains(&format!("oifname \"{veth_name}\" jump {chain_name}"))
        })
}

/// Remove rules in the forward chain that jump to the given zone chain.
/// Uses nft handle-based deletion to avoid leaving stale rules.
fn remove_forward_chain_jumps(chain_name: &str) -> Result<()> {
    let output = Command::new("nft")
        .args(["-a", "list", "chain", TABLE_FAMILY, TABLE_NAME, "forward"])
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to list nftables forward chain: {e}"),
            hint: "ensure nftables is installed (nft command)".into(),
        })?;

    if !output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        if line.contains("jump") && line.contains(chain_name) {
            if let Some(idx) = line.find("# handle ") {
                let handle = line[idx + "# handle ".len()..].trim();
                if !handle.is_empty() {
                    let _ = run_nft(&[
                        "delete",
                        "rule",
                        TABLE_FAMILY,
                        TABLE_NAME,
                        "forward",
                        "handle",
                        handle,
                    ]);
                }
            }
        }
    }

    Ok(())
}

fn zone_chain_name(zone_name: &str) -> String {
    // Zone names are validated by validate_zone_name: no path separators,
    // no NUL, not "." or "..", max 128 chars. This produces safe nftables
    // chain identifiers (max 256 chars).
    format!("zone-{zone_name}")
}

fn egress_rules(veth_name: &str, destinations: &[String]) -> Vec<String> {
    destinations
        .iter()
        .map(|dest| format!("iifname \"{veth_name}\" ip daddr {dest} accept"))
        .collect()
}

fn table_exists() -> Result<bool> {
    let output = Command::new("nft")
        .args(["list", "table", TABLE_FAMILY, TABLE_NAME])
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to check nftables table: {e}"),
            hint: "ensure nftables is installed (nft command)".into(),
        })?;

    Ok(output.status.success())
}

fn run_nft(args: &[&str]) -> Result<()> {
    let output = Command::new("nft")
        .args(args)
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to run `nft {}`: {e}", args.join(" ")),
            hint: "ensure nftables is installed and rauhad runs as root".into(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RauhaError::NetworkError {
            message: format!("nft {} failed: {stderr}", args.join(" ")),
            hint: "run rauhad as root".into(),
        });
    }

    Ok(())
}

fn run_nft_script(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to start nftables transaction: {e}"),
            hint: "ensure nftables is installed and rauhad runs as root".into(),
        })?;
    let mut stdin = child.stdin.take().ok_or_else(|| RauhaError::NetworkError {
        message: "failed to open nftables transaction input".into(),
        hint: "restart rauhad".into(),
    })?;
    if let Err(e) = stdin.write_all(script.as_bytes()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(RauhaError::NetworkError {
            message: format!("failed to write nftables transaction: {e}"),
            hint: "restart rauhad".into(),
        });
    }
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to wait for nftables transaction: {e}"),
            hint: "restart rauhad".into(),
        })?;
    if !output.status.success() {
        return Err(RauhaError::NetworkError {
            message: format!(
                "nftables transaction failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
            hint: "check nftables support and run rauhad as root".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_chain_name_format() {
        assert_eq!(zone_chain_name("web"), "zone-web");
        assert_eq!(zone_chain_name("my-app"), "zone-my-app");
    }

    #[test]
    fn empty_egress_adds_no_implicit_dns_exception() {
        assert!(egress_rules("veth-test", &[]).is_empty());
    }

    #[test]
    fn base_ruleset_replaces_atomically_with_default_drop() {
        let rules = base_ruleset("10.89.0.0/16", true);
        assert!(rules.starts_with("delete table inet rauha\nadd table inet rauha"));
        assert!(rules.contains("policy drop"));
        assert!(rules.contains("ip saddr 10.89.0.0/16"));
    }
}
