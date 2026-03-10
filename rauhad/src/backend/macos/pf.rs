//! pf firewall management for per-zone network isolation on macOS.
//!
//! Each zone gets its own pf anchor (`com.rauha/zone-{name}`), allowing
//! independent rule management. Rules are generated from ZonePolicy and
//! loaded via pfctl.

use std::path::{Path, PathBuf};
use std::process::Command;

use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::{NetworkMode, ZonePolicy};

const ANCHOR_ROOT: &str = "com.rauha";
const ANCHOR_DIR: &str = "/etc/pf.anchors";

pub struct PfManager {
    anchor_dir: PathBuf,
}

impl PfManager {
    pub fn new() -> Self {
        Self {
            anchor_dir: PathBuf::from(ANCHOR_DIR),
        }
    }

    /// Create pf rules for a zone based on its policy.
    pub fn create_zone_rules(&self, zone_name: &str, policy: &ZonePolicy) -> Result<()> {
        let rules = generate_rules(zone_name, policy);
        let anchor_file = self.anchor_file(zone_name);

        // Write rules file.
        if let Some(parent) = anchor_file.parent() {
            std::fs::create_dir_all(parent).map_err(|e| RauhaError::NetworkError {
                message: format!("failed to create anchor dir: {e}"),
                hint: "Ensure rauhad has write access to /etc/pf.anchors/".into(),
            })?;
        }

        std::fs::write(&anchor_file, &rules).map_err(|e| RauhaError::NetworkError {
            message: format!("failed to write pf rules to {}: {e}", anchor_file.display()),
            hint: "Ensure rauhad runs as root or has pf management permissions".into(),
        })?;

        // Load rules into the anchor.
        self.load_anchor(zone_name, &anchor_file)?;

        tracing::info!(zone = zone_name, "pf rules created");
        Ok(())
    }

    /// Remove all pf rules for a zone.
    pub fn remove_zone_rules(&self, zone_name: &str) -> Result<()> {
        let anchor = format!("{ANCHOR_ROOT}/zone-{zone_name}");

        // Flush anchor rules.
        let status = Command::new("pfctl")
            .args(["-a", &anchor, "-F", "all"])
            .output()
            .map_err(|e| RauhaError::NetworkError {
                message: format!("failed to flush pf anchor: {e}"),
                hint: "Is pfctl available? Are you running as root?".into(),
            })?;

        if !status.status.success() {
            tracing::warn!(
                zone = zone_name,
                stderr = %String::from_utf8_lossy(&status.stderr),
                "pfctl flush returned non-zero (anchor may not exist)"
            );
        }

        // Remove rules file.
        let anchor_file = self.anchor_file(zone_name);
        if anchor_file.exists() {
            let _ = std::fs::remove_file(&anchor_file);
        }

        tracing::info!(zone = zone_name, "pf rules removed");
        Ok(())
    }

    /// Update pf rules for a zone (remove + recreate).
    pub fn update_zone_rules(&self, zone_name: &str, policy: &ZonePolicy) -> Result<()> {
        self.remove_zone_rules(zone_name)?;
        self.create_zone_rules(zone_name, policy)
    }

    /// Ensure the root anchor is configured in the system pf config.
    /// This only needs to run once (during `rauha setup`).
    pub fn ensure_root_anchor() -> Result<()> {
        let root_anchor_file = Path::new(ANCHOR_DIR).join(ANCHOR_ROOT);
        let root_anchor_content = format!("anchor \"{ANCHOR_ROOT}/*\"\n");

        if !root_anchor_file.exists() {
            std::fs::write(&root_anchor_file, &root_anchor_content).map_err(|e| {
                RauhaError::NetworkError {
                    message: format!("failed to write root anchor: {e}"),
                    hint: "Run `sudo rauha setup` to configure pf".into(),
                }
            })?;
        }

        Ok(())
    }

    fn anchor_file(&self, zone_name: &str) -> PathBuf {
        self.anchor_dir
            .join(format!("{ANCHOR_ROOT}.zone-{zone_name}"))
    }

    fn load_anchor(&self, zone_name: &str, rules_file: &Path) -> Result<()> {
        let anchor = format!("{ANCHOR_ROOT}/zone-{zone_name}");

        let output = Command::new("pfctl")
            .args(["-a", &anchor, "-f", &rules_file.to_string_lossy()])
            .output()
            .map_err(|e| RauhaError::NetworkError {
                message: format!("failed to load pf rules: {e}"),
                hint: "Is pfctl available? Are you running as root?".into(),
            })?;

        if !output.status.success() {
            return Err(RauhaError::NetworkError {
                message: format!(
                    "pfctl failed to load rules: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
                hint: "Check rule syntax in the anchor file".into(),
            });
        }

        Ok(())
    }
}

/// Generate pf rules from a ZonePolicy.
fn generate_rules(zone_name: &str, policy: &ZonePolicy) -> String {
    let mut rules = String::new();
    let table_name = format!("zone-{zone_name}-ips");

    rules.push_str(&format!("# Rules for zone: {zone_name}\n"));

    match policy.network.mode {
        NetworkMode::Isolated => {
            // Block all outbound traffic from VM.
            rules.push_str(&format!(
                "block out quick on ! lo0 from <{table_name}> to any\n"
            ));
        }
        NetworkMode::Bridged => {
            // Allow traffic but apply egress/ingress rules.
            if !policy.network.allowed_egress.is_empty() {
                // Block all outbound, then allow specific destinations.
                rules.push_str(&format!(
                    "block out quick on ! lo0 from <{table_name}> to any\n"
                ));
                for dest in &policy.network.allowed_egress {
                    rules.push_str(&format!(
                        "pass out quick from <{table_name}> to {dest}\n"
                    ));
                }
            }
            if !policy.network.allowed_ingress.is_empty() {
                for source in &policy.network.allowed_ingress {
                    rules.push_str(&format!(
                        "pass in quick from {source} to <{table_name}>\n"
                    ));
                }
            }
            // Always allow DNS to host resolver.
            rules.push_str(&format!(
                "pass out quick proto udp from <{table_name}> to any port 53\n"
            ));
            rules.push_str(&format!(
                "pass out quick proto tcp from <{table_name}> to any port 53\n"
            ));
        }
        NetworkMode::Host => {
            // No restrictions — VM shares host networking.
            rules.push_str("# host mode: no restrictions\n");
        }
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use rauha_common::zone::*;

    #[test]
    fn generate_isolated_rules() {
        let policy = ZonePolicy {
            network: NetworkPolicy {
                mode: NetworkMode::Isolated,
                ..Default::default()
            },
            ..Default::default()
        };

        let rules = generate_rules("test", &policy);
        assert!(rules.contains("block out quick on ! lo0"));
        assert!(rules.contains("zone-test-ips"));
    }

    #[test]
    fn generate_bridged_rules_with_egress() {
        let policy = ZonePolicy {
            network: NetworkPolicy {
                mode: NetworkMode::Bridged,
                allowed_egress: vec!["10.0.0.0/8".into()],
                ..Default::default()
            },
            ..Default::default()
        };

        let rules = generate_rules("myzone", &policy);
        assert!(rules.contains("block out quick"));
        assert!(rules.contains("pass out quick from <zone-myzone-ips> to 10.0.0.0/8"));
        assert!(rules.contains("port 53")); // DNS always allowed
    }

    #[test]
    fn generate_host_mode_rules() {
        let policy = ZonePolicy {
            network: NetworkPolicy {
                mode: NetworkMode::Host,
                ..Default::default()
            },
            ..Default::default()
        };

        let rules = generate_rules("host-zone", &policy);
        assert!(rules.contains("no restrictions"));
        assert!(!rules.contains("block"));
    }
}
