//! Zone policy loader — reads TOML policy files from a directory.
//!
//! Each file in the policy directory becomes a zone. The filename (without
//! extension) is the zone name. E.g., `agent-sandbox.toml` defines zone
//! `agent-sandbox`.

use std::collections::HashMap;
use std::path::Path;

use rauha_common::zone::ZonePolicy;

/// Load all `.toml` policy files from a directory.
///
/// Returns a map of zone_name → ZonePolicy. Files that fail to parse are
/// logged as warnings and skipped — never silently enforce with wrong policy.
pub fn load_policies(dir: &Path) -> anyhow::Result<HashMap<String, ZonePolicy>> {
    let mut policies = HashMap::new();

    if !dir.exists() {
        tracing::warn!(dir = %dir.display(), "policy directory does not exist — no zones will be enforced");
        return Ok(policies);
    }

    let entries = std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("failed to read policy dir {}: {e}", dir.display()))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(%e, "skipping unreadable directory entry");
                continue;
            }
        };

        let path = entry.path();
        if path.extension().map(|e| e != "toml").unwrap_or(true) {
            continue;
        }

        let zone_name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(file = %path.display(), %e, "skipping unreadable policy file");
                continue;
            }
        };

        match toml::from_str::<ZonePolicy>(&content) {
            Ok(policy) => {
                tracing::info!(zone = zone_name, file = %path.display(), "loaded zone policy");
                policies.insert(zone_name, policy);
            }
            Err(e) => {
                tracing::warn!(
                    file = %path.display(), %e,
                    "failed to parse policy file — zone will not be enforced"
                );
            }
        }
    }

    Ok(policies)
}
