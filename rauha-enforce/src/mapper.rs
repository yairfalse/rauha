//! Zone mapper — maps container labels to zone assignments.
//!
//! Containers with a `rauha.dev/zone` label are assigned to the named zone.
//! Containers without this label are treated as global (no enforcement).

/// Label keys for zone assignment.
pub const LABEL_ZONE: &str = "rauha.dev/zone";
pub const LABEL_POLICY: &str = "rauha.dev/policy";

/// Determine the zone name from container labels.
///
/// Returns None if the container has no `rauha.dev/zone` label (global/unzoned).
pub fn zone_from_labels(labels: &std::collections::HashMap<String, String>) -> Option<String> {
    labels.get(LABEL_ZONE).cloned()
}
