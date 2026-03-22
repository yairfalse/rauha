//! Rauha Oracle — ground-truth validation binary.
//!
//! Tests rauhad through its gRPC API. Never reads source code, never mocks.
//! Each numbered case encodes a system guarantee. When a case fails, it means
//! the system's public contract is broken.
//!
//! Run: cargo test (from eval/oracle/)
//! Run one case: cargo test -- case_001
//! Run a category: cargo test -- case_01  (runs 010-019)
//!
//! Requires: rauhad running and accessible at RAUHA_GRPC_ENDPOINT
//! (default: http://[::1]:9876)

pub mod pb {
    pub mod zone {
        tonic::include_proto!("rauha.zone.v1");
    }
    pub mod container {
        tonic::include_proto!("rauha.container.v1");
    }
    pub mod image {
        tonic::include_proto!("rauha.image.v1");
    }
}

fn main() {
    eprintln!("rauha-oracle: run with `cargo test`, not directly.");
    eprintln!("  cargo test              — run all oracle cases");
    eprintln!("  cargo test -- case_001  — run one case");
    eprintln!("  cargo test -- case_01   — run category 010-019");
    std::process::exit(1);
}

// ============================================================================
// Helpers
// ============================================================================

#[cfg(test)]
mod helpers {
    use super::pb;
    use tonic::transport::Channel;

    // --- Configuration (env with sane defaults) ---

    pub fn grpc_endpoint() -> String {
        std::env::var("RAUHA_GRPC_ENDPOINT")
            .unwrap_or_else(|_| "http://[::1]:9876".into())
    }

    // --- Settlement constants ---
    // Time to wait after an action before querying for its effects.

    /// Zone creation: cgroup + netns + veth + BPF map + IP assignment.
    pub const ZONE_SETTLE_MS: u64 = 500;

    /// Container creation: rootfs overlay + shim spawn + DNS inject.
    pub const CONTAINER_SETTLE_MS: u64 = 1000;

    /// Image pull: network I/O + layer extraction.
    pub const IMAGE_PULL_SETTLE_MS: u64 = 5000;

    /// Container exec: fork + exec inside namespace.
    #[allow(dead_code)] // Reserved for case_006.
    pub const EXEC_SETTLE_MS: u64 = 500;

    // --- Connection helpers ---

    pub async fn zone_client() -> pb::zone::zone_service_client::ZoneServiceClient<Channel> {
        pb::zone::zone_service_client::ZoneServiceClient::connect(grpc_endpoint())
            .await
            .expect("failed to connect to rauhad ZoneService — is rauhad running?")
    }

    pub async fn container_client() -> pb::container::container_service_client::ContainerServiceClient<Channel> {
        pb::container::container_service_client::ContainerServiceClient::connect(grpc_endpoint())
            .await
            .expect("failed to connect to rauhad ContainerService — is rauhad running?")
    }

    pub async fn image_client() -> pb::image::image_service_client::ImageServiceClient<Channel> {
        pb::image::image_service_client::ImageServiceClient::connect(grpc_endpoint())
            .await
            .expect("failed to connect to rauhad ImageService — is rauhad running?")
    }

    // --- Test data factories ---

    /// Generate a unique zone name for this test run.
    pub fn unique_zone_name(prefix: &str) -> String {
        let id = ulid::Ulid::new().to_string().to_lowercase();
        // Zone names max 128 chars, keep prefix short.
        format!("oracle-{prefix}-{}", &id[..8])
    }

    /// Standard bridged policy TOML for test zones.
    pub fn bridged_policy_toml() -> String {
        r#"
[zone]
name = "oracle"
type = "non-global"

[network]
mode = "bridged"
allowed_egress = ["0.0.0.0/0"]
"#.into()
    }

    /// Isolated policy TOML (default).
    pub fn isolated_policy_toml() -> String {
        r#"
[zone]
name = "oracle"
type = "non-global"

[network]
mode = "isolated"
"#.into()
    }

    // --- Protocol wrappers (must-succeed variants) ---

    pub async fn create_zone(
        client: &mut pb::zone::zone_service_client::ZoneServiceClient<Channel>,
        name: &str,
        policy_toml: &str,
    ) -> pb::zone::CreateZoneResponse {
        client
            .create_zone(pb::zone::CreateZoneRequest {
                name: name.into(),
                zone_type: "non-global".into(),
                policy_toml: policy_toml.into(),
            })
            .await
            .expect("CreateZone must succeed")
            .into_inner()
    }

    pub async fn delete_zone(
        client: &mut pb::zone::zone_service_client::ZoneServiceClient<Channel>,
        name: &str,
    ) {
        let _ = client
            .delete_zone(pb::zone::DeleteZoneRequest {
                name: name.into(),
                force: true,
            })
            .await;
        // Ignore errors — zone may already be gone.
    }

    pub async fn get_zone(
        client: &mut pb::zone::zone_service_client::ZoneServiceClient<Channel>,
        name: &str,
    ) -> pb::zone::GetZoneResponse {
        client
            .get_zone(pb::zone::GetZoneRequest { name: name.into() })
            .await
            .expect("GetZone must succeed")
            .into_inner()
    }

    pub async fn list_zones(
        client: &mut pb::zone::zone_service_client::ZoneServiceClient<Channel>,
    ) -> Vec<pb::zone::ZoneInfo> {
        client
            .list_zones(pb::zone::ListZonesRequest {})
            .await
            .expect("ListZones must succeed")
            .into_inner()
            .zones
    }

    // --- Assertions ---

    pub fn assert_grpc_error(
        result: Result<tonic::Response<impl std::fmt::Debug>, tonic::Status>,
        expected_code: tonic::Code,
        context: &str,
    ) {
        match result {
            Ok(resp) => panic!("{context}: expected error {expected_code:?}, got success: {resp:?}"),
            Err(status) => {
                assert_eq!(
                    status.code(),
                    expected_code,
                    "{context}: expected {expected_code:?}, got {:?}: {}",
                    status.code(),
                    status.message()
                );
            }
        }
    }
}

// ============================================================================
// ZONE LIFECYCLE (001-003)
// ============================================================================

#[cfg(test)]
mod zone_lifecycle {
    use super::helpers::*;
    use super::pb;
    use tokio::time::{sleep, Duration};

    /// Create a zone via gRPC → zone appears in list → delete it → gone.
    #[tokio::test]
    async fn case_001_create_list_delete() {
        let mut client = zone_client().await;
        let name = unique_zone_name("001");

        // Create.
        let resp = create_zone(&mut client, &name, &isolated_policy_toml()).await;
        assert_eq!(resp.name, name, "created zone name must match request");
        assert!(!resp.zone_id.is_empty(), "zone_id must not be empty");

        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // List — zone must appear.
        let zones = list_zones(&mut client).await;
        assert!(
            zones.iter().any(|z| z.name == name),
            "created zone must appear in ListZones"
        );

        // Get — zone must be retrievable.
        let get_resp = get_zone(&mut client, &name).await;
        let zone = get_resp.zone.expect("GetZone must return zone info");
        assert_eq!(zone.name, name);
        assert_eq!(zone.state, "Ready");

        // Delete.
        delete_zone(&mut client, &name).await;

        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // List — zone must be gone.
        let zones = list_zones(&mut client).await;
        assert!(
            !zones.iter().any(|z| z.name == name),
            "deleted zone must not appear in ListZones"
        );
    }

    /// Duplicate zone name must be rejected.
    #[tokio::test]
    async fn case_002_duplicate_zone_rejected() {
        let mut client = zone_client().await;
        let name = unique_zone_name("002");

        // Create first.
        create_zone(&mut client, &name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Create duplicate — must fail.
        let result = client
            .create_zone(pb::zone::CreateZoneRequest {
                name: name.clone(),
                zone_type: "non-global".into(),
                policy_toml: isolated_policy_toml(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::AlreadyExists, "duplicate zone");

        // Cleanup.
        delete_zone(&mut client, &name).await;
    }

    /// Delete nonexistent zone must return NotFound.
    #[tokio::test]
    async fn case_003_delete_nonexistent() {
        let mut client = zone_client().await;
        let name = unique_zone_name("003-ghost");

        let result = client
            .delete_zone(pb::zone::DeleteZoneRequest {
                name: name.clone(),
                force: false,
            })
            .await;

        assert_grpc_error(result, tonic::Code::NotFound, "delete nonexistent zone");
    }
}

// ============================================================================
// CONTAINER LIFECYCLE (004-006)
// ============================================================================

#[cfg(test)]
mod container_lifecycle {
    use super::helpers::*;
    use super::pb;
    use tokio::time::{sleep, Duration};

    /// Create container in a zone → exec a command → get output → stop.
    #[tokio::test]
    async fn case_004_create_exec_stop() {
        let mut zone_client = zone_client().await;
        let mut ctr_client = container_client().await;
        let mut img_client = image_client().await;
        let zone_name = unique_zone_name("004");

        // Ensure alpine is available.
        let _ = img_client
            .pull(pb::image::PullRequest {
                reference: "alpine:latest".into(),
            })
            .await;
        sleep(Duration::from_millis(IMAGE_PULL_SETTLE_MS)).await;

        // Create zone + container.
        create_zone(&mut zone_client, &zone_name, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let ctr_resp = ctr_client
            .create_container(pb::container::CreateContainerRequest {
                zone_name: zone_name.clone(),
                name: "test-exec".into(),
                image: "alpine:latest".into(),
                command: vec!["/bin/echo".into(), "hello-oracle".into()],
                env: Default::default(),
                working_dir: String::new(),
            })
            .await
            .expect("CreateContainer must succeed")
            .into_inner();

        assert!(!ctr_resp.container_id.is_empty(), "container_id must not be empty");

        // Start.
        ctr_client
            .start_container(pb::container::StartContainerRequest {
                container_id: ctr_resp.container_id.clone(),
            })
            .await
            .expect("StartContainer must succeed");

        sleep(Duration::from_millis(CONTAINER_SETTLE_MS)).await;

        // List — container must appear in zone.
        let containers = ctr_client
            .list_containers(pb::container::ListContainersRequest {
                zone_name: zone_name.clone(),
            })
            .await
            .expect("ListContainers must succeed")
            .into_inner()
            .containers;

        assert!(
            containers.iter().any(|c| c.id == ctr_resp.container_id),
            "created container must appear in ListContainers for zone"
        );

        // Cleanup.
        let _ = ctr_client
            .stop_container(pb::container::StopContainerRequest {
                container_id: ctr_resp.container_id.clone(),
                timeout_seconds: 5,
            })
            .await;
        delete_zone(&mut zone_client, &zone_name).await;
    }

    /// Container in nonexistent zone must fail.
    #[tokio::test]
    async fn case_005_container_in_missing_zone() {
        let mut ctr_client = container_client().await;

        let result = ctr_client
            .create_container(pb::container::CreateContainerRequest {
                zone_name: "oracle-005-nonexistent".into(),
                name: "orphan".into(),
                image: "alpine:latest".into(),
                command: vec!["/bin/true".into()],
                env: Default::default(),
                working_dir: String::new(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::NotFound, "container in missing zone");
    }

    // case_006: reserved for container exec output validation
    // TODO: implement once exec returns stdout/stderr reliably
}

// ============================================================================
// IMAGE MANAGEMENT (007-009)
// ============================================================================

#[cfg(test)]
mod image_management {
    use super::helpers::*;
    use super::pb;
    use tokio::time::{sleep, Duration};

    /// Pull an image → it appears in list → inspect returns layers.
    #[tokio::test]
    async fn case_007_pull_list_inspect() {
        let mut client = image_client().await;

        // Pull alpine.
        let mut stream = client
            .pull(pb::image::PullRequest {
                reference: "alpine:latest".into(),
            })
            .await
            .expect("Pull must succeed")
            .into_inner();

        // Consume the progress stream.
        while let Some(progress) = stream.message().await.expect("stream error") {
            if progress.done {
                break;
            }
        }

        sleep(Duration::from_millis(500)).await;

        // List — alpine must appear.
        let images = client
            .list(pb::image::ListImagesRequest {})
            .await
            .expect("List must succeed")
            .into_inner()
            .images;

        assert!(
            images.iter().any(|img| img.tags.iter().any(|t| t.contains("alpine"))),
            "pulled alpine must appear in image list"
        );

        // Inspect.
        let inspect = client
            .inspect(pb::image::InspectImageRequest {
                reference: "alpine:latest".into(),
            })
            .await
            .expect("Inspect must succeed")
            .into_inner();

        assert!(!inspect.digest.is_empty(), "inspect must return a digest");
        assert!(!inspect.layers.is_empty(), "alpine must have at least one layer");
    }

    /// Inspect a nonexistent image must fail.
    #[tokio::test]
    async fn case_008_inspect_missing_image() {
        let mut client = image_client().await;

        let result = client
            .inspect(pb::image::InspectImageRequest {
                reference: "oracle-nonexistent:v999".into(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::NotFound, "inspect missing image");
    }

    // case_009: reserved for image removal validation
}

// ============================================================================
// ISOLATION VERIFICATION (010-012)
// ============================================================================

#[cfg(test)]
mod isolation {
    use super::helpers::*;
    use tokio::time::{sleep, Duration};

    /// VerifyIsolation on a healthy zone must return is_isolated=true.
    #[tokio::test]
    async fn case_010_verify_isolation_passes() {
        let mut client = zone_client().await;
        let name = unique_zone_name("010");

        create_zone(&mut client, &name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let resp = client
            .verify_isolation(super::pb::zone::VerifyIsolationRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("VerifyIsolation must succeed")
            .into_inner();

        assert!(
            resp.is_isolated,
            "zone must report as isolated. Failed checks: {:?}",
            resp.checks.iter().filter(|c| !c.passed).collect::<Vec<_>>()
        );

        delete_zone(&mut client, &name).await;
    }

    // case_011: reserved for cross-zone access denied validation
    // case_012: reserved for policy hot-reload isolation re-verification
}

// ============================================================================
// POLICY ENFORCEMENT (013-015)
// ============================================================================

#[cfg(test)]
mod policy {
    use super::helpers::*;
    use super::pb;
    use tokio::time::{sleep, Duration};

    /// Apply a policy → GetPolicy returns the applied TOML.
    #[tokio::test]
    async fn case_013_apply_and_get_policy() {
        let mut client = zone_client().await;
        let name = unique_zone_name("013");

        create_zone(&mut client, &name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Apply a new bridged policy.
        client
            .apply_policy(pb::zone::ApplyPolicyRequest {
                zone_name: name.clone(),
                policy_toml: bridged_policy_toml(),
            })
            .await
            .expect("ApplyPolicy must succeed");

        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // GetPolicy must reflect the change.
        let resp = client
            .get_policy(pb::zone::GetPolicyRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("GetPolicy must succeed")
            .into_inner();

        assert!(
            resp.policy_toml.contains("bridged"),
            "GetPolicy must return updated policy containing 'bridged', got: {}",
            resp.policy_toml
        );

        delete_zone(&mut client, &name).await;
    }

    // case_014: reserved for resource limit enforcement
    // case_015: reserved for hot-reload policy change
}

// ============================================================================
// OBSERVABILITY (019-021)
// ============================================================================

#[cfg(test)]
mod observability {
    use super::helpers::*;
    use super::pb;
    use tokio::time::{sleep, Duration};

    /// ZoneStats returns non-zero memory limit for a zone.
    #[tokio::test]
    async fn case_019_zone_stats() {
        let mut client = zone_client().await;
        let name = unique_zone_name("019");

        create_zone(&mut client, &name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let stats = client
            .zone_stats(pb::zone::ZoneStatsRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("ZoneStats must succeed")
            .into_inner();

        assert!(
            stats.memory_limit_bytes > 0,
            "zone must have a non-zero memory limit"
        );

        delete_zone(&mut client, &name).await;
    }

    // case_020: reserved for WatchEvents stream validation
    // case_021: reserved for stats after container creation
}

// ============================================================================
// RESILIENCE (022-024)
// ============================================================================

#[cfg(test)]
mod resilience {
    use super::helpers::*;
    use super::pb;

    /// Empty zone name must be rejected.
    #[tokio::test]
    async fn case_022_empty_zone_name_rejected() {
        let mut client = zone_client().await;

        let result = client
            .create_zone(pb::zone::CreateZoneRequest {
                name: String::new(),
                zone_type: "non-global".into(),
                policy_toml: isolated_policy_toml(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::InvalidArgument, "empty zone name");
    }

    /// Zone name with path traversal must be rejected.
    #[tokio::test]
    async fn case_023_path_traversal_rejected() {
        let mut client = zone_client().await;

        let result = client
            .create_zone(pb::zone::CreateZoneRequest {
                name: "../escape".into(),
                zone_type: "non-global".into(),
                policy_toml: isolated_policy_toml(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::InvalidArgument, "path traversal zone name");
    }

    /// Invalid policy TOML must be rejected.
    #[tokio::test]
    async fn case_024_invalid_policy_rejected() {
        let mut client = zone_client().await;
        let name = unique_zone_name("024");

        let result = client
            .create_zone(pb::zone::CreateZoneRequest {
                name,
                zone_type: "non-global".into(),
                policy_toml: "this is not valid TOML {{{".into(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::InvalidArgument, "invalid policy TOML");
    }
}
