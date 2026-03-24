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
//!
//! Case ranges:
//!   001-003: Zone lifecycle (create, list, delete)
//!   004-006: Container lifecycle (create, start, exec, stop, delete)
//!   007-009: Image management (pull, list, inspect, remove)
//!   010-012: Isolation verification
//!   013-015: Policy enforcement (apply, hot-reload, resource limits)
//!   016-018: Networking (IP assignment, DNS, cross-zone)
//!   019-021: Observability (stats, logs, container count)
//!   022-029: Resilience (input validation, error codes, force delete)
//!   030-034: Multi-zone interaction
//!   035-039: Container edge cases
//!   040-049: Invariants & data integrity
//!   050-054: Stress & boundary conditions

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

    /// Zone creation: cgroup + netns + veth + BPF map + IP assignment.
    pub const ZONE_SETTLE_MS: u64 = 500;

    /// Container creation: rootfs overlay + shim spawn + DNS inject.
    pub const CONTAINER_SETTLE_MS: u64 = 1000;

    /// Image pull: network I/O + layer extraction.
    pub const IMAGE_PULL_SETTLE_MS: u64 = 5000;

    /// Container exec: fork + exec inside namespace.
    pub const EXEC_SETTLE_MS: u64 = 500;

    /// Container stop: SIGTERM + wait + SIGKILL.
    pub const STOP_SETTLE_MS: u64 = 1000;

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

    pub fn unique_zone_name(prefix: &str) -> String {
        let id = ulid::Ulid::new().to_string().to_lowercase();
        format!("oracle-{prefix}-{}", &id[..8])
    }

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

    pub fn isolated_policy_toml() -> String {
        r#"
[zone]
name = "oracle"
type = "non-global"

[network]
mode = "isolated"
"#.into()
    }

    pub fn policy_with_memory(mem: &str) -> String {
        format!(r#"
[zone]
name = "oracle"
type = "non-global"

[resources]
memory_limit = "{mem}"
"#)
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

    /// Cleanup helper — logs failures instead of silently eating them.
    /// Verifies the zone is actually gone after deletion.
    pub async fn delete_zone_checked(
        client: &mut pb::zone::zone_service_client::ZoneServiceClient<Channel>,
        name: &str,
    ) {
        match client
            .delete_zone(pb::zone::DeleteZoneRequest {
                name: name.into(),
                force: true,
            })
            .await
        {
            Ok(_) => {}
            Err(status) if status.code() == tonic::Code::NotFound => {
                // Already gone — fine.
            }
            Err(status) => {
                panic!(
                    "delete_zone cleanup failed for '{}': {:?}: {}",
                    name,
                    status.code(),
                    status.message()
                );
            }
        }
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

    pub async fn ensure_alpine(client: &mut pb::image::image_service_client::ImageServiceClient<Channel>) {
        let mut stream = client
            .pull(pb::image::PullRequest {
                reference: "alpine:latest".into(),
            })
            .await
            .expect("Pull must succeed")
            .into_inner();
        while let Some(p) = stream.message().await.expect("stream error") {
            if p.done { break; }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(IMAGE_PULL_SETTLE_MS)).await;
    }

    pub async fn create_and_start_container(
        ctr_client: &mut pb::container::container_service_client::ContainerServiceClient<Channel>,
        zone_name: &str,
        name: &str,
        command: Vec<String>,
    ) -> String {
        let resp = ctr_client
            .create_container(pb::container::CreateContainerRequest {
                zone_name: zone_name.into(),
                name: name.into(),
                image: "alpine:latest".into(),
                command,
                env: Default::default(),
                working_dir: String::new(),
            })
            .await
            .expect("CreateContainer must succeed")
            .into_inner();

        ctr_client
            .start_container(pb::container::StartContainerRequest {
                container_id: resp.container_id.clone(),
            })
            .await
            .expect("StartContainer must succeed");

        tokio::time::sleep(tokio::time::Duration::from_millis(CONTAINER_SETTLE_MS)).await;
        resp.container_id
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

        let resp = create_zone(&mut client, &name, &isolated_policy_toml()).await;
        assert_eq!(resp.name, name, "created zone name must match request");
        assert!(!resp.zone_id.is_empty(), "zone_id must not be empty");
        assert!(!resp.state.is_empty(), "CreateZoneResponse.state must not be empty");

        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let zones = list_zones(&mut client).await;
        assert!(zones.iter().any(|z| z.name == name), "zone must appear in list");

        let get_resp = get_zone(&mut client, &name).await;
        let zone = get_resp.zone.expect("GetZone must return zone info");
        assert_eq!(zone.name, name);
        assert_eq!(zone.state, "Ready");

        delete_zone_checked(&mut client, &name).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let zones = list_zones(&mut client).await;
        assert!(!zones.iter().any(|z| z.name == name), "zone must be gone after delete");
    }

    /// Duplicate zone name must be rejected.
    #[tokio::test]
    async fn case_002_duplicate_zone_rejected() {
        let mut client = zone_client().await;
        let name = unique_zone_name("002");

        create_zone(&mut client, &name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let result = client
            .create_zone(pb::zone::CreateZoneRequest {
                name: name.clone(),
                zone_type: "non-global".into(),
                policy_toml: isolated_policy_toml(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::AlreadyExists, "duplicate zone");
        delete_zone_checked(&mut client, &name).await;
    }

    /// Delete nonexistent zone must return NotFound.
    #[tokio::test]
    async fn case_003_delete_nonexistent() {
        let mut client = zone_client().await;
        let name = unique_zone_name("003-ghost");

        let result = client
            .delete_zone(pb::zone::DeleteZoneRequest {
                name,
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

    /// Create container → start → verify in list → stop → verify stopped.
    #[tokio::test]
    async fn case_004_create_start_list_stop() {
        let mut zone_cl = zone_client().await;
        let mut ctr_cl = container_client().await;
        let mut img_cl = image_client().await;
        let zone_name = unique_zone_name("004");

        ensure_alpine(&mut img_cl).await;
        create_zone(&mut zone_cl, &zone_name, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let ctr_id = create_and_start_container(
            &mut ctr_cl,
            &zone_name,
            "test-004",
            vec!["/bin/sleep".into(), "30".into()],
        ).await;

        // Container must appear in zone listing.
        let containers = ctr_cl
            .list_containers(pb::container::ListContainersRequest {
                zone_name: zone_name.clone(),
            })
            .await
            .expect("ListContainers must succeed")
            .into_inner()
            .containers;

        assert!(
            containers.iter().any(|c| c.id == ctr_id),
            "container must appear in ListContainers"
        );

        // Stop and verify.
        ctr_cl
            .stop_container(pb::container::StopContainerRequest {
                container_id: ctr_id.clone(),
                timeout_seconds: 5,
            })
            .await
            .expect("StopContainer must succeed");

        sleep(Duration::from_millis(STOP_SETTLE_MS)).await;

        // After stop, container state must not be "Running".
        let get_resp = ctr_cl
            .get_container(pb::container::GetContainerRequest {
                container_id: ctr_id,
            })
            .await;
        // Container may be gone (cleaned up) or in stopped state — both are valid.
        // What's NOT valid is it still being "Running".
        if let Ok(resp) = get_resp {
            let info = resp.into_inner().container.unwrap();
            assert_ne!(info.state, "Running", "container must not be Running after stop");
        }

        delete_zone_checked(&mut zone_cl, &zone_name).await;
    }

    /// Container in nonexistent zone must fail.
    #[tokio::test]
    async fn case_005_container_in_missing_zone() {
        let mut ctr_cl = container_client().await;

        let result = ctr_cl
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

    /// Short-lived container runs a command and exits.
    #[tokio::test]
    async fn case_006_container_runs_and_exits() {
        let mut zone_cl = zone_client().await;
        let mut ctr_cl = container_client().await;
        let mut img_cl = image_client().await;
        let zone_name = unique_zone_name("006");

        ensure_alpine(&mut img_cl).await;
        create_zone(&mut zone_cl, &zone_name, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let resp = ctr_cl
            .create_container(pb::container::CreateContainerRequest {
                zone_name: zone_name.clone(),
                name: "echo-test".into(),
                image: "alpine:latest".into(),
                command: vec!["/bin/echo".into(), "hello-oracle".into()],
                env: Default::default(),
                working_dir: String::new(),
            })
            .await
            .expect("CreateContainer must succeed")
            .into_inner();

        assert!(!resp.container_id.is_empty(), "container_id must not be empty");

        ctr_cl
            .start_container(pb::container::StartContainerRequest {
                container_id: resp.container_id.clone(),
            })
            .await
            .expect("StartContainer must succeed");

        // Wait for the short-lived process to exit.
        sleep(Duration::from_millis(EXEC_SETTLE_MS)).await;

        // Verify the container is no longer Running (it exited naturally).
        let get_result = ctr_cl
            .get_container(pb::container::GetContainerRequest {
                container_id: resp.container_id.clone(),
            })
            .await;

        if let Ok(get_resp) = get_result {
            let info = get_resp.into_inner().container.unwrap();
            assert_ne!(
                info.state, "Running",
                "short-lived container must not be Running after exec_settle"
            );
        }
        // If GetContainer returns NotFound, the container was cleaned up — also valid.

        delete_zone_checked(&mut zone_cl, &zone_name).await;
    }
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

        ensure_alpine(&mut client).await;

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

        let inspect = client
            .inspect(pb::image::InspectImageRequest {
                reference: "alpine:latest".into(),
            })
            .await
            .expect("Inspect must succeed")
            .into_inner();

        assert!(!inspect.digest.is_empty(), "inspect must return a digest");
        assert!(inspect.digest.starts_with("sha256:"), "digest must be sha256");
        assert!(!inspect.layers.is_empty(), "alpine must have at least one layer");
        assert!(inspect.layers.iter().all(|l| l.starts_with("sha256:")), "layer digests must be sha256");
        assert!(inspect.size > 0, "image size must be non-zero");
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

    /// Remove an image → inspect fails. Uses busybox to avoid racing with alpine users.
    #[tokio::test]
    async fn case_009_remove_image() {
        let mut client = image_client().await;
        let image_ref = "busybox:latest";

        // Pull busybox for this test.
        let mut stream = client
            .pull(pb::image::PullRequest {
                reference: image_ref.into(),
            })
            .await
            .expect("Pull must succeed")
            .into_inner();
        while let Some(p) = stream.message().await.expect("stream error") {
            if p.done { break; }
        }
        sleep(Duration::from_millis(IMAGE_PULL_SETTLE_MS)).await;

        // Verify it's there before removing.
        client
            .inspect(pb::image::InspectImageRequest {
                reference: image_ref.into(),
            })
            .await
            .expect("busybox must be inspectable before remove");

        // Remove.
        client
            .remove(pb::image::RemoveImageRequest {
                reference: image_ref.into(),
            })
            .await
            .expect("Remove must succeed");

        sleep(Duration::from_millis(200)).await;

        // Inspect must now fail.
        let result = client
            .inspect(pb::image::InspectImageRequest {
                reference: image_ref.into(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::NotFound, "inspect after remove");
    }
}

// ============================================================================
// ISOLATION VERIFICATION (010-012)
// ============================================================================

#[cfg(test)]
mod isolation {
    use super::helpers::*;
    use super::pb;
    use tokio::time::{sleep, Duration};

    /// VerifyIsolation on a healthy zone must return is_isolated=true.
    #[tokio::test]
    async fn case_010_verify_isolation_passes() {
        let mut client = zone_client().await;
        let name = unique_zone_name("010");

        create_zone(&mut client, &name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let resp = client
            .verify_isolation(pb::zone::VerifyIsolationRequest {
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

        assert!(!resp.checks.is_empty(), "isolation report must include checks");
        assert!(
            resp.checks.iter().all(|c| c.passed),
            "all isolation checks must pass"
        );

        delete_zone_checked(&mut client, &name).await;
    }

    /// VerifyIsolation on nonexistent zone must return NotFound.
    #[tokio::test]
    async fn case_011_verify_nonexistent_zone() {
        let mut client = zone_client().await;

        let result = client
            .verify_isolation(pb::zone::VerifyIsolationRequest {
                zone_name: "oracle-011-ghost".into(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::NotFound, "verify nonexistent zone");
    }

    /// Policy hot-reload does not break isolation. Verifies reload actually took effect.
    #[tokio::test]
    async fn case_012_isolation_survives_policy_reload() {
        let mut client = zone_client().await;
        let name = unique_zone_name("012");

        create_zone(&mut client, &name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Hot-reload to bridged policy.
        client
            .apply_policy(pb::zone::ApplyPolicyRequest {
                zone_name: name.clone(),
                policy_toml: bridged_policy_toml(),
            })
            .await
            .expect("ApplyPolicy must succeed");

        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Confirm the reload actually changed the policy.
        let policy_resp = client
            .get_policy(pb::zone::GetPolicyRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("GetPolicy must succeed")
            .into_inner();

        assert!(
            policy_resp.policy_toml.contains(r#"mode = "bridged""#),
            "policy must have been reloaded to bridged mode, got: {}",
            policy_resp.policy_toml
        );

        // Isolation must still hold after reload.
        let resp = client
            .verify_isolation(pb::zone::VerifyIsolationRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("VerifyIsolation must succeed")
            .into_inner();

        assert!(
            resp.is_isolated,
            "zone must remain isolated after policy reload. Failed: {:?}",
            resp.checks.iter().filter(|c| !c.passed).collect::<Vec<_>>()
        );

        delete_zone_checked(&mut client, &name).await;
    }
}

// ============================================================================
// POLICY ENFORCEMENT (013-015)
// ============================================================================

#[cfg(test)]
mod policy {
    use super::helpers::*;
    use super::pb;
    use tokio::time::{sleep, Duration};

    /// Apply a policy → GetPolicy returns the applied TOML with correct mode.
    #[tokio::test]
    async fn case_013_apply_and_get_policy() {
        let mut client = zone_client().await;
        let name = unique_zone_name("013");

        create_zone(&mut client, &name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Verify initial policy is isolated.
        let initial = client
            .get_policy(pb::zone::GetPolicyRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("GetPolicy must succeed")
            .into_inner();

        assert!(
            initial.policy_toml.contains(r#"mode = "isolated""#),
            "initial policy must be isolated mode, got: {}",
            initial.policy_toml
        );

        // Apply bridged policy.
        client
            .apply_policy(pb::zone::ApplyPolicyRequest {
                zone_name: name.clone(),
                policy_toml: bridged_policy_toml(),
            })
            .await
            .expect("ApplyPolicy must succeed");

        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Verify updated policy.
        let updated = client
            .get_policy(pb::zone::GetPolicyRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("GetPolicy must succeed")
            .into_inner();

        assert!(
            updated.policy_toml.contains(r#"mode = "bridged""#),
            "updated policy must be bridged mode, got: {}",
            updated.policy_toml
        );

        delete_zone_checked(&mut client, &name).await;
    }

    /// Memory limit in policy is reflected in ZoneStats.
    #[tokio::test]
    async fn case_014_memory_limit_from_policy() {
        let mut client = zone_client().await;
        let name = unique_zone_name("014");

        create_zone(&mut client, &name, &policy_with_memory("256Mi")).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let stats = client
            .zone_stats(pb::zone::ZoneStatsRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("ZoneStats must succeed")
            .into_inner();

        assert_eq!(
            stats.memory_limit_bytes,
            256 * 1024 * 1024,
            "memory_limit_bytes must be 256Mi (268435456)"
        );

        delete_zone_checked(&mut client, &name).await;
    }

    /// Apply invalid policy to existing zone → INVALID_ARGUMENT, zone survives.
    #[tokio::test]
    async fn case_015_apply_invalid_policy() {
        let mut client = zone_client().await;
        let name = unique_zone_name("015");

        create_zone(&mut client, &name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let result = client
            .apply_policy(pb::zone::ApplyPolicyRequest {
                zone_name: name.clone(),
                policy_toml: "not valid toml {{{".into(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::InvalidArgument, "apply invalid policy");

        // Zone must still work after rejected policy.
        let get_resp = get_zone(&mut client, &name).await;
        let zone = get_resp.zone.expect("zone must survive rejected policy apply");
        assert_eq!(zone.state, "Ready", "zone must still be Ready after rejected apply");

        delete_zone_checked(&mut client, &name).await;
    }
}

// ============================================================================
// NETWORKING (016-018)
// ============================================================================

#[cfg(test)]
mod networking {
    use super::helpers::*;
    use super::pb;
    use tokio::time::{sleep, Duration};

    /// Bridged zone creation succeeds and isolation passes.
    #[tokio::test]
    async fn case_016_bridged_zone_creation() {
        let mut client = zone_client().await;
        let name = unique_zone_name("016");

        create_zone(&mut client, &name, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let get_resp = get_zone(&mut client, &name).await;
        let zone = get_resp.zone.expect("zone must exist");
        assert_eq!(zone.state, "Ready", "bridged zone must reach Ready state");

        let iso = client
            .verify_isolation(pb::zone::VerifyIsolationRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("VerifyIsolation must succeed")
            .into_inner();

        assert!(iso.is_isolated, "bridged zone must be isolated");

        delete_zone_checked(&mut client, &name).await;
    }

    /// Zone created with host networking mode — policy round-trips correctly.
    #[tokio::test]
    async fn case_017_host_network_mode() {
        let mut client = zone_client().await;
        let name = unique_zone_name("017");

        let host_policy = r#"
[zone]
name = "oracle"
type = "non-global"

[network]
mode = "host"
"#;
        create_zone(&mut client, &name, host_policy).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let resp = client
            .get_policy(pb::zone::GetPolicyRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("GetPolicy must succeed")
            .into_inner();

        assert!(
            resp.policy_toml.contains(r#"mode = "host""#),
            "policy must contain host mode as key-value, got: {}",
            resp.policy_toml
        );

        delete_zone_checked(&mut client, &name).await;
    }

    /// Container in bridged zone can be created (rootfs + DNS injection succeeds).
    #[tokio::test]
    async fn case_018_container_in_bridged_zone() {
        let mut zone_cl = zone_client().await;
        let mut ctr_cl = container_client().await;
        let mut img_cl = image_client().await;
        let zone_name = unique_zone_name("018");

        ensure_alpine(&mut img_cl).await;
        create_zone(&mut zone_cl, &zone_name, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Create and start a container that reads resolv.conf.
        let ctr_id = create_and_start_container(
            &mut ctr_cl,
            &zone_name,
            "dns-test",
            vec!["/bin/cat".into(), "/etc/resolv.conf".into()],
        ).await;

        // If we got here, the container was created, rootfs was prepared
        // (including DNS injection), and the process started successfully.
        // Verify the container actually ran by checking it's in the list.
        let containers = ctr_cl
            .list_containers(pb::container::ListContainersRequest {
                zone_name: zone_name.clone(),
            })
            .await
            .expect("ListContainers must succeed")
            .into_inner()
            .containers;

        assert!(
            containers.iter().any(|c| c.id == ctr_id),
            "container must appear in zone listing after start"
        );

        delete_zone_checked(&mut zone_cl, &zone_name).await;
    }
}

// ============================================================================
// OBSERVABILITY (019-021)
// ============================================================================

#[cfg(test)]
mod observability {
    use super::helpers::*;
    use super::pb;
    use tokio::time::{sleep, Duration};

    /// ZoneStats returns non-zero memory limit and valid zone_id.
    #[tokio::test]
    async fn case_019_zone_stats() {
        let mut client = zone_client().await;
        let name = unique_zone_name("019");

        let create_resp = create_zone(&mut client, &name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let stats = client
            .zone_stats(pb::zone::ZoneStatsRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("ZoneStats must succeed")
            .into_inner();

        assert!(stats.memory_limit_bytes > 0, "zone must have non-zero memory limit");
        assert_eq!(stats.zone_id, create_resp.zone_id, "stats zone_id must match created zone_id");

        delete_zone_checked(&mut client, &name).await;
    }

    /// ZoneStats on nonexistent zone returns NotFound.
    #[tokio::test]
    async fn case_020_stats_nonexistent_zone() {
        let mut client = zone_client().await;

        let result = client
            .zone_stats(pb::zone::ZoneStatsRequest {
                zone_name: "oracle-020-ghost".into(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::NotFound, "stats nonexistent zone");
    }

    /// GetPolicy on nonexistent zone returns NotFound.
    #[tokio::test]
    async fn case_021_get_policy_nonexistent() {
        let mut client = zone_client().await;

        let result = client
            .get_policy(pb::zone::GetPolicyRequest {
                zone_name: "oracle-021-ghost".into(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::NotFound, "get policy nonexistent zone");
    }
}

// ============================================================================
// RESILIENCE (022-029)
// ============================================================================

#[cfg(test)]
mod resilience {
    use super::helpers::*;
    use super::pb;

    #[tokio::test]
    async fn case_022_empty_zone_name_rejected() {
        let mut client = zone_client().await;
        let result = client.create_zone(pb::zone::CreateZoneRequest {
            name: String::new(), zone_type: "non-global".into(), policy_toml: isolated_policy_toml(),
        }).await;
        assert_grpc_error(result, tonic::Code::InvalidArgument, "empty zone name");
    }

    #[tokio::test]
    async fn case_023_path_traversal_rejected() {
        let mut client = zone_client().await;
        let result = client.create_zone(pb::zone::CreateZoneRequest {
            name: "../escape".into(), zone_type: "non-global".into(), policy_toml: isolated_policy_toml(),
        }).await;
        assert_grpc_error(result, tonic::Code::InvalidArgument, "path traversal zone name");
    }

    #[tokio::test]
    async fn case_024_invalid_policy_rejected() {
        let mut client = zone_client().await;
        let result = client.create_zone(pb::zone::CreateZoneRequest {
            name: unique_zone_name("024"), zone_type: "non-global".into(),
            policy_toml: "this is not valid TOML {{{".into(),
        }).await;
        assert_grpc_error(result, tonic::Code::InvalidArgument, "invalid policy TOML");
    }

    #[tokio::test]
    async fn case_025_nul_byte_rejected() {
        let mut client = zone_client().await;
        let result = client.create_zone(pb::zone::CreateZoneRequest {
            name: "bad\0name".into(), zone_type: "non-global".into(), policy_toml: isolated_policy_toml(),
        }).await;
        assert_grpc_error(result, tonic::Code::InvalidArgument, "NUL byte in zone name");
    }

    #[tokio::test]
    async fn case_026_dot_name_rejected() {
        let mut client = zone_client().await;
        let result = client.create_zone(pb::zone::CreateZoneRequest {
            name: ".".into(), zone_type: "non-global".into(), policy_toml: isolated_policy_toml(),
        }).await;
        assert_grpc_error(result, tonic::Code::InvalidArgument, "dot zone name");
    }

    #[tokio::test]
    async fn case_027_long_name_rejected() {
        let mut client = zone_client().await;
        let result = client.create_zone(pb::zone::CreateZoneRequest {
            name: "a".repeat(129), zone_type: "non-global".into(), policy_toml: isolated_policy_toml(),
        }).await;
        assert_grpc_error(result, tonic::Code::InvalidArgument, "name too long");
    }

    #[tokio::test]
    async fn case_028_apply_policy_missing_zone() {
        let mut client = zone_client().await;
        let result = client.apply_policy(pb::zone::ApplyPolicyRequest {
            zone_name: "oracle-028-ghost".into(), policy_toml: isolated_policy_toml(),
        }).await;
        assert_grpc_error(result, tonic::Code::NotFound, "apply policy to missing zone");
    }

    #[tokio::test]
    async fn case_029_get_missing_zone() {
        let mut client = zone_client().await;
        let result = client.get_zone(pb::zone::GetZoneRequest {
            name: "oracle-029-ghost".into(),
        }).await;
        assert_grpc_error(result, tonic::Code::NotFound, "get missing zone");
    }
}

// ============================================================================
// MULTI-ZONE INTERACTION (030-034)
// ============================================================================

#[cfg(test)]
mod multi_zone {
    use super::helpers::*;
    use super::pb;
    use tokio::time::{sleep, Duration};

    /// Multiple zones can coexist and be listed.
    #[tokio::test]
    async fn case_030_multiple_zones_coexist() {
        let mut client = zone_client().await;
        let name_a = unique_zone_name("030a");
        let name_b = unique_zone_name("030b");

        create_zone(&mut client, &name_a, &isolated_policy_toml()).await;
        create_zone(&mut client, &name_b, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let zones = list_zones(&mut client).await;
        assert!(zones.iter().any(|z| z.name == name_a), "zone A must be in list");
        assert!(zones.iter().any(|z| z.name == name_b), "zone B must be in list");

        delete_zone_checked(&mut client, &name_a).await;
        delete_zone_checked(&mut client, &name_b).await;
    }

    /// Deleting one zone does not affect another.
    #[tokio::test]
    async fn case_031_delete_one_preserves_other() {
        let mut client = zone_client().await;
        let name_a = unique_zone_name("031a");
        let name_b = unique_zone_name("031b");

        create_zone(&mut client, &name_a, &isolated_policy_toml()).await;
        create_zone(&mut client, &name_b, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        delete_zone_checked(&mut client, &name_a).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let get_resp = get_zone(&mut client, &name_b).await;
        let zone = get_resp.zone.expect("zone B must survive deletion of A");
        assert_eq!(zone.state, "Ready");

        delete_zone_checked(&mut client, &name_b).await;
    }

    /// Zones with different policies both pass isolation.
    #[tokio::test]
    async fn case_032_mixed_policy_zones() {
        let mut client = zone_client().await;
        let isolated = unique_zone_name("032-iso");
        let bridged = unique_zone_name("032-br");

        create_zone(&mut client, &isolated, &isolated_policy_toml()).await;
        create_zone(&mut client, &bridged, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        for name in [&isolated, &bridged] {
            let resp = client
                .verify_isolation(pb::zone::VerifyIsolationRequest {
                    zone_name: name.clone(),
                })
                .await
                .expect("VerifyIsolation must succeed")
                .into_inner();

            assert!(resp.is_isolated, "zone {} must be isolated", name);
        }

        delete_zone_checked(&mut client, &isolated).await;
        delete_zone_checked(&mut client, &bridged).await;
    }

    /// Containers are scoped to their zone — list A doesn't show B's containers.
    #[tokio::test]
    async fn case_033_containers_scoped_to_zone() {
        let mut zone_cl = zone_client().await;
        let mut ctr_cl = container_client().await;
        let mut img_cl = image_client().await;
        let zone_a = unique_zone_name("033a");
        let zone_b = unique_zone_name("033b");

        ensure_alpine(&mut img_cl).await;
        create_zone(&mut zone_cl, &zone_a, &bridged_policy_toml()).await;
        create_zone(&mut zone_cl, &zone_b, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let ctr_a = create_and_start_container(
            &mut ctr_cl, &zone_a, "ctr-a", vec!["/bin/sleep".into(), "30".into()],
        ).await;
        let ctr_b = create_and_start_container(
            &mut ctr_cl, &zone_b, "ctr-b", vec!["/bin/sleep".into(), "30".into()],
        ).await;

        // List zone A — must see ctr_a but NOT ctr_b.
        let list_a = ctr_cl
            .list_containers(pb::container::ListContainersRequest {
                zone_name: zone_a.clone(),
            })
            .await.expect("ListContainers must succeed")
            .into_inner().containers;

        assert!(list_a.iter().any(|c| c.id == ctr_a), "zone A must contain ctr_a");
        assert!(!list_a.iter().any(|c| c.id == ctr_b), "zone A must NOT contain ctr_b");

        // Verify zone_name field in the response is correct.
        let ctr_a_info = list_a.iter().find(|c| c.id == ctr_a).unwrap();
        assert!(
            ctr_a_info.zone_name == zone_a || ctr_a_info.zone_name.is_empty(),
            "container zone_name must match zone A or be empty (TODO), got: {}",
            ctr_a_info.zone_name
        );

        // List zone B — must see ctr_b but NOT ctr_a.
        let list_b = ctr_cl
            .list_containers(pb::container::ListContainersRequest {
                zone_name: zone_b.clone(),
            })
            .await.expect("ListContainers must succeed")
            .into_inner().containers;

        assert!(list_b.iter().any(|c| c.id == ctr_b), "zone B must contain ctr_b");
        assert!(!list_b.iter().any(|c| c.id == ctr_a), "zone B must NOT contain ctr_a");

        delete_zone_checked(&mut zone_cl, &zone_a).await;
        delete_zone_checked(&mut zone_cl, &zone_b).await;
    }

    /// Force-delete zone with running container — zone gone, container gone.
    #[tokio::test]
    async fn case_034_force_delete_zone_with_container() {
        let mut zone_cl = zone_client().await;
        let mut ctr_cl = container_client().await;
        let mut img_cl = image_client().await;
        let zone_name = unique_zone_name("034");

        ensure_alpine(&mut img_cl).await;
        create_zone(&mut zone_cl, &zone_name, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let ctr_id = create_and_start_container(
            &mut ctr_cl, &zone_name, "doomed", vec!["/bin/sleep".into(), "300".into()],
        ).await;

        // Force delete.
        zone_cl
            .delete_zone(pb::zone::DeleteZoneRequest {
                name: zone_name.clone(),
                force: true,
            })
            .await
            .expect("force delete with running container must succeed");

        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Zone must be gone.
        let zones = list_zones(&mut zone_cl).await;
        assert!(
            !zones.iter().any(|z| z.name == zone_name),
            "force-deleted zone must not appear in list"
        );

        // Container must also be gone (or at least not findable).
        let ctr_result = ctr_cl
            .get_container(pb::container::GetContainerRequest {
                container_id: ctr_id,
            })
            .await;

        assert!(
            ctr_result.is_err(),
            "container in force-deleted zone must not be retrievable"
        );
    }
}

// ============================================================================
// CONTAINER EDGE CASES (035-039)
// ============================================================================

#[cfg(test)]
mod container_edge_cases {
    use super::helpers::*;
    use super::pb;

    /// Stop nonexistent container → NotFound.
    #[tokio::test]
    async fn case_035_stop_nonexistent_container() {
        let mut client = container_client().await;

        let result = client
            .stop_container(pb::container::StopContainerRequest {
                container_id: "00000000-0000-0000-0000-000000000000".into(),
                timeout_seconds: 5,
            })
            .await;

        assert_grpc_error(result, tonic::Code::NotFound, "stop nonexistent container");
    }

    /// Get nonexistent container → NotFound.
    #[tokio::test]
    async fn case_036_get_nonexistent_container() {
        let mut client = container_client().await;

        let result = client
            .get_container(pb::container::GetContainerRequest {
                container_id: "00000000-0000-0000-0000-000000000000".into(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::NotFound, "get nonexistent container");
    }

    /// ListContainers with empty zone_name returns a valid list (not an error).
    #[tokio::test]
    async fn case_037_list_all_containers() {
        let mut ctr_cl = container_client().await;

        let resp = ctr_cl
            .list_containers(pb::container::ListContainersRequest {
                zone_name: String::new(),
            })
            .await
            .expect("ListContainers with empty zone must succeed");

        let containers = resp.into_inner().containers;
        // Every container in the global list must have a non-empty id.
        for ctr in &containers {
            assert!(!ctr.id.is_empty(), "container in global list must have non-empty id");
        }
    }

    /// Delete nonexistent container → NotFound.
    #[tokio::test]
    async fn case_038_delete_nonexistent_container() {
        let mut client = container_client().await;

        let result = client
            .delete_container(pb::container::DeleteContainerRequest {
                container_id: "00000000-0000-0000-0000-000000000000".into(),
                force: false,
            })
            .await;

        assert_grpc_error(result, tonic::Code::NotFound, "delete nonexistent container");
    }

    /// Invalid container ID format returns error.
    #[tokio::test]
    async fn case_039_invalid_container_id_format() {
        let mut client = container_client().await;

        let result = client
            .get_container(pb::container::GetContainerRequest {
                container_id: "not-a-uuid".into(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::InvalidArgument, "invalid container ID");
    }
}

// ============================================================================
// INVARIANTS & DATA INTEGRITY (040-049)
// ============================================================================

#[cfg(test)]
mod invariants {
    use super::helpers::*;
    use super::pb;
    use tokio::time::{sleep, Duration};

    /// zone_id is consistent across create, get, list, and stats.
    #[tokio::test]
    async fn case_040_zone_id_consistent_across_apis() {
        let mut client = zone_client().await;
        let name = unique_zone_name("040");

        let create_resp = create_zone(&mut client, &name, &isolated_policy_toml()).await;
        let zone_id = create_resp.zone_id.clone();
        assert!(!zone_id.is_empty());

        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // GetZone must return the same id.
        let get_resp = get_zone(&mut client, &name).await;
        let zone_info = get_resp.zone.unwrap();
        assert_eq!(zone_info.id, zone_id, "GetZone.id must match CreateZone.zone_id");

        // ListZones must contain the same id.
        let zones = list_zones(&mut client).await;
        let listed = zones.iter().find(|z| z.name == name).expect("zone must be in list");
        assert_eq!(listed.id, zone_id, "ListZones.id must match CreateZone.zone_id");

        // ZoneStats must return the same id.
        let stats = client
            .zone_stats(pb::zone::ZoneStatsRequest { zone_name: name.clone() })
            .await
            .expect("ZoneStats must succeed")
            .into_inner();
        assert_eq!(stats.zone_id, zone_id, "ZoneStats.zone_id must match CreateZone.zone_id");

        delete_zone_checked(&mut client, &name).await;
    }

    /// created_at is a valid, non-empty timestamp that is not in the future.
    #[tokio::test]
    async fn case_041_created_at_is_valid_timestamp() {
        let mut client = zone_client().await;
        let name = unique_zone_name("041");

        create_zone(&mut client, &name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let get_resp = get_zone(&mut client, &name).await;
        let zone = get_resp.zone.unwrap();

        assert!(!zone.created_at.is_empty(), "created_at must not be empty");
        // Must be parseable — the format should be RFC3339 or similar.
        assert!(
            zone.created_at.contains('T') || zone.created_at.contains('-'),
            "created_at must look like a timestamp, got: {}",
            zone.created_at
        );
        // Must not be a zero/epoch value.
        assert!(
            !zone.created_at.starts_with("1970"),
            "created_at must not be epoch, got: {}",
            zone.created_at
        );

        delete_zone_checked(&mut client, &name).await;
    }

    /// Create 5 zones, delete 2, exactly 3 remain (our 3, not others).
    #[tokio::test]
    async fn case_042_batch_create_partial_delete() {
        let mut client = zone_client().await;
        let prefix = unique_zone_name("042");
        let names: Vec<String> = (0..5).map(|i| format!("{prefix}-{i}")).collect();

        // Create all 5.
        for name in &names {
            create_zone(&mut client, name, &isolated_policy_toml()).await;
        }
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Delete the first 2.
        delete_zone_checked(&mut client, &names[0]).await;
        delete_zone_checked(&mut client, &names[1]).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // List — exactly names[2..5] must be present (from our batch).
        let zones = list_zones(&mut client).await;
        for deleted in &names[..2] {
            assert!(
                !zones.iter().any(|z| z.name == *deleted),
                "deleted zone {} must not be in list",
                deleted
            );
        }
        for remaining in &names[2..] {
            assert!(
                zones.iter().any(|z| z.name == *remaining),
                "surviving zone {} must be in list",
                remaining
            );
        }

        // Cleanup.
        for name in &names[2..] {
            delete_zone_checked(&mut client, name).await;
        }
    }

    /// Deleting a zone twice — second delete returns NotFound, not success.
    #[tokio::test]
    async fn case_043_double_delete_returns_not_found() {
        let mut client = zone_client().await;
        let name = unique_zone_name("043");

        create_zone(&mut client, &name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // First delete — must succeed.
        client
            .delete_zone(pb::zone::DeleteZoneRequest {
                name: name.clone(),
                force: true,
            })
            .await
            .expect("first delete must succeed");

        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Second delete — must return NotFound.
        let result = client
            .delete_zone(pb::zone::DeleteZoneRequest {
                name: name.clone(),
                force: true,
            })
            .await;

        assert_grpc_error(result, tonic::Code::NotFound, "second delete of same zone");
    }

    /// Privileged zone type is accepted and round-trips through GetZone.
    #[tokio::test]
    async fn case_044_privileged_zone_type() {
        let mut client = zone_client().await;
        let name = unique_zone_name("044");

        client
            .create_zone(pb::zone::CreateZoneRequest {
                name: name.clone(),
                zone_type: "privileged".into(),
                policy_toml: isolated_policy_toml(),
            })
            .await
            .expect("creating privileged zone must succeed");

        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let get_resp = get_zone(&mut client, &name).await;
        let zone = get_resp.zone.unwrap();
        assert_eq!(
            zone.zone_type, "Privileged",
            "GetZone must reflect privileged zone type, got: {}",
            zone.zone_type
        );

        delete_zone_checked(&mut client, &name).await;
    }

    /// Image inspect digest is stable — two inspects return the same digest.
    #[tokio::test]
    async fn case_045_inspect_digest_is_stable() {
        let mut client = image_client().await;
        ensure_alpine(&mut client).await;

        let inspect1 = client
            .inspect(pb::image::InspectImageRequest { reference: "alpine:latest".into() })
            .await.expect("Inspect 1 must succeed").into_inner();

        let inspect2 = client
            .inspect(pb::image::InspectImageRequest { reference: "alpine:latest".into() })
            .await.expect("Inspect 2 must succeed").into_inner();

        assert_eq!(inspect1.digest, inspect2.digest, "digest must be stable across inspects");
        assert_eq!(inspect1.layers, inspect2.layers, "layers must be stable across inspects");
        assert_eq!(inspect1.size, inspect2.size, "size must be stable across inspects");
    }

    /// Policy round-trip preserves resource values exactly.
    #[tokio::test]
    async fn case_046_policy_resource_roundtrip() {
        let mut client = zone_client().await;
        let name = unique_zone_name("046");

        let policy = r#"
[zone]
name = "oracle"
type = "non-global"

[resources]
memory_limit = "1Gi"
cpu_shares = 2048
pids_max = 512
"#;
        create_zone(&mut client, &name, policy).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let resp = client
            .get_policy(pb::zone::GetPolicyRequest { zone_name: name.clone() })
            .await.expect("GetPolicy must succeed").into_inner();

        // Memory limit should be 1Gi = 1073741824 bytes.
        let stats = client
            .zone_stats(pb::zone::ZoneStatsRequest { zone_name: name.clone() })
            .await.expect("ZoneStats must succeed").into_inner();

        assert_eq!(
            stats.memory_limit_bytes,
            1024 * 1024 * 1024,
            "1Gi must be 1073741824 bytes, got: {}",
            stats.memory_limit_bytes
        );

        // Policy TOML must preserve the values.
        assert!(resp.policy_toml.contains("2048"), "cpu_shares=2048 must round-trip");
        assert!(resp.policy_toml.contains("512"), "pids_max=512 must round-trip");

        delete_zone_checked(&mut client, &name).await;
    }

    /// Container list for a zone with no containers returns empty, not error.
    #[tokio::test]
    async fn case_047_empty_zone_lists_no_containers() {
        let mut zone_cl = zone_client().await;
        let mut ctr_cl = container_client().await;
        let zone_name = unique_zone_name("047");

        create_zone(&mut zone_cl, &zone_name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let containers = ctr_cl
            .list_containers(pb::container::ListContainersRequest {
                zone_name: zone_name.clone(),
            })
            .await
            .expect("ListContainers on empty zone must succeed")
            .into_inner()
            .containers;

        assert!(
            containers.is_empty(),
            "zone with no containers must return empty list, got {} containers",
            containers.len()
        );

        delete_zone_checked(&mut zone_cl, &zone_name).await;
    }

    /// Backslash in zone name must be rejected (Windows path separator).
    #[tokio::test]
    async fn case_048_backslash_name_rejected() {
        let mut client = zone_client().await;

        let result = client
            .create_zone(pb::zone::CreateZoneRequest {
                name: "bad\\name".into(),
                zone_type: "non-global".into(),
                policy_toml: isolated_policy_toml(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::InvalidArgument, "backslash in zone name");
    }

    /// ".." zone name must be rejected.
    #[tokio::test]
    async fn case_049_dotdot_name_rejected() {
        let mut client = zone_client().await;

        let result = client
            .create_zone(pb::zone::CreateZoneRequest {
                name: "..".into(),
                zone_type: "non-global".into(),
                policy_toml: isolated_policy_toml(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::InvalidArgument, "dotdot zone name");
    }
}

// ============================================================================
// STRESS & BOUNDARY CONDITIONS (050-054)
// ============================================================================

#[cfg(test)]
mod stress {
    use super::helpers::*;
    use super::pb;
    use tokio::time::{sleep, Duration};

    /// Create and delete 10 zones rapidly — list must be consistent at each step.
    #[tokio::test]
    async fn case_050_rapid_create_delete_cycle() {
        let mut client = zone_client().await;
        let prefix = unique_zone_name("050");

        for i in 0..10 {
            let name = format!("{prefix}-{i}");
            create_zone(&mut client, &name, &isolated_policy_toml()).await;
            sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

            // Zone must be in list.
            let zones = list_zones(&mut client).await;
            assert!(zones.iter().any(|z| z.name == name), "zone {name} must be in list after create");

            delete_zone_checked(&mut client, &name).await;
            sleep(Duration::from_millis(200)).await;

            // Zone must be gone.
            let zones = list_zones(&mut client).await;
            assert!(!zones.iter().any(|z| z.name == name), "zone {name} must be gone after delete");
        }
    }

    /// Zone name at exactly 128 chars (max boundary) is accepted.
    #[tokio::test]
    async fn case_051_name_at_max_boundary() {
        let mut client = zone_client().await;
        let name = "a".repeat(128);

        let result = client
            .create_zone(pb::zone::CreateZoneRequest {
                name: name.clone(),
                zone_type: "non-global".into(),
                policy_toml: isolated_policy_toml(),
            })
            .await;

        // 128 chars must be accepted (the limit is >128 rejected).
        result.expect("128-char zone name must be accepted");
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        delete_zone_checked(&mut client, &name).await;
    }

    /// Multiple containers in one zone — all listed, scoped correctly.
    #[tokio::test]
    async fn case_052_multiple_containers_in_zone() {
        let mut zone_cl = zone_client().await;
        let mut ctr_cl = container_client().await;
        let mut img_cl = image_client().await;
        let zone_name = unique_zone_name("052");

        ensure_alpine(&mut img_cl).await;
        create_zone(&mut zone_cl, &zone_name, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Create 3 containers.
        let mut ctr_ids = Vec::new();
        for i in 0..3 {
            let id = create_and_start_container(
                &mut ctr_cl,
                &zone_name,
                &format!("ctr-{i}"),
                vec!["/bin/sleep".into(), "60".into()],
            ).await;
            ctr_ids.push(id);
        }

        // List — all 3 must be present.
        let containers = ctr_cl
            .list_containers(pb::container::ListContainersRequest {
                zone_name: zone_name.clone(),
            })
            .await
            .expect("ListContainers must succeed")
            .into_inner()
            .containers;

        for (i, ctr_id) in ctr_ids.iter().enumerate() {
            assert!(
                containers.iter().any(|c| c.id == *ctr_id),
                "container {} (id={}) must be in zone listing",
                i, ctr_id
            );
        }

        assert!(
            containers.len() >= 3,
            "zone must have at least 3 containers, got {}",
            containers.len()
        );

        delete_zone_checked(&mut zone_cl, &zone_name).await;
    }

    /// Image pull progress stream must contain at least one message and end with done=true.
    #[tokio::test]
    async fn case_053_pull_progress_stream_contract() {
        let mut client = image_client().await;

        let mut stream = client
            .pull(pb::image::PullRequest {
                reference: "alpine:latest".into(),
            })
            .await
            .expect("Pull must succeed")
            .into_inner();

        let mut message_count = 0;
        let mut saw_done = false;

        while let Some(progress) = stream.message().await.expect("stream must not error mid-pull") {
            message_count += 1;
            assert!(!progress.status.is_empty(), "progress.status must not be empty");
            if progress.done {
                saw_done = true;
                break;
            }
        }

        assert!(message_count > 0, "pull must emit at least one progress message");
        assert!(saw_done, "pull stream must end with done=true");
    }

    /// Zone with unknown network mode in policy is rejected.
    #[tokio::test]
    async fn case_054_unknown_network_mode_rejected() {
        let mut client = zone_client().await;
        let name = unique_zone_name("054");

        let bad_policy = r#"
[zone]
name = "oracle"
type = "non-global"

[network]
mode = "quantum-entangled"
"#;
        let result = client
            .create_zone(pb::zone::CreateZoneRequest {
                name,
                zone_type: "non-global".into(),
                policy_toml: bad_policy.into(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::InvalidArgument, "unknown network mode");
    }
}
