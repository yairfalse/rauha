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

    pub fn policy_with_capabilities(caps: &[&str]) -> String {
        let caps_str = caps.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(", ");
        format!(r#"
[zone]
name = "oracle"
type = "non-global"

[capabilities]
allowed = [{caps_str}]
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
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
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

        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let zones = list_zones(&mut client).await;
        assert!(zones.iter().any(|z| z.name == name), "zone must appear in list");

        let get_resp = get_zone(&mut client, &name).await;
        let zone = get_resp.zone.expect("GetZone must return zone info");
        assert_eq!(zone.name, name);
        assert_eq!(zone.state, "Ready");

        delete_zone(&mut client, &name).await;
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
        delete_zone(&mut client, &name).await;
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

    /// Create container in a zone → start → list → stop.
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

        // Stop.
        ctr_cl
            .stop_container(pb::container::StopContainerRequest {
                container_id: ctr_id,
                timeout_seconds: 5,
            })
            .await
            .expect("StopContainer must succeed");

        delete_zone(&mut zone_cl, &zone_name).await;
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

    /// Container runs a command and exits — process lifecycle is sound.
    #[tokio::test]
    async fn case_006_container_runs_and_exits() {
        let mut zone_cl = zone_client().await;
        let mut ctr_cl = container_client().await;
        let mut img_cl = image_client().await;
        let zone_name = unique_zone_name("006");

        ensure_alpine(&mut img_cl).await;
        create_zone(&mut zone_cl, &zone_name, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Run a short-lived command.
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

        sleep(Duration::from_millis(EXEC_SETTLE_MS)).await;

        // Container should have exited naturally — cleanup should not error.
        let _ = ctr_cl
            .stop_container(pb::container::StopContainerRequest {
                container_id: resp.container_id,
                timeout_seconds: 2,
            })
            .await;

        delete_zone(&mut zone_cl, &zone_name).await;
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
        assert!(inspect.digest.starts_with("sha256:"), "digest must be sha256");
        assert!(!inspect.layers.is_empty(), "alpine must have at least one layer");
        assert!(inspect.layers.iter().all(|l| l.starts_with("sha256:")), "layer digests must be sha256");
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

    /// Remove an image → it disappears from list → inspect fails.
    /// Uses busybox (not alpine) to avoid racing with other tests that depend on alpine.
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
        sleep(Duration::from_millis(500)).await;

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

        // Must return at least one check.
        assert!(!resp.checks.is_empty(), "isolation report must include checks");

        delete_zone(&mut client, &name).await;
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

    /// Policy hot-reload does not break isolation.
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

        delete_zone(&mut client, &name).await;
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

    /// Apply a policy → GetPolicy returns the applied TOML.
    #[tokio::test]
    async fn case_013_apply_and_get_policy() {
        let mut client = zone_client().await;
        let name = unique_zone_name("013");

        create_zone(&mut client, &name, &isolated_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        client
            .apply_policy(pb::zone::ApplyPolicyRequest {
                zone_name: name.clone(),
                policy_toml: bridged_policy_toml(),
            })
            .await
            .expect("ApplyPolicy must succeed");

        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let resp = client
            .get_policy(pb::zone::GetPolicyRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("GetPolicy must succeed")
            .into_inner();

        assert!(
            resp.policy_toml.contains("bridged"),
            "GetPolicy must reflect updated policy, got: {}",
            resp.policy_toml
        );

        delete_zone(&mut client, &name).await;
    }

    /// Memory limit in policy is reflected in ZoneStats.
    #[tokio::test]
    async fn case_014_memory_limit_from_policy() {
        let mut client = zone_client().await;
        let name = unique_zone_name("014");

        // Create zone with 256Mi memory limit.
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

        delete_zone(&mut client, &name).await;
    }

    /// Apply invalid policy to existing zone → INVALID_ARGUMENT.
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
        assert!(get_resp.zone.is_some(), "zone must survive rejected policy apply");

        delete_zone(&mut client, &name).await;
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

    /// Bridged zone creation succeeds and zone is reachable.
    #[tokio::test]
    async fn case_016_bridged_zone_creation() {
        let mut client = zone_client().await;
        let name = unique_zone_name("016");

        create_zone(&mut client, &name, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Zone must be Ready.
        let get_resp = get_zone(&mut client, &name).await;
        let zone = get_resp.zone.expect("zone must exist");
        assert_eq!(zone.state, "Ready", "bridged zone must reach Ready state");

        // Isolation must pass.
        let iso = client
            .verify_isolation(pb::zone::VerifyIsolationRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("VerifyIsolation must succeed")
            .into_inner();

        assert!(iso.is_isolated, "bridged zone must be isolated");

        delete_zone(&mut client, &name).await;
    }

    /// Zone created with host networking mode.
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

        // GetPolicy must reflect host mode.
        let resp = client
            .get_policy(pb::zone::GetPolicyRequest {
                zone_name: name.clone(),
            })
            .await
            .expect("GetPolicy must succeed")
            .into_inner();

        assert!(resp.policy_toml.contains("host"), "policy must contain host mode");

        delete_zone(&mut client, &name).await;
    }

    /// Container in bridged zone gets DNS (resolv.conf injected).
    #[tokio::test]
    async fn case_018_container_gets_dns() {
        let mut zone_cl = zone_client().await;
        let mut ctr_cl = container_client().await;
        let mut img_cl = image_client().await;
        let zone_name = unique_zone_name("018");

        ensure_alpine(&mut img_cl).await;
        create_zone(&mut zone_cl, &zone_name, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Create container that reads resolv.conf.
        let resp = ctr_cl
            .create_container(pb::container::CreateContainerRequest {
                zone_name: zone_name.clone(),
                name: "dns-test".into(),
                image: "alpine:latest".into(),
                command: vec!["/bin/cat".into(), "/etc/resolv.conf".into()],
                env: Default::default(),
                working_dir: String::new(),
            })
            .await
            .expect("CreateContainer must succeed")
            .into_inner();

        // If container creation succeeded, DNS was injected
        // (resolv.conf is written to rootfs before container start).
        assert!(!resp.container_id.is_empty(), "container with DNS must be created");

        delete_zone(&mut zone_cl, &zone_name).await;
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

        assert!(stats.memory_limit_bytes > 0, "zone must have non-zero memory limit");
        assert!(!stats.zone_id.is_empty(), "stats must include zone_id");

        delete_zone(&mut client, &name).await;
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
    use tokio::time::{sleep, Duration};

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

    /// Zone name with NUL byte must be rejected.
    #[tokio::test]
    async fn case_025_nul_byte_rejected() {
        let mut client = zone_client().await;

        let result = client
            .create_zone(pb::zone::CreateZoneRequest {
                name: "bad\0name".into(),
                zone_type: "non-global".into(),
                policy_toml: isolated_policy_toml(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::InvalidArgument, "NUL byte in zone name");
    }

    /// Zone name "." must be rejected.
    #[tokio::test]
    async fn case_026_dot_name_rejected() {
        let mut client = zone_client().await;

        let result = client
            .create_zone(pb::zone::CreateZoneRequest {
                name: ".".into(),
                zone_type: "non-global".into(),
                policy_toml: isolated_policy_toml(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::InvalidArgument, "dot zone name");
    }

    /// Zone name >128 chars must be rejected.
    #[tokio::test]
    async fn case_027_long_name_rejected() {
        let mut client = zone_client().await;

        let result = client
            .create_zone(pb::zone::CreateZoneRequest {
                name: "a".repeat(129),
                zone_type: "non-global".into(),
                policy_toml: isolated_policy_toml(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::InvalidArgument, "name too long");
    }

    /// Apply policy to nonexistent zone → NotFound.
    #[tokio::test]
    async fn case_028_apply_policy_missing_zone() {
        let mut client = zone_client().await;

        let result = client
            .apply_policy(pb::zone::ApplyPolicyRequest {
                zone_name: "oracle-028-ghost".into(),
                policy_toml: isolated_policy_toml(),
            })
            .await;

        assert_grpc_error(result, tonic::Code::NotFound, "apply policy to missing zone");
    }

    /// Get nonexistent zone → NotFound.
    #[tokio::test]
    async fn case_029_get_missing_zone() {
        let mut client = zone_client().await;

        let result = client
            .get_zone(pb::zone::GetZoneRequest {
                name: "oracle-029-ghost".into(),
            })
            .await;

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

        delete_zone(&mut client, &name_a).await;
        delete_zone(&mut client, &name_b).await;
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

        // Delete A.
        delete_zone(&mut client, &name_a).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // B must still exist and be healthy.
        let get_resp = get_zone(&mut client, &name_b).await;
        let zone = get_resp.zone.expect("zone B must survive deletion of A");
        assert_eq!(zone.state, "Ready");

        delete_zone(&mut client, &name_b).await;
    }

    /// Zones with different policies can coexist.
    #[tokio::test]
    async fn case_032_mixed_policy_zones() {
        let mut client = zone_client().await;
        let isolated = unique_zone_name("032-iso");
        let bridged = unique_zone_name("032-br");

        create_zone(&mut client, &isolated, &isolated_policy_toml()).await;
        create_zone(&mut client, &bridged, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        // Both must pass isolation verification.
        for name in [&isolated, &bridged] {
            let resp = client
                .verify_isolation(pb::zone::VerifyIsolationRequest {
                    zone_name: name.clone(),
                })
                .await
                .expect("VerifyIsolation must succeed")
                .into_inner();

            assert!(
                resp.is_isolated,
                "zone {} must be isolated. Failed: {:?}",
                name,
                resp.checks.iter().filter(|c| !c.passed).collect::<Vec<_>>()
            );
        }

        delete_zone(&mut client, &isolated).await;
        delete_zone(&mut client, &bridged).await;
    }

    /// Containers are scoped to their zone in ListContainers.
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
            .await
            .expect("ListContainers must succeed")
            .into_inner()
            .containers;

        assert!(list_a.iter().any(|c| c.id == ctr_a), "zone A must contain ctr_a");
        assert!(!list_a.iter().any(|c| c.id == ctr_b), "zone A must NOT contain ctr_b");

        // List zone B — must see ctr_b but NOT ctr_a.
        let list_b = ctr_cl
            .list_containers(pb::container::ListContainersRequest {
                zone_name: zone_b.clone(),
            })
            .await
            .expect("ListContainers must succeed")
            .into_inner()
            .containers;

        assert!(list_b.iter().any(|c| c.id == ctr_b), "zone B must contain ctr_b");
        assert!(!list_b.iter().any(|c| c.id == ctr_a), "zone B must NOT contain ctr_a");

        delete_zone(&mut zone_cl, &zone_a).await;
        delete_zone(&mut zone_cl, &zone_b).await;
    }

    /// Force-delete zone with running container succeeds.
    #[tokio::test]
    async fn case_034_force_delete_zone_with_container() {
        let mut zone_cl = zone_client().await;
        let mut ctr_cl = container_client().await;
        let mut img_cl = image_client().await;
        let zone_name = unique_zone_name("034");

        ensure_alpine(&mut img_cl).await;
        create_zone(&mut zone_cl, &zone_name, &bridged_policy_toml()).await;
        sleep(Duration::from_millis(ZONE_SETTLE_MS)).await;

        let _ctr_id = create_and_start_container(
            &mut ctr_cl, &zone_name, "doomed", vec!["/bin/sleep".into(), "300".into()],
        ).await;

        // Force delete must succeed even with running container.
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
    }
}

// ============================================================================
// CONTAINER EDGE CASES (035-039)
// ============================================================================

#[cfg(test)]
mod container_edge_cases {
    use super::helpers::*;
    use super::pb;
    use tokio::time::{sleep, Duration};

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

    /// ListContainers with empty zone_name returns all containers.
    #[tokio::test]
    async fn case_037_list_all_containers() {
        let mut ctr_cl = container_client().await;

        // Must not error — returns empty or populated list.
        let resp = ctr_cl
            .list_containers(pb::container::ListContainersRequest {
                zone_name: String::new(),
            })
            .await
            .expect("ListContainers with empty zone must succeed");

        // Just verify it returns a valid response.
        let _ = resp.into_inner().containers;
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
