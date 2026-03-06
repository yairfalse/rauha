//! Network setup for zone isolation: veth pairs and bridge.
//!
//! Each zone gets a veth pair:
//! - host side: `veth-{zone}` attached to the rauha0 bridge
//! - zone side: `eth0` inside the zone's network namespace
//!
//! The rauha0 bridge connects all zone veth host-side interfaces,
//! with eBPF-enforced policy controlling which zones can communicate.

use std::process::Command;

use rauha_common::error::{RauhaError, Result};

const BRIDGE_NAME: &str = "rauha0";

/// Ensure the rauha0 bridge exists.
pub fn ensure_bridge() -> Result<()> {
    // Check if bridge already exists.
    let output = Command::new("ip")
        .args(["link", "show", BRIDGE_NAME])
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to check bridge: {e}"),
            hint: "ensure iproute2 is installed".into(),
        })?;

    if output.status.success() {
        return Ok(()); // Already exists.
    }

    // Create the bridge.
    run_ip(&["link", "add", "name", BRIDGE_NAME, "type", "bridge"])?;
    run_ip(&["link", "set", BRIDGE_NAME, "up"])?;

    tracing::info!(bridge = BRIDGE_NAME, "created network bridge");
    Ok(())
}

/// Create a veth pair for a zone and attach to bridge + namespace.
///
/// Creates:
/// - `veth-{zone}` on the host, attached to rauha0 bridge
/// - `eth0` inside the zone's network namespace
pub fn create_veth_pair(zone_name: &str) -> Result<()> {
    let host_if = veth_host_name(zone_name);
    let zone_if = "eth0";
    let ns_name = format!("rauha-{zone_name}");

    // Create the veth pair.
    run_ip(&[
        "link", "add", &host_if, "type", "veth", "peer", "name", zone_if,
    ])?;

    // Move zone-side interface into the namespace.
    run_ip(&["link", "set", zone_if, "netns", &ns_name])?;

    // Attach host-side to the bridge.
    run_ip(&["link", "set", &host_if, "master", BRIDGE_NAME])?;
    run_ip(&["link", "set", &host_if, "up"])?;

    // Bring up the zone-side interface.
    run_ip_netns(&ns_name, &["link", "set", zone_if, "up"])?;
    run_ip_netns(&ns_name, &["link", "set", "lo", "up"])?;

    tracing::info!(
        zone = zone_name,
        host_if = host_if,
        "created veth pair"
    );
    Ok(())
}

/// Destroy a zone's veth pair. Deleting the host side automatically
/// removes the zone side too.
pub fn destroy_veth_pair(zone_name: &str) -> Result<()> {
    let host_if = veth_host_name(zone_name);

    // Check if interface exists.
    let output = Command::new("ip")
        .args(["link", "show", &host_if])
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to check veth: {e}"),
            hint: "ensure iproute2 is installed".into(),
        })?;

    if !output.status.success() {
        return Ok(()); // Already gone.
    }

    run_ip(&["link", "delete", &host_if])?;

    tracing::info!(zone = zone_name, "destroyed veth pair");
    Ok(())
}

/// Destroy the rauha0 bridge (called on daemon shutdown).
pub fn destroy_bridge() -> Result<()> {
    let output = Command::new("ip")
        .args(["link", "show", BRIDGE_NAME])
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to check bridge: {e}"),
            hint: "ensure iproute2 is installed".into(),
        })?;

    if !output.status.success() {
        return Ok(()); // Already gone.
    }

    run_ip(&["link", "set", BRIDGE_NAME, "down"])?;
    run_ip(&["link", "delete", BRIDGE_NAME, "type", "bridge"])?;

    tracing::info!(bridge = BRIDGE_NAME, "destroyed network bridge");
    Ok(())
}

fn veth_host_name(zone_name: &str) -> String {
    // Truncate to fit Linux's 15-char interface name limit.
    let suffix = if zone_name.len() > 10 {
        &zone_name[..10]
    } else {
        zone_name
    };
    format!("veth-{suffix}")
}

fn run_ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to run `ip {}`: {e}", args.join(" ")),
            hint: "ensure iproute2 is installed and rauhad runs as root".into(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RauhaError::NetworkError {
            message: format!("ip {} failed: {stderr}", args.join(" ")),
            hint: "run rauhad as root".into(),
        });
    }

    Ok(())
}

fn run_ip_netns(ns_name: &str, args: &[&str]) -> Result<()> {
    let mut cmd_args = vec!["netns", "exec", ns_name, "ip"];
    cmd_args.extend_from_slice(args);

    let output = Command::new("ip")
        .args(&cmd_args)
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to run `ip netns exec {ns_name} ip {}`: {e}", args.join(" ")),
            hint: "ensure iproute2 is installed".into(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RauhaError::NetworkError {
            message: format!("ip netns exec {ns_name} ip {} failed: {stderr}", args.join(" ")),
            hint: "check namespace exists".into(),
        });
    }

    Ok(())
}
