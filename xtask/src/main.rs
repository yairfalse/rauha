use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
enum Cli {
    /// Build the eBPF programs for rauha-ebpf.
    BuildEbpf {
        /// Build in release mode.
        #[clap(long)]
        release: bool,
    },
    /// Cross-compile the guest agent for Linux (used inside macOS VMs).
    BuildGuestAgent {
        /// Build in release mode.
        #[clap(long)]
        release: bool,
        /// Target triple (default: aarch64-unknown-linux-musl).
        #[clap(long, default_value = "aarch64-unknown-linux-musl")]
        target: String,
    },
    /// Build a minimal initramfs containing the guest agent.
    BuildInitramfs {
        /// Build guest agent in release mode.
        #[clap(long)]
        release: bool,
        /// Target triple for the guest agent.
        #[clap(long, default_value = "aarch64-unknown-linux-musl")]
        target: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
        Cli::BuildGuestAgent { release, target } => build_guest_agent(release, &target),
        Cli::BuildInitramfs { release, target } => build_initramfs(release, &target),
    }
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is in project root")
        .to_path_buf()
}

fn build_ebpf(release: bool) -> Result<()> {
    let root = project_root();
    let ebpf_dir = root.join("rauha-ebpf");

    if !ebpf_dir.exists() {
        bail!(
            "rauha-ebpf directory not found at {}. Create it first.",
            ebpf_dir.display()
        );
    }

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args([
            "+nightly",
            "build",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to run cargo build for eBPF")?;
    if !status.success() {
        bail!("eBPF build failed");
    }

    let profile = if release { "release" } else { "debug" };
    let artifact = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("rauha-ebpf");

    println!("eBPF object built: {}", artifact.display());
    Ok(())
}

fn build_guest_agent(release: bool, target: &str) -> Result<()> {
    let root = project_root();

    println!("Building rauha-guest-agent for {target}...");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root).args([
        "build",
        "--package",
        "rauha-guest-agent",
        "--target",
        target,
    ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .context("failed to run cargo build for guest agent")?;
    if !status.success() {
        bail!("guest agent build failed");
    }

    let profile = if release { "release" } else { "debug" };
    let artifact = root
        .join("target")
        .join(target)
        .join(profile)
        .join("rauha-guest-agent");

    println!("Guest agent built: {}", artifact.display());
    Ok(())
}

fn build_initramfs(release: bool, target: &str) -> Result<()> {
    // First build the guest agent.
    build_guest_agent(release, target)?;

    let root = project_root();
    let profile = if release { "release" } else { "debug" };
    let agent_binary = root
        .join("target")
        .join(target)
        .join(profile)
        .join("rauha-guest-agent");

    if !agent_binary.exists() {
        bail!(
            "Guest agent binary not found at {}",
            agent_binary.display()
        );
    }

    let vm_dir = root.join("target").join("vm-assets");
    let initramfs_root = vm_dir.join("initramfs");

    // Create initramfs directory structure.
    std::fs::create_dir_all(initramfs_root.join("bin"))?;
    std::fs::create_dir_all(initramfs_root.join("usr/bin"))?;
    std::fs::create_dir_all(initramfs_root.join("proc"))?;
    std::fs::create_dir_all(initramfs_root.join("sys"))?;
    std::fs::create_dir_all(initramfs_root.join("dev"))?;
    std::fs::create_dir_all(initramfs_root.join("mnt/rauha"))?;
    std::fs::create_dir_all(initramfs_root.join("run"))?;
    std::fs::create_dir_all(initramfs_root.join("tmp"))?;

    // Copy guest agent binary.
    std::fs::copy(&agent_binary, initramfs_root.join("usr/bin/rauha-guest-agent"))?;

    // Create /init script.
    let init_script = r#"#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts

# Mount virtio-fs share from host.
mount -t virtiofs rauha /mnt/rauha 2>/dev/null || true

echo "rauha-guest-agent starting..."
/usr/bin/rauha-guest-agent
poweroff -f
"#;

    std::fs::write(initramfs_root.join("init"), init_script)?;

    // Make init executable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            initramfs_root.join("init"),
            std::fs::Permissions::from_mode(0o755),
        )?;
        std::fs::set_permissions(
            initramfs_root.join("usr/bin/rauha-guest-agent"),
            std::fs::Permissions::from_mode(0o755),
        )?;
    }

    // Build cpio archive (initramfs).
    let initramfs_path = vm_dir.join("initramfs.img");
    let status = Command::new("sh")
        .current_dir(&initramfs_root)
        .args([
            "-c",
            &format!(
                "find . | cpio -o -H newc 2>/dev/null | gzip > {}",
                initramfs_path.display()
            ),
        ])
        .status()
        .context("failed to create initramfs cpio archive")?;

    if !status.success() {
        bail!("initramfs creation failed");
    }

    println!("Initramfs built: {}", initramfs_path.display());
    println!(
        "Size: {} bytes",
        std::fs::metadata(&initramfs_path)?.len()
    );
    Ok(())
}
