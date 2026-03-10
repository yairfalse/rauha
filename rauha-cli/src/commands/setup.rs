//! `rauha setup` — prepare the macOS environment for Virtualization.framework.

use clap::Args;
use std::path::Path;

#[derive(Args)]
pub struct SetupArgs {
    /// Skip pf firewall configuration.
    #[arg(long)]
    skip_pf: bool,

    /// Path to a pre-built VM kernel (vmlinux). If not provided, downloads from release.
    #[arg(long)]
    kernel: Option<String>,

    /// Path to a pre-built initramfs. If not provided, uses default from target/vm-assets/.
    #[arg(long)]
    initramfs: Option<String>,
}

pub async fn handle(args: SetupArgs) -> anyhow::Result<()> {
    println!("Rauha macOS setup");
    println!("=================\n");

    // 1. Create directories.
    let vm_dir = Path::new("/var/lib/rauha/vm");
    let containers_dir = Path::new("/var/lib/rauha/containers");

    println!("[1/4] Creating directories...");
    for dir in [vm_dir, containers_dir] {
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
            println!("  Created {}", dir.display());
        } else {
            println!("  {} already exists", dir.display());
        }
    }

    // 2. Install VM assets.
    println!("\n[2/4] Installing VM assets...");
    let kernel_dst = vm_dir.join("vmlinux");
    let initramfs_dst = vm_dir.join("initramfs.img");

    if let Some(ref kernel_path) = args.kernel {
        std::fs::copy(kernel_path, &kernel_dst)?;
        println!("  Copied kernel from {kernel_path}");
    } else if !kernel_dst.exists() {
        println!("  WARNING: No kernel at {}.", kernel_dst.display());
        println!("  Provide one with --kernel or build with `cargo xtask build-initramfs`");
    } else {
        println!("  Kernel already installed at {}", kernel_dst.display());
    }

    if let Some(ref initramfs_path) = args.initramfs {
        std::fs::copy(initramfs_path, &initramfs_dst)?;
        println!("  Copied initramfs from {initramfs_path}");
    } else if !initramfs_dst.exists() {
        // Try the default build output.
        let build_output = Path::new("target/vm-assets/initramfs.img");
        if build_output.exists() {
            std::fs::copy(build_output, &initramfs_dst)?;
            println!("  Installed initramfs from build output");
        } else {
            println!("  WARNING: No initramfs at {}.", initramfs_dst.display());
            println!("  Build with `cargo xtask build-initramfs` first");
        }
    } else {
        println!(
            "  Initramfs already installed at {}",
            initramfs_dst.display()
        );
    }

    // 3. Configure pf firewall.
    if !args.skip_pf {
        println!("\n[3/4] Configuring pf firewall...");
        configure_pf()?;
    } else {
        println!("\n[3/4] Skipping pf configuration (--skip-pf)");
    }

    // 4. Verify entitlements.
    println!("\n[4/4] Checking Virtualization.framework entitlements...");
    check_entitlements();

    println!("\nSetup complete!");
    println!("\nNext steps:");
    if !kernel_dst.exists() || !initramfs_dst.exists() {
        println!("  1. Build VM assets: cargo xtask build-initramfs");
        println!("  2. Run setup again: sudo rauha setup");
    }
    println!("  - Start the daemon: sudo rauhad");
    println!("  - Create a zone:    rauha zone create --name myzone");

    Ok(())
}

fn configure_pf() -> anyhow::Result<()> {
    let anchor_dir = Path::new("/etc/pf.anchors");
    let anchor_file = anchor_dir.join("com.rauha");
    let anchor_content = "anchor \"com.rauha/*\"\n";

    if !anchor_dir.exists() {
        std::fs::create_dir_all(anchor_dir)?;
    }

    if anchor_file.exists() {
        let existing = std::fs::read_to_string(&anchor_file)?;
        if existing.contains("com.rauha/*") {
            println!("  Root anchor already configured");
            return Ok(());
        }
    }

    std::fs::write(&anchor_file, anchor_content)?;
    println!("  Created root anchor at {}", anchor_file.display());

    // Check if pf.conf references our anchor.
    let pf_conf = Path::new("/etc/pf.conf");
    if pf_conf.exists() {
        let content = std::fs::read_to_string(pf_conf)?;
        if !content.contains("com.rauha") {
            println!("  NOTE: Add this line to /etc/pf.conf:");
            println!("    anchor \"com.rauha\"");
            println!("    load anchor \"com.rauha\" from \"/etc/pf.anchors/com.rauha\"");
            println!("  Then reload: sudo pfctl -f /etc/pf.conf");
        } else {
            println!("  pf.conf already references com.rauha anchor");
        }
    }

    Ok(())
}

fn check_entitlements() {
    #[cfg(target_os = "macos")]
    {
        // Check if the current binary has the virtualization entitlement.
        let current_exe = std::env::current_exe().ok();
        if let Some(exe) = current_exe {
            let output = std::process::Command::new("codesign")
                .args(["-d", "--entitlements", "-", &exe.to_string_lossy()])
                .output();

            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    if stdout.contains("com.apple.security.virtualization")
                        || stderr.contains("com.apple.security.virtualization")
                    {
                        println!("  Virtualization entitlement: present");
                    } else {
                        println!("  WARNING: Virtualization entitlement not found.");
                        println!("  The rauhad binary must be signed with:");
                        println!("    com.apple.security.virtualization = true");
                        println!("  Create an entitlements.plist and sign with:");
                        println!("    codesign --entitlements entitlements.plist -s - target/debug/rauhad");
                    }
                }
                Err(_) => {
                    println!("  Could not check entitlements (codesign not available)");
                }
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        println!("  Skipped (not on macOS)");
    }
}
