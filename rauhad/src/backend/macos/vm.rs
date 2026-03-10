//! Virtualization.framework VM lifecycle manager.
//!
//! Each zone gets one lightweight Linux VM. The VM runs a minimal kernel
//! + initramfs containing rauha-guest-agent. Communication happens over
//! virtio-vsock, and the container rootfs is shared via virtio-fs.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

#[cfg(target_os = "macos")]
use objc2::AnyThread;

use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::ZonePolicy;

/// Default vsock port the guest agent listens on.
pub const GUEST_AGENT_VSOCK_PORT: u32 = 5123;

/// Default VM assets directory.
const VM_ASSETS_DIR: &str = "/var/lib/rauha/vm";

/// Configuration for a zone VM.
pub struct VmConfig {
    pub cpus: u32,
    pub memory_bytes: u64,
    pub shared_dir: PathBuf,
}

impl VmConfig {
    pub fn from_policy(policy: &ZonePolicy, shared_dir: PathBuf) -> Self {
        let cpus = match policy.resources.cpu_shares {
            0..=1024 => 1,
            1025..=2048 => 2,
            _ => 4,
        };
        Self {
            cpus,
            memory_bytes: policy.resources.memory_limit,
            shared_dir,
        }
    }
}

/// Wrapper to make VZVirtualMachine Send + Sync.
///
/// Safety: all access is guarded by the VmManager's Mutex. The only method
/// we call across threads is `socketDevices` + `connectToPort:completionHandler:`,
/// which Virtualization.framework documents as dispatching internally.
#[cfg(target_os = "macos")]
struct SendableVm(objc2::rc::Retained<objc2_virtualization::VZVirtualMachine>);

#[cfg(target_os = "macos")]
unsafe impl Send for SendableVm {}
#[cfg(target_os = "macos")]
unsafe impl Sync for SendableVm {}

struct VmEntry {
    vsock_port: u32,
    #[cfg(target_os = "macos")]
    vm: SendableVm,
}

/// Manages the lifecycle of one VM per zone.
pub struct VmManager {
    vms: Mutex<HashMap<String, VmEntry>>,
    kernel_path: PathBuf,
    initramfs_path: PathBuf,
}

impl VmManager {
    pub fn new() -> Self {
        let assets_dir = PathBuf::from(VM_ASSETS_DIR);
        Self {
            vms: Mutex::new(HashMap::new()),
            kernel_path: assets_dir.join("vmlinux"),
            initramfs_path: assets_dir.join("initramfs.img"),
        }
    }

    /// Check that VM assets (kernel + initramfs) exist.
    pub fn verify_assets(&self) -> Result<()> {
        if !self.kernel_path.exists() {
            return Err(RauhaError::BackendError(format!(
                "VM kernel not found at {}. Run `rauha setup` first.",
                self.kernel_path.display()
            )));
        }
        if !self.initramfs_path.exists() {
            return Err(RauhaError::BackendError(format!(
                "VM initramfs not found at {}. Run `rauha setup` first.",
                self.initramfs_path.display()
            )));
        }
        Ok(())
    }

    /// Boot a VM for the given zone.
    #[cfg(target_os = "macos")]
    pub fn boot_vm(&self, zone_name: &str, config: &VmConfig) -> Result<()> {
        use objc2_foundation::{NSArray, NSString, NSURL};
        use objc2_virtualization::*;

        self.verify_assets()?;

        {
            let vms = self.vms.lock().unwrap();
            if vms.contains_key(zone_name) {
                return Err(RauhaError::BackendError(format!(
                    "VM already running for zone {zone_name}"
                )));
            }
        }

        let kernel_url =
            NSURL::fileURLWithPath(&NSString::from_str(&self.kernel_path.to_string_lossy()));
        let boot_loader = unsafe {
            let loader = VZLinuxBootLoader::initWithKernelURL(
                VZLinuxBootLoader::alloc(),
                &kernel_url,
            );
            let initramfs_url = NSURL::fileURLWithPath(&NSString::from_str(
                &self.initramfs_path.to_string_lossy(),
            ));
            loader.setInitialRamdiskURL(Some(&initramfs_url));
            loader.setCommandLine(&NSString::from_str("console=hvc0 quiet"));
            loader
        };

        let vm_config_obj = unsafe {
            let cfg = VZVirtualMachineConfiguration::new();
            cfg.setBootLoader(Some(&boot_loader));
            cfg.setCPUCount(config.cpus as usize);
            cfg.setMemorySize(config.memory_bytes);

            let vsock_config = VZVirtioSocketDeviceConfiguration::new();
            cfg.setSocketDevices(&NSArray::from_retained_slice(&[
                objc2::rc::Retained::cast_unchecked(vsock_config),
            ]));

            let shared_dir = VZSharedDirectory::initWithURL_readOnly(
                VZSharedDirectory::alloc(),
                &NSURL::fileURLWithPath(&NSString::from_str(
                    &config.shared_dir.to_string_lossy(),
                )),
                false,
            );
            let single_dir_share = VZSingleDirectoryShare::initWithDirectory(
                VZSingleDirectoryShare::alloc(),
                &shared_dir,
            );
            let fs_config = VZVirtioFileSystemDeviceConfiguration::initWithTag(
                VZVirtioFileSystemDeviceConfiguration::alloc(),
                &NSString::from_str("rauha"),
            );
            fs_config.setShare(Some(&single_dir_share));
            cfg.setDirectorySharingDevices(&NSArray::from_retained_slice(&[
                objc2::rc::Retained::cast_unchecked(fs_config),
            ]));

            let net_config = VZVirtioNetworkDeviceConfiguration::new();
            let nat_attachment = VZNATNetworkDeviceAttachment::new();
            net_config.setAttachment(Some(&nat_attachment));
            cfg.setNetworkDevices(&NSArray::from_retained_slice(&[
                objc2::rc::Retained::cast_unchecked(net_config),
            ]));

            cfg
        };

        unsafe {
            if let Err(e) = vm_config_obj.validateWithError() {
                return Err(RauhaError::BackendError(format!(
                    "VM configuration invalid: {e}"
                )));
            }
        }

        let zone = zone_name.to_string();
        let vm = unsafe {
            let vm = VZVirtualMachine::initWithConfiguration(
                VZVirtualMachine::alloc(),
                &vm_config_obj,
            );
            vm.startWithCompletionHandler(&block2::RcBlock::new(
                move |err: *mut objc2_foundation::NSError| {
                    if !err.is_null() {
                        let e = &*err;
                        tracing::error!(error = %e, zone = %zone, "VM start failed");
                    }
                },
            ));
            vm
        };

        let mut vms = self.vms.lock().unwrap();
        vms.insert(
            zone_name.to_string(),
            VmEntry {
                vsock_port: GUEST_AGENT_VSOCK_PORT,
                vm: SendableVm(vm),
            },
        );

        tracing::info!(
            zone = zone_name,
            cpus = config.cpus,
            memory_mb = config.memory_bytes / (1024 * 1024),
            "VM booted"
        );
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    pub fn boot_vm(&self, zone_name: &str, _config: &VmConfig) -> Result<()> {
        let mut vms = self.vms.lock().unwrap();
        vms.insert(
            zone_name.to_string(),
            VmEntry {
                vsock_port: GUEST_AGENT_VSOCK_PORT,
            },
        );
        tracing::warn!(zone = zone_name, "VM boot stub (not on macOS)");
        Ok(())
    }

    /// Connect to the guest agent's vsock port inside a zone's VM.
    ///
    /// Returns a pair of owned file descriptors (read_fd, write_fd) extracted
    /// from the VZVirtioSocketConnection. These are plain fds — Send and usable
    /// from any thread.
    #[cfg(target_os = "macos")]
    pub fn connect_vsock(
        &self,
        zone_name: &str,
    ) -> Result<std::os::fd::OwnedFd> {
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::sync::{Arc, Condvar};

        let vms = self.vms.lock().unwrap();
        let entry = vms.get(zone_name).ok_or_else(|| {
            RauhaError::BackendError(format!("VM not running for zone {zone_name}"))
        })?;

        let port = entry.vsock_port;
        let vm = &entry.vm.0;

        // Get the first socket device from the VM.
        let socket_devices = unsafe { vm.socketDevices() };
        if socket_devices.count() == 0 {
            return Err(RauhaError::BackendError(format!(
                "VM for zone {zone_name} has no socket devices"
            )));
        }
        // socketDevices returns VZSocketDevice; downcast to VZVirtioSocketDevice.
        let base_device = socket_devices.objectAtIndex(0);
        let socket_device: &objc2_virtualization::VZVirtioSocketDevice =
            unsafe { &*(&*base_device as *const _ as *const _) };

        // connectToPort_completionHandler is async — we use a condvar to wait.
        let result: Arc<Mutex<Option<std::result::Result<i32, String>>>> =
            Arc::new(Mutex::new(None));
        let cond = Arc::new(Condvar::new());

        let result_clone = Arc::clone(&result);
        let cond_clone = Arc::clone(&cond);

        unsafe {
            socket_device.connectToPort_completionHandler(
                port,
                &block2::RcBlock::new(
                    move |conn: *mut objc2_virtualization::VZVirtioSocketConnection,
                          err: *mut objc2_foundation::NSError| {
                        let res = if !err.is_null() {
                            let e = &*err;
                            Err(format!("vsock connect failed: {e}"))
                        } else if conn.is_null() {
                            Err("vsock connect returned null connection".into())
                        } else {
                            let connection = &*conn;
                            let fd = connection.fileDescriptor();
                            // Dup the fd so we own it independently of the ObjC object.
                            let duped = libc::dup(fd);
                            if duped < 0 {
                                Err(format!(
                                    "dup failed: {}",
                                    std::io::Error::last_os_error()
                                ))
                            } else {
                                Ok(duped)
                            }
                        };
                        let mut guard = result_clone.lock().unwrap();
                        *guard = Some(res);
                        cond_clone.notify_one();
                    },
                ),
            );
        }

        // Wait for the callback (with timeout).
        let guard = result.lock().unwrap();
        let (guard, timeout) = cond
            .wait_timeout_while(guard, std::time::Duration::from_secs(10), |r| r.is_none())
            .unwrap();

        if timeout.timed_out() {
            return Err(RauhaError::BackendError(format!(
                "vsock connect to zone {zone_name} timed out"
            )));
        }

        match guard.as_ref().unwrap() {
            Ok(fd) => {
                let owned = unsafe { OwnedFd::from_raw_fd(*fd) };
                Ok(owned)
            }
            Err(e) => Err(RauhaError::BackendError(e.clone())),
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn connect_vsock(
        &self,
        zone_name: &str,
    ) -> Result<std::os::fd::OwnedFd> {
        Err(RauhaError::BackendError(format!(
            "vsock not available on this platform (zone: {zone_name})"
        )))
    }

    /// Shut down a zone's VM.
    #[cfg(target_os = "macos")]
    pub fn shutdown_vm(&self, zone_name: &str) -> Result<()> {
        use objc2_virtualization::VZVirtualMachineState;

        let mut vms = self.vms.lock().unwrap();
        if let Some(entry) = vms.remove(zone_name) {
            let vm = &entry.vm.0;
            unsafe {
                if vm.canRequestStop() {
                    let _ = vm.requestStopWithError();
                }
            }
            // Brief wait, then force stop if still running.
            std::thread::sleep(std::time::Duration::from_secs(2));
            unsafe {
                if vm.state() != VZVirtualMachineState::Stopped {
                    vm.stopWithCompletionHandler(&block2::RcBlock::new(|_err| {}));
                }
            }
            tracing::info!(zone = zone_name, "VM shut down");
        }
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    pub fn shutdown_vm(&self, zone_name: &str) -> Result<()> {
        let mut vms = self.vms.lock().unwrap();
        vms.remove(zone_name);
        tracing::warn!(zone = zone_name, "VM shutdown stub (not on macOS)");
        Ok(())
    }

    pub fn is_running(&self, zone_name: &str) -> bool {
        let vms = self.vms.lock().unwrap();
        vms.contains_key(zone_name)
    }

    pub fn vsock_port(&self, zone_name: &str) -> Option<u32> {
        let vms = self.vms.lock().unwrap();
        vms.get(zone_name).map(|h| h.vsock_port)
    }

    pub fn running_zones(&self) -> Vec<String> {
        let vms = self.vms.lock().unwrap();
        vms.keys().cloned().collect()
    }

    pub fn assets_dir() -> PathBuf {
        PathBuf::from(VM_ASSETS_DIR)
    }
}
