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

/// Wrapper to make DispatchQueue Send + Sync.
#[cfg(target_os = "macos")]
struct SendableQueue(dispatch2::DispatchRetained<dispatch2::DispatchQueue>);
#[cfg(target_os = "macos")]
unsafe impl Send for SendableQueue {}
#[cfg(target_os = "macos")]
unsafe impl Sync for SendableQueue {}

struct VmEntry {
    vsock_port: u32,
    #[cfg(target_os = "macos")]
    vm: SendableVm,
    /// The serial dispatch queue this VM is bound to. All VM operations
    /// (including vsock connect) must be dispatched to this queue.
    #[cfg(target_os = "macos")]
    queue: SendableQueue,
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
    ///
    /// Virtualization.framework requires that `VZVirtualMachine` is created
    /// and operated from the dispatch queue it's bound to. We create a
    /// serial dispatch queue per VM and use `exec_sync` to run the start
    /// call on that queue.
    #[cfg(target_os = "macos")]
    pub fn boot_vm(&self, zone_name: &str, config: &VmConfig) -> Result<()> {
        self.verify_assets()?;

        {
            let vms = self.vms.lock().unwrap();
            if vms.contains_key(zone_name) {
                return Err(RauhaError::BackendError(format!(
                    "VM already running for zone {zone_name}"
                )));
            }
        }

        // Wrap all ObjC calls in exception handling. Virtualization.framework
        // throws NSExceptions for invalid configurations instead of returning
        // NSError, which would abort the Rust process without this.
        self.boot_vm_inner(zone_name, config)
    }

    #[cfg(target_os = "macos")]
    fn boot_vm_inner(&self, zone_name: &str, config: &VmConfig) -> Result<()> {
        use std::sync::{Arc, Condvar};
        use objc2_foundation::{NSArray, NSString, NSURL};
        use objc2_virtualization::*;

        eprintln!("[vm] creating boot loader + VM configuration (cpus={}, mem={})", config.cpus, config.memory_bytes);

        // Capture paths as strings so the closure is UnwindSafe.
        let kernel_path_str = self.kernel_path.to_string_lossy().to_string();
        let initramfs_path_str = self.initramfs_path.to_string_lossy().to_string();
        let shared_dir_str = config.shared_dir.to_string_lossy().to_string();
        let shared_dir_clone = config.shared_dir.clone();
        let cpus = config.cpus;
        let memory_bytes = config.memory_bytes;

        // Catch ObjC exceptions from VZ configuration setup.
        // Virtualization.framework throws NSExceptions for invalid
        // configurations instead of returning NSError.
        let vm_config_result = unsafe {
            objc2::exception::catch(move || {
                let kernel_url =
                    NSURL::fileURLWithPath(&NSString::from_str(&kernel_path_str));
                let boot_loader = {
                    let loader = VZLinuxBootLoader::initWithKernelURL(
                        VZLinuxBootLoader::alloc(),
                        &kernel_url,
                    );
                    let initramfs_url = NSURL::fileURLWithPath(&NSString::from_str(
                        &initramfs_path_str,
                    ));
                    loader.setInitialRamdiskURL(Some(&initramfs_url));
                    loader.setCommandLine(&NSString::from_str("console=hvc0"));
                    loader
                };

                let cfg = VZVirtualMachineConfiguration::new();
                cfg.setBootLoader(Some(&boot_loader));
                cfg.setCPUCount(cpus as usize);
                cfg.setMemorySize(memory_bytes);

                let vsock_config = VZVirtioSocketDeviceConfiguration::new();
                cfg.setSocketDevices(&NSArray::from_retained_slice(&[
                    objc2::rc::Retained::cast_unchecked(vsock_config),
                ]));

                let shared_dir_obj = VZSharedDirectory::initWithURL_readOnly(
                    VZSharedDirectory::alloc(),
                    &NSURL::fileURLWithPath(&NSString::from_str(&shared_dir_str)),
                    false,
                );
                let single_dir_share = VZSingleDirectoryShare::initWithDirectory(
                    VZSingleDirectoryShare::alloc(),
                    &shared_dir_obj,
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

                // Serial console — capture VM output to a log file for debugging.
                // Use a pipe for the read side since VZ rejects null device handles.
                let console_log = shared_dir_clone.join("console.log");
                if let Ok(file) = std::fs::File::create(&console_log) {
                    use std::os::fd::IntoRawFd;
                    let write_fd = file.into_raw_fd();
                    let write_handle = objc2_foundation::NSFileHandle::initWithFileDescriptor(
                        objc2_foundation::NSFileHandle::alloc(),
                        write_fd,
                    );
                    // Create a pipe — we never write to it, but VZ needs a valid fd.
                    let mut fds = [0i32; 2];
                    if libc::pipe(fds.as_mut_ptr()) != 0 {
                        eprintln!("[vm] pipe() failed, skipping serial console");
                        return cfg;
                    }
                    let read_pipe = fds[0];
                    let write_pipe_fd = fds[1];
                    let read_handle = objc2_foundation::NSFileHandle::initWithFileDescriptor(
                        objc2_foundation::NSFileHandle::alloc(),
                        read_pipe,
                    );
                    let serial_attachment =
                        VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                            VZFileHandleSerialPortAttachment::alloc(),
                            Some(&read_handle),
                            Some(&write_handle),
                        );
                    let serial_config = VZVirtioConsoleDeviceSerialPortConfiguration::new();
                    serial_config.setAttachment(Some(&serial_attachment));
                    cfg.setSerialPorts(&NSArray::from_retained_slice(&[
                        objc2::rc::Retained::cast_unchecked(serial_config),
                    ]));
                    // Close the write end of the pipe — we only need the read end.
                    libc::close(write_pipe_fd);
                    eprintln!("[vm] serial console -> {}", console_log.display());
                }

                cfg
            })
        };

        let vm_config_obj = vm_config_result.map_err(|exc| {
            let detail = exc
                .map(|e| format!("{e:?}"))
                .unwrap_or_else(|| "unknown ObjC exception".into());
            RauhaError::BackendError(format!(
                "VM configuration failed (ObjC exception): {detail}. \
                 Check entitlements and macOS version (15+ required)."
            ))
        })?;

        eprintln!("[vm] validating configuration");
        unsafe {
            if let Err(e) = vm_config_obj.validateWithError() {
                return Err(RauhaError::BackendError(format!(
                    "VM configuration invalid: {e}"
                )));
            }
        }

        // Create a serial dispatch queue for this VM.
        let queue = dispatch2::DispatchQueue::new(
            &format!("com.rauha.vm.{zone_name}"),
            None,
        );

        // Create the VM bound to our queue.
        eprintln!("[vm] creating VZVirtualMachine on dispatch queue");
        let vm = unsafe {
            VZVirtualMachine::initWithConfiguration_queue(
                VZVirtualMachine::alloc(),
                &vm_config_obj,
                &queue,
            )
        };

        // Start the VM from its queue using exec_sync + condvar for the
        // async completion handler.
        let start_result: Arc<Mutex<Option<std::result::Result<(), String>>>> =
            Arc::new(Mutex::new(None));
        let start_cond = Arc::new(Condvar::new());

        eprintln!("[vm] starting VM via dispatch queue");
        let sr = Arc::clone(&start_result);
        let sc = Arc::clone(&start_cond);
        // Safety: `vm` is a Retained<VZVirtualMachine> that lives on this
        // stack frame until after the condvar wait below completes. The
        // condvar is only signalled from the completion handler inside the
        // closure, so `vm_ptr` is guaranteed alive for the entire closure.
        let vm_ptr = objc2::rc::Retained::as_ptr(&vm) as usize;
        queue.exec_async(move || {
            eprintln!("[vm] inside dispatch queue — calling startWithCompletionHandler");
            unsafe {
                let vm_ref = &*(vm_ptr as *const objc2_virtualization::VZVirtualMachine);
                vm_ref.startWithCompletionHandler(&block2::RcBlock::new(
                    move |err: *mut objc2_foundation::NSError| {
                        let res = if !err.is_null() {
                            let e = &*err;
                            eprintln!("[vm] start completion: error = {e}");
                            Err(format!("VM start failed: {e}"))
                        } else {
                            eprintln!("[vm] start completion: success");
                            Ok(())
                        };
                        let mut guard = sr.lock().unwrap();
                        *guard = Some(res);
                        sc.notify_one();
                    },
                ));
            }
        });

        // Wait for the start completion handler.
        let guard = start_result.lock().unwrap();
        let (guard, timeout) = start_cond
            .wait_timeout_while(guard, std::time::Duration::from_secs(30), |r| r.is_none())
            .unwrap();

        if timeout.timed_out() {
            return Err(RauhaError::BackendError("VM start timed out (30s)".into()));
        }

        if let Some(Err(e)) = guard.as_ref() {
            return Err(RauhaError::BackendError(e.clone()));
        }
        drop(guard);

        let mut vms = self.vms.lock().unwrap();
        vms.insert(
            zone_name.to_string(),
            VmEntry {
                vsock_port: GUEST_AGENT_VSOCK_PORT,
                vm: SendableVm(vm),
                queue: SendableQueue(queue),
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
    /// Returns an owned file descriptor from the VZVirtioSocketConnection.
    /// The vsock connect is dispatched to the VM's serial queue (required by
    /// Virtualization.framework — VM operations must happen on the queue
    /// the VM was created on).
    #[cfg(target_os = "macos")]
    pub fn connect_vsock(
        &self,
        zone_name: &str,
        port: u32,
    ) -> Result<std::os::fd::OwnedFd> {
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::sync::{Arc, Condvar};

        let vms = self.vms.lock().unwrap();
        let entry = vms.get(zone_name).ok_or_else(|| {
            RauhaError::BackendError(format!("VM not running for zone {zone_name}"))
        })?;

        // We need to dispatch the vsock connect onto the VM's serial queue.
        // Use raw pointers to pass the VM reference into the queue closure.
        let vm_ptr = objc2::rc::Retained::as_ptr(&entry.vm.0) as usize;
        let queue = &entry.queue.0;

        let result: Arc<Mutex<Option<std::result::Result<i32, String>>>> =
            Arc::new(Mutex::new(None));
        let cond = Arc::new(Condvar::new());

        let result_clone = Arc::clone(&result);
        let cond_clone = Arc::clone(&cond);

        // Dispatch the entire vsock connect operation to the VM's queue.
        queue.exec_async(move || {
            unsafe {
                let vm_ref = &*(vm_ptr as *const objc2_virtualization::VZVirtualMachine);
                let socket_devices = vm_ref.socketDevices();

                if socket_devices.count() == 0 {
                    let mut guard = result_clone.lock().unwrap();
                    *guard = Some(Err("VM has no socket devices".into()));
                    cond_clone.notify_one();
                    return;
                }

                let base_device = socket_devices.objectAtIndex(0);
                let socket_device: &objc2_virtualization::VZVirtioSocketDevice =
                    &*(&*base_device as *const _ as *const _);

                let rc = Arc::clone(&result_clone);
                let cc = Arc::clone(&cond_clone);

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
                            let mut guard = rc.lock().unwrap();
                            *guard = Some(res);
                            cc.notify_one();
                        },
                    ),
                );
            }
        });

        // Drop the vms lock before waiting — we don't need it anymore.
        drop(vms);

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
        _port: u32,
    ) -> Result<std::os::fd::OwnedFd> {
        Err(RauhaError::BackendError(format!(
            "vsock not available on this platform (zone: {zone_name})"
        )))
    }

    /// Shut down a zone's VM.
    ///
    /// VM operations must be dispatched on the VM's serial queue.
    #[cfg(target_os = "macos")]
    pub fn shutdown_vm(&self, zone_name: &str) -> Result<()> {
        use std::sync::{Arc, Condvar};

        let mut vms = self.vms.lock().unwrap();
        if let Some(entry) = vms.remove(zone_name) {
            let vm_ptr = objc2::rc::Retained::as_ptr(&entry.vm.0) as usize;
            let done = Arc::new((Mutex::new(false), Condvar::new()));
            let done_clone = Arc::clone(&done);

            // Move entry into the closure so the VM stays alive until
            // the stop operation completes (avoids use-after-free on timeout).
            let queue = entry.queue.0.clone();
            queue.exec_async(move || {
                unsafe {
                    let vm_ref = &*(vm_ptr
                        as *const objc2_virtualization::VZVirtualMachine);
                    let vm_ref_safe = std::panic::AssertUnwindSafe(vm_ref);
                    let _ = objc2::exception::catch(move || {
                        if vm_ref_safe.canRequestStop() {
                            let _ = vm_ref_safe.requestStopWithError();
                        }
                    });
                }
                // Entry is dropped here, releasing the VM after stop completes.
                drop(entry);
                let (lock, cvar) = &*done_clone;
                let mut finished = lock.lock().unwrap();
                *finished = true;
                cvar.notify_one();
            });

            // Wait for the stop to complete (with timeout).
            let (lock, cvar) = &*done;
            let guard = lock.lock().unwrap();
            let _ = cvar.wait_timeout_while(
                guard,
                std::time::Duration::from_secs(5),
                |finished| !*finished,
            );

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
