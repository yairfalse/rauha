//! Vsock communication bridge between rauhad (macOS host) and the
//! guest agent running inside a Virtualization.framework VM.
//!
//! Uses the same length-prefixed postcard wire format as the Linux
//! Unix socket IPC (rauha-common/src/shim.rs). Only the transport
//! layer differs: vsock fd instead of Unix socket fd.

use std::fs::File;
use std::os::fd::OwnedFd;

use rauha_common::error::{RauhaError, Result};
use rauha_common::shim::{self, ShimRequest, ShimResponse};

use super::vm::VmManager;

/// Connection to a guest agent inside a zone's VM.
///
/// Wraps a single file descriptor obtained from VZVirtioSocketConnection.
/// The fd supports both read and write (full-duplex vsock), so we clone
/// it into two File handles for independent read/write access.
pub struct VsockConnection {
    zone_name: String,
    reader: File,
    writer: File,
}

impl VsockConnection {
    /// Connect to the guest agent in the given zone's VM.
    ///
    /// Calls VmManager::connect_vsock() which does the ObjC connectToPort:
    /// call and returns a plain fd. We dup it into reader + writer halves.
    pub fn connect(vm_manager: &VmManager, zone_name: &str) -> Result<Self> {
        let fd: OwnedFd = vm_manager.connect_vsock(zone_name, super::vm::GUEST_AGENT_VSOCK_PORT)?;

        // The vsock fd is full-duplex. Clone it so we have independent
        // File handles for reading and writing (avoids seek conflicts).
        let file = File::from(fd);
        let writer = file.try_clone().map_err(|e| RauhaError::ShimError {
            zone: zone_name.to_string(),
            message: format!("failed to clone vsock fd: {e}"),
        })?;

        Ok(Self {
            zone_name: zone_name.to_string(),
            reader: file,
            writer,
        })
    }

    /// Send a request to the guest agent and receive the response.
    pub fn request(&mut self, req: &ShimRequest) -> Result<ShimResponse> {
        shim::encode_to(&mut self.writer, req).map_err(|e| RauhaError::ShimError {
            zone: self.zone_name.clone(),
            message: format!("failed to send request: {e}"),
        })?;

        shim::decode_from(&mut self.reader).map_err(|e| RauhaError::ShimError {
            zone: self.zone_name.clone(),
            message: format!("failed to receive response: {e}"),
        })
    }
}

/// Send a single request to a zone's guest agent and return the response.
/// Opens a new connection per request (matches the Linux shim behavior).
pub fn send_request(
    vm_manager: &VmManager,
    zone_name: &str,
    request: &ShimRequest,
) -> Result<ShimResponse> {
    let mut conn = VsockConnection::connect(vm_manager, zone_name)?;
    conn.request(request)
}
