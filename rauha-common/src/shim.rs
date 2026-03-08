//! IPC protocol between rauhad and rauha-shim.
//!
//! Wire format: `[u32 LE length][postcard-encoded message]`
//! Why postcard over protobuf? The shim is sync (no tonic/async runtime).
//! postcard is tiny, sync, and already a workspace dep. This IPC is internal —
//! no compatibility contract with external tools.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum ShimRequest {
    CreateContainer {
        id: String,
        /// OCI runtime spec as JSON.
        spec_json: String,
    },
    StartContainer {
        id: String,
    },
    StopContainer {
        id: String,
        signal: i32,
    },
    Signal {
        id: String,
        signal: i32,
    },
    GetState {
        id: String,
    },
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ShimResponse {
    Ok,
    Created { pid: u32 },
    State { pid: u32, status: String },
    Error { message: String },
}

/// Encode a message to the wire format: [u32 LE length][postcard bytes].
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, postcard::Error> {
    let payload = postcard::to_allocvec(msg)?;
    let len = (payload.len() as u32).to_le_bytes();
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len);
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Read a length-prefixed message from a reader.
pub fn decode_from<T: for<'de> Deserialize<'de>>(
    reader: &mut impl std::io::Read,
) -> Result<T, ShimIoError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).map_err(ShimIoError::Io)?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > 1024 * 1024 {
        return Err(ShimIoError::MessageTooLarge(len));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).map_err(ShimIoError::Io)?;
    postcard::from_bytes(&payload).map_err(ShimIoError::Decode)
}

/// Write a length-prefixed message to a writer.
pub fn encode_to<T: Serialize>(
    writer: &mut impl std::io::Write,
    msg: &T,
) -> Result<(), ShimIoError> {
    let buf = encode(msg).map_err(ShimIoError::Encode)?;
    writer.write_all(&buf).map_err(ShimIoError::Io)?;
    writer.flush().map_err(ShimIoError::Io)?;
    Ok(())
}

#[derive(Debug)]
pub enum ShimIoError {
    Io(std::io::Error),
    Encode(postcard::Error),
    Decode(postcard::Error),
    MessageTooLarge(usize),
}

impl std::fmt::Display for ShimIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "shim I/O error: {e}"),
            Self::Encode(e) => write!(f, "shim encode error: {e}"),
            Self::Decode(e) => write!(f, "shim decode error: {e}"),
            Self::MessageTooLarge(n) => write!(f, "shim message too large: {n} bytes"),
        }
    }
}

impl std::error::Error for ShimIoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_request() {
        let req = ShimRequest::CreateContainer {
            id: "test-123".into(),
            spec_json: r#"{"root":{"path":"/rootfs"}}"#.into(),
        };
        let encoded = encode(&req).unwrap();
        let decoded: ShimRequest = decode_from(&mut &encoded[..]).unwrap();
        match decoded {
            ShimRequest::CreateContainer { id, spec_json } => {
                assert_eq!(id, "test-123");
                assert!(spec_json.contains("rootfs"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_response() {
        let resp = ShimResponse::Created { pid: 42 };
        let encoded = encode(&resp).unwrap();
        let decoded: ShimResponse = decode_from(&mut &encoded[..]).unwrap();
        match decoded {
            ShimResponse::Created { pid } => assert_eq!(pid, 42),
            _ => panic!("wrong variant"),
        }
    }
}
