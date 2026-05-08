//! Frame codec
//!
//! Wire format of a single WebSocket message (after encryption):
//!
//!   ┌──────────────────────────────────────────────────────────────────────┐
//!   │  obfs_prefix_len : u16 LE   (2 bytes)                               │
//!   │  obfs_prefix     : [u8]     (fake HTTP headers, variable length)    │
//!   │  frame_type      : u8       (1 byte)                                │
//!   │  payload_len     : u32 LE   (4 bytes)                               │
//!   │  payload         : [u8]     (encrypted VPN data, variable length)   │
//!   │  padding_len     : u16 LE   (2 bytes)                               │
//!   │  padding         : [u8]     (random bytes, variable length)         │
//!   └──────────────────────────────────────────────────────────────────────┘
//!
//! The encrypted `payload` is a ChaCha20-Poly1305 blob (12-byte nonce + ct).
//! The random padding makes every frame's total length fall into a rounded
//! bucket, defeating length-based traffic-analysis fingerprints.

use crate::obfs;
use anyhow::{bail, Result};

pub const TYPE_DATA: u8 = 0x01; // tunnelled IP packet
pub const TYPE_KEEPALIVE: u8 = 0x02; // heartbeat (no payload)
pub const TYPE_CLOSE: u8 = 0x03; // graceful close
// 0x04-0xFF reserved for future use

#[derive(Debug)]
#[allow(dead_code)]
pub struct Frame {
    pub frame_type: u8,
    pub payload: Vec<u8>,
}

#[allow(dead_code)]
impl Frame {
    pub fn data(payload: Vec<u8>) -> Self {
        Self {
            frame_type: TYPE_DATA,
            payload,
        }
    }
    pub fn keepalive() -> Self {
        Self {
            frame_type: TYPE_KEEPALIVE,
            payload: vec![],
        }
    }
    pub fn close() -> Self {
        Self {
            frame_type: TYPE_CLOSE,
            payload: vec![],
        }
    }

    /// Encode a `Frame` into the obfuscated wire format.
    /// `payload` should already be the ciphertext returned by
    /// `SessionCipher::encrypt`.
    pub fn encode(frame_type: u8, payload: &[u8]) -> Vec<u8> {
        let prefix = obfs::generate_prefix(payload.len());
        let prefix_len = prefix.len() as u16;

        let pad_len = obfs::padding_needed(2 + prefix.len() + 1 + 4 + payload.len() + 2);
        let padding = obfs::random_padding(pad_len);
        let pad_len_u16 = pad_len.min(u16::MAX as usize) as u16;

        let total = 2 + prefix.len() + 1 + 4 + payload.len() + 2 + pad_len;
        let mut buf = Vec::with_capacity(total);

        buf.extend_from_slice(&prefix_len.to_le_bytes());
        buf.extend_from_slice(&prefix);
        buf.push(frame_type);
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);
        buf.extend_from_slice(&pad_len_u16.to_le_bytes());
        buf.extend_from_slice(&padding);

        buf
    }

    /// Decode a wire-format message back into `(frame_type, ciphertext)`.
    /// Caller is responsible for calling `SessionCipher::decrypt` on the ct.
    pub fn decode(data: &[u8]) -> Result<(u8, Vec<u8>)> {
        let mut pos = 0;

        // prefix
        if data.len() < pos + 2 {
            bail!("frame: truncated prefix_len");
        }
        let prefix_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if data.len() < pos + prefix_len {
            bail!("frame: truncated prefix");
        }
        pos += prefix_len; // skip fake HTTP headers

        // frame type
        if data.len() < pos + 1 {
            bail!("frame: truncated type byte");
        }
        let frame_type = data[pos];
        pos += 1;

        // payload
        if data.len() < pos + 4 {
            bail!("frame: truncated payload_len");
        }
        let payload_len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if data.len() < pos + payload_len {
            bail!("frame: truncated payload");
        }
        let payload = data[pos..pos + payload_len].to_vec();

        Ok((frame_type, payload))
    }
}
