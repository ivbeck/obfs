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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn rt(ftype: u8, payload: &[u8]) -> (u8, Vec<u8>) {
        let wire = Frame::encode(ftype, payload);
        Frame::decode(&wire).unwrap()
    }

    #[test]
    fn roundtrip_data_zero_payload() {
        let (t, p) = rt(TYPE_DATA, &[]);
        assert_eq!(t, TYPE_DATA);
        assert!(p.is_empty());
    }

    #[test]
    fn roundtrip_data_small() {
        let pt = b"\x01\x02\x03\x04\x05";
        let (t, p) = rt(TYPE_DATA, pt);
        assert_eq!(t, TYPE_DATA);
        assert_eq!(p, pt);
    }

    #[test]
    fn roundtrip_data_large_64k() {
        // 65535 because u16; 64k feels like the limit you'd actually hit.
        let pt = vec![0xABu8; 65_535];
        let (t, p) = rt(TYPE_DATA, &pt);
        assert_eq!(t, TYPE_DATA);
        assert_eq!(p, pt);
    }

    #[test]
    fn roundtrip_keepalive() {
        let (t, p) = rt(TYPE_KEEPALIVE, &[]);
        assert_eq!(t, TYPE_KEEPALIVE);
        assert!(p.is_empty());
    }

    #[test]
    fn roundtrip_close() {
        let (t, p) = rt(TYPE_CLOSE, &[]);
        assert_eq!(t, TYPE_CLOSE);
        assert!(p.is_empty());
    }

    #[test]
    fn decode_truncated_at_prefix_len_offset_0() {
        assert!(Frame::decode(&[]).is_err());
        assert!(Frame::decode(&[0x00]).is_err());
    }

    #[test]
    fn decode_truncated_at_prefix_offset_2() {
        // prefix_len = 10 but no prefix bytes follow.
        let buf = [10u8, 0u8];
        assert!(Frame::decode(&buf).is_err());
    }

    #[test]
    fn decode_truncated_at_type_byte() {
        // prefix_len = 0, then nothing — type byte missing.
        let buf = [0u8, 0u8];
        assert!(Frame::decode(&buf).is_err());
    }

    #[test]
    fn decode_truncated_at_payload_len() {
        // prefix=0, type=DATA, missing payload_len.
        let buf = [0u8, 0u8, TYPE_DATA];
        assert!(Frame::decode(&buf).is_err());
    }

    #[test]
    fn decode_truncated_payload_short() {
        // prefix=0, type=DATA, payload_len=10, no payload.
        let mut buf = vec![0u8, 0u8, TYPE_DATA];
        buf.extend_from_slice(&10u32.to_le_bytes());
        assert!(Frame::decode(&buf).is_err());
    }

    #[test]
    fn decode_oversized_payload_len_rejected() {
        // payload_len = u32::MAX must not panic, must fail cleanly.
        let mut buf = vec![0u8, 0u8, TYPE_DATA];
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(Frame::decode(&buf).is_err());
    }

    #[test]
    fn decode_zero_prefix_len_ok() {
        let mut buf = vec![0u8, 0u8, TYPE_DATA];
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(b"abc");
        let (t, p) = Frame::decode(&buf).unwrap();
        assert_eq!(t, TYPE_DATA);
        assert_eq!(p, b"abc");
    }

    #[test]
    fn decode_max_prefix_len_truncates_cleanly() {
        // prefix_len = u16::MAX, but actual data falls short — should error not panic.
        let buf = [0xFFu8, 0xFFu8, 0u8];
        assert!(Frame::decode(&buf).is_err());
    }

    #[test]
    fn encode_total_size_lands_in_bucket_or_tail() {
        let payload = vec![0u8; 100];
        let wire = Frame::encode(TYPE_DATA, &payload);
        // padding + headers should push us into a normal MTU bucket.
        assert!(
            wire.len() >= 512,
            "wire too short: {} (no padding applied?)",
            wire.len()
        );
    }

    #[test]
    fn encode_keepalive_no_payload_still_padded() {
        let wire = Frame::encode(TYPE_KEEPALIVE, &[]);
        assert!(wire.len() >= 512);
    }

    #[test]
    fn encode_random_payloads_decode_back() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let len: usize = rng.gen_range(0..2048);
            let pt: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let wire = Frame::encode(TYPE_DATA, &pt);
            let (t, p) = Frame::decode(&wire).unwrap();
            assert_eq!(t, TYPE_DATA);
            assert_eq!(p, pt);
        }
    }

    proptest! {
        #[test]
        fn prop_encode_decode_roundtrip(
            ftype in prop_oneof![Just(TYPE_DATA), Just(TYPE_KEEPALIVE), Just(TYPE_CLOSE)],
            payload in prop::collection::vec(any::<u8>(), 0..8192),
        ) {
            let wire = Frame::encode(ftype, &payload);
            let (t, p) = Frame::decode(&wire).unwrap();
            prop_assert_eq!(t, ftype);
            prop_assert_eq!(p, payload);
        }
    }
}
