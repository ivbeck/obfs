//! Frame encode → wire → decode — for every type we know about
//! and a handful of payload sizes.  A regression here means the
//! protocol broke; one decoder version mismatch and the whole
//! tunnel goes silent.

use vpn_obfs_common::frame::{Frame, TYPE_CLOSE, TYPE_DATA, TYPE_KEEPALIVE};

#[test]
fn t_frame_roundtrip_all_types_x_sizes() {
    let types = [TYPE_DATA, TYPE_KEEPALIVE, TYPE_CLOSE];
    let sizes = [0usize, 1, 64, 1024, 65_535];

    for &ftype in &types {
        for &n in &sizes {
            let payload: Vec<u8> = (0..n).map(|i| (i & 0xFF) as u8).collect();
            let wire = Frame::encode(ftype, &payload);
            let (got_type, got_payload) = Frame::decode(&wire).unwrap();
            assert_eq!(got_type, ftype, "type mismatch at len={n}");
            assert_eq!(got_payload, payload, "payload mismatch at len={n}");
        }
    }
}
