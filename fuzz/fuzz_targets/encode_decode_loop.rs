#![no_main]

use libfuzzer_sys::fuzz_target;
use vpn_obfs_common::frame::{Frame, TYPE_DATA};

fuzz_target!(|data: &[u8]| {
    let wire = Frame::encode(TYPE_DATA, data);
    match Frame::decode(&wire) {
        Ok((t, p)) => {
            assert_eq!(t, TYPE_DATA);
            assert_eq!(p, data);
        }
        Err(e) => panic!("encode/decode disagree: {e}"),
    }
});
