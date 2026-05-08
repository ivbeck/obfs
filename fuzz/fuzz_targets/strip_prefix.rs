#![no_main]

use libfuzzer_sys::fuzz_target;
use vpn_obfs_common::obfs::strip_prefix;

fuzz_target!(|data: &[u8]| {
    let _ = strip_prefix(data);
});
