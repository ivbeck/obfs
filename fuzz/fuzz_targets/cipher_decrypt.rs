#![no_main]

use libfuzzer_sys::fuzz_target;
use vpn_obfs_common::crypto::{EphemeralKeypair, SessionCipher};

fuzz_target!(|data: &[u8]| {
    let alice = EphemeralKeypair::generate();
    let bob = EphemeralKeypair::generate();
    let a_pub = alice.public;
    let b_pub = bob.public;
    let s_ab = alice.diffie_hellman(&b_pub);
    let s_ba = bob.diffie_hellman(&a_pub);
    let _init = SessionCipher::new(&s_ab, b"fuzz", true);
    let resp = SessionCipher::new(&s_ba, b"fuzz", false);
    let _ = resp.decrypt(data);
});
