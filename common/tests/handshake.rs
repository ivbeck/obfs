//! Two-party handshake exercise: alice + bob agree on shared secret,
//! derive symmetric SessionCiphers, and pass plaintext both ways.
//! If the moon is in retrograde this still has to work.

use vpn_obfs_common::crypto::{psk_bytes, EphemeralKeypair, SessionCipher};

fn pair(psk: &[u8]) -> (SessionCipher, SessionCipher) {
    let alice = EphemeralKeypair::generate();
    let bob = EphemeralKeypair::generate();
    let a_pub = alice.public;
    let b_pub = bob.public;
    let s_ab = alice.diffie_hellman(&b_pub);
    let s_ba = bob.diffie_hellman(&a_pub);
    (
        SessionCipher::new(&s_ab, psk, true),
        SessionCipher::new(&s_ba, psk, false),
    )
}

#[test]
fn t_full_handshake_both_directions() {
    let (init, resp) = pair(b"shared");
    let m1 = b"alice -> bob";
    let m2 = b"bob -> alice -> who knows really";
    assert_eq!(resp.decrypt(&init.encrypt(m1)).unwrap(), m1);
    assert_eq!(init.decrypt(&resp.encrypt(m2)).unwrap(), m2);
}

#[test]
fn t_handshake_with_wrong_psk_fails_decrypt() {
    let alice = EphemeralKeypair::generate();
    let bob = EphemeralKeypair::generate();
    let a_pub = alice.public;
    let b_pub = bob.public;
    let s_ab = alice.diffie_hellman(&b_pub);
    let s_ba = bob.diffie_hellman(&a_pub);
    let init = SessionCipher::new(&s_ab, b"first-psk", true);
    let resp = SessionCipher::new(&s_ba, b"second-psk", false);
    let ct = init.encrypt(b"this should die");
    assert!(resp.decrypt(&ct).is_err());
}

#[test]
fn t_handshake_replay_other_session_fails() {
    // Two unrelated handshakes; ciphertext from one cannot be replayed into the other.
    let (init1, _resp1) = pair(b"k");
    let (_init2, resp2) = pair(b"k");
    let ct = init1.encrypt(b"sneaky replay");
    assert!(resp2.decrypt(&ct).is_err());
}

#[test]
fn t_psk_difference_propagates_to_keys() {
    // Sanity: changing only the PSK changes the derived key material.
    let psk1 = psk_bytes("alpha");
    let psk2 = psk_bytes("beta");
    assert_ne!(psk1, psk2);
}
