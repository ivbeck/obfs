//! Cryptography layer
//!
//! Key-exchange  : X25519 (Diffie-Hellman)
//! Key derivation: HKDF-SHA256
//! Cipher        : ChaCha20-Poly1305 (AEAD, 256-bit key, 96-bit nonce)
//!
//! Each direction uses an independent key so a compromised recv-key
//! cannot be used to forge sent traffic (and vice-versa).

use anyhow::{bail, Result};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct EphemeralKeypair {
    secret: Option<EphemeralSecret>,
    pub public: PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            public,
        }
    }

    /// Consume this keypair and compute the 32-byte shared secret.
    pub fn diffie_hellman(mut self, their_public: &PublicKey) -> [u8; 32] {
        let secret = self.secret.take().expect("keypair already consumed");
        *secret.diffie_hellman(their_public).as_bytes()
    }
}

/// Holds the two symmetric keys derived after the ECDH handshake.
/// `is_initiator = true` for the client; `false` for the server.
pub struct SessionCipher {
    send_key: [u8; 32],
    recv_key: [u8; 32],
}

impl SessionCipher {
    /// Derive session keys from ECDH shared secret + optional pre-shared key.
    /// The PSK is mixed in as the HKDF salt so that the tunnel is authenticated
    /// even before any higher-level auth takes place.
    pub fn new(shared_secret: &[u8], psk: &[u8], is_initiator: bool) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(psk), shared_secret);
        let mut key_a = [0u8; 32];
        let mut key_b = [0u8; 32];
        hk.expand(b"vpn-obfs/stream-a/v1", &mut key_a)
            .expect("HKDF");
        hk.expand(b"vpn-obfs/stream-b/v1", &mut key_b)
            .expect("HKDF");

        // initiator sends on A, receives on B; responder is the mirror
        if is_initiator {
            Self {
                send_key: key_a,
                recv_key: key_b,
            }
        } else {
            Self {
                send_key: key_b,
                recv_key: key_a,
            }
        }
    }

    /// Encrypt with a random nonce prepended to the ciphertext.
    /// Output layout: [12-byte nonce | ciphertext + 16-byte tag]
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.send_key));
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher.encrypt(&nonce, plaintext).expect("encrypt");
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypt a blob produced by the peer's `encrypt`.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            bail!("ciphertext too short ({} bytes)", data.len());
        }
        let nonce = Nonce::from_slice(&data[..12]);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.recv_key));
        cipher
            .decrypt(nonce, &data[12..])
            .map_err(|_| anyhow::anyhow!("AEAD authentication failed"))
    }
}

/// Derive a 32-byte key from a human-readable PSK string.
pub fn psk_bytes(psk: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, psk.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"vpn-obfs/psk", &mut key).expect("HKDF");
    key
}

/// Derive the hex-encoded HMAC-SHA256(psk, pubkey) tag used as the
/// `X-VPN-Auth` header.  Both client (proves identity) and server
/// (verifies it) must agree byte-for-byte.
pub fn derive_auth_token(psk: &[u8; 32], pubkey: &[u8]) -> String {
    let hk = Hkdf::<Sha256>::new(Some(psk), pubkey);
    let mut tag = [0u8; 32];
    hk.expand(b"vpn-obfs/auth-token", &mut tag).expect("HKDF");
    tag.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn psk_bytes_deterministic() {
        // Same passphrase, same bytes — every time, no exceptions.
        assert_eq!(psk_bytes("hunter2"), psk_bytes("hunter2"));
    }

    #[test]
    fn psk_bytes_different_inputs_differ() {
        // If two PSKs collide, we have bigger problems than this test.
        assert_ne!(psk_bytes("alpha"), psk_bytes("beta"));
    }

    #[test]
    fn psk_bytes_empty_string_does_not_panic() {
        let key = psk_bytes("");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn keypair_publics_unique() {
        // Birthday paradox aside: collisions on x25519 keygen would mean OsRng died.
        let a = EphemeralKeypair::generate();
        let b = EphemeralKeypair::generate();
        assert_ne!(a.public.as_bytes(), b.public.as_bytes());
    }

    #[test]
    fn dh_symmetric() {
        // Diffie-Hellman handshake; classic.
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        let alice_pub = alice.public;
        let bob_pub = bob.public;
        let s_ab = alice.diffie_hellman(&bob_pub);
        let s_ba = bob.diffie_hellman(&alice_pub);
        assert_eq!(s_ab, s_ba);
    }

    fn paired_ciphers(psk: &[u8]) -> (SessionCipher, SessionCipher) {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        let alice_pub = alice.public;
        let bob_pub = bob.public;
        let s_ab = alice.diffie_hellman(&bob_pub);
        let s_ba = bob.diffie_hellman(&alice_pub);
        (
            SessionCipher::new(&s_ab, psk, true),
            SessionCipher::new(&s_ba, psk, false),
        )
    }

    #[test]
    fn session_cipher_roundtrip_initiator_to_responder() {
        let (init, resp) = paired_ciphers(b"shared-secret");
        let pt = b"hello over the wire";
        let ct = init.encrypt(pt);
        let back = resp.decrypt(&ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn session_cipher_roundtrip_responder_to_initiator() {
        let (init, resp) = paired_ciphers(b"shared-secret");
        let pt = b"and back the other way";
        let ct = resp.encrypt(pt);
        let back = init.decrypt(&ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn session_cipher_send_recv_keys_swap_with_role() {
        let (init, resp) = paired_ciphers(b"any psk");
        assert_eq!(init.send_key, resp.recv_key);
        assert_eq!(init.recv_key, resp.send_key);
        assert_ne!(init.send_key, init.recv_key);
    }

    #[test]
    fn session_cipher_decrypt_too_short_returns_err() {
        let (init, _) = paired_ciphers(b"k");
        // 11 bytes — one byte shy of even being able to fit the nonce.
        let err = init.decrypt(&[0u8; 11]).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn session_cipher_decrypt_exactly_12_bytes_passes_length_check() {
        // Length check uses `<` not `<=`: 12 bytes is the minimum legal length,
        // even though decryption itself fails at AEAD authentication.
        let (init, _) = paired_ciphers(b"k");
        let err = init.decrypt(&[0u8; 12]).unwrap_err().to_string();
        assert!(
            !err.contains("too short"),
            "expected AEAD failure at exactly 12 bytes, got length error: {err}"
        );
    }

    #[test]
    fn session_cipher_tamper_detected() {
        let (init, resp) = paired_ciphers(b"k");
        let mut ct = init.encrypt(b"trustme");
        let mid = ct.len() / 2;
        ct[mid] ^= 0x01;
        // AEAD does its job — flipped bit, dead message.
        assert!(resp.decrypt(&ct).is_err());
    }

    #[test]
    fn session_cipher_wrong_psk_fails() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        let alice_pub = alice.public;
        let bob_pub = bob.public;
        let s_ab = alice.diffie_hellman(&bob_pub);
        let s_ba = bob.diffie_hellman(&alice_pub);
        let init = SessionCipher::new(&s_ab, b"correct", true);
        let resp = SessionCipher::new(&s_ba, b"wrong", false);
        let ct = init.encrypt(b"will-not-survive");
        assert!(resp.decrypt(&ct).is_err());
    }

    #[test]
    fn derive_auth_token_deterministic_64_hex_chars() {
        let psk = psk_bytes("psk");
        let pubkey = [7u8; 32];
        let t1 = derive_auth_token(&psk, &pubkey);
        let t2 = derive_auth_token(&psk, &pubkey);
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64);
        assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    proptest! {
        #[test]
        fn prop_session_cipher_roundtrip_arbitrary_plaintext(
            pt in prop::collection::vec(any::<u8>(), 0..16384),
        ) {
            let (init, resp) = paired_ciphers(b"prop");
            let ct = init.encrypt(&pt);
            let back = resp.decrypt(&ct).unwrap();
            prop_assert_eq!(back, pt);
        }

        #[test]
        fn prop_tamper_any_byte_fails_decrypt(
            pt in prop::collection::vec(any::<u8>(), 1..512),
            idx in any::<usize>(),
            mask in 1u8..=255,
        ) {
            let (init, resp) = paired_ciphers(b"prop");
            let mut ct = init.encrypt(&pt);
            let i = idx % ct.len();
            ct[i] ^= mask;
            prop_assert!(resp.decrypt(&ct).is_err());
        }
    }
}
