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
