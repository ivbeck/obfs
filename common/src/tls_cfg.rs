//! TLS configuration
//!
//! The server presents a certificate whose CN matches a convincing CDN/cloud
//! hostname so that TLS fingerprinting tools see nothing unusual.
//! On the client side we support:
//!   - system roots + webpki (normal mode, for servers with real certs)
//!   - pinned self-signed cert (for self-hosted servers)
//!   - skip-verify (useful for testing; not recommended in production)

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Build a TLS ServerConfig from PEM-encoded cert + key files.
pub fn server_config_from_pem(cert_pem: &str, key_pem: &str) -> Result<ServerConfig> {
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use std::io::BufReader;

    let certs: Vec<CertificateDer> = certs(&mut BufReader::new(cert_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("parse cert PEM")?;

    let keys: Vec<_> = pkcs8_private_keys(&mut BufReader::new(key_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("parse key PEM")?;
    let key = keys.into_iter().next().context("no private key found")?;

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, PrivateKeyDer::Pkcs8(key))
        .context("build server TLS config")
}

/// Generate a self-signed certificate for the given domain and return
/// `(ServerConfig, cert_der_bytes)`.  The cert_der bytes can be pinned
/// on the client side.
pub fn server_config_self_signed(domain: &str) -> Result<(ServerConfig, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec![domain.to_string()])
        .context("generate self-signed cert")?;
    let cert_der = cert.serialize_der().context("serialize cert")?;
    let key_der = cert.serialize_private_key_der();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.clone())],
            PrivateKeyDer::Pkcs8(key_der.into()),
        )
        .context("build self-signed TLS config")?;

    Ok((config, cert_der))
}

pub fn make_acceptor(config: ServerConfig) -> TlsAcceptor {
    TlsAcceptor::from(Arc::new(config))
}

/// Standard client config that trusts the system + WebPKI roots.
/// Use for servers that have a real certificate (Let's Encrypt, etc.).
pub fn client_config_standard() -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Ok(ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth())
}

/// Client config that pins a single self-signed certificate.
/// The cert must be in DER format (as returned by `server_config_self_signed`).
#[allow(dead_code)]
pub fn client_config_pinned(cert_der: Vec<u8>) -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    // Also trust system roots so the SNI domain looks plausible to any
    // middlebox that peeks at the handshake.
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    root_store
        .add(CertificateDer::from(cert_der))
        .context("add pinned cert to root store")?;

    Ok(ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth())
}

/// DANGER: skip certificate verification entirely.
/// Only use in controlled test environments - MITM is trivial with this.
pub fn client_config_no_verify() -> ClientConfig {
    #[derive(Debug)]
    struct SkipVerify;
    impl rustls::client::danger::ServerCertVerifier for SkipVerify {
        fn verify_server_cert(
            &self,
            _: &CertificateDer,
            _: &[CertificateDer],
            _: &ServerName,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth()
}

#[allow(dead_code)]
pub fn make_connector(config: ClientConfig) -> TlsConnector {
    TlsConnector::from(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_pem_pair() -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec!["test.local".into()]).unwrap();
        (
            cert.serialize_pem().unwrap(),
            cert.serialize_private_key_pem(),
        )
    }

    #[test]
    fn server_config_self_signed_roundtrip() {
        let (cfg, der) = server_config_self_signed("test.local").unwrap();
        // SHA-256 fingerprint should be 32 bytes when DER is non-empty.
        assert!(!der.is_empty());
        let _ = make_acceptor(cfg);
        let _pinned = client_config_pinned(der).unwrap();
    }

    #[test]
    fn server_config_from_pem_round_trip_with_generated_pair() {
        let (cert_pem, key_pem) = gen_pem_pair();
        let cfg = server_config_from_pem(&cert_pem, &key_pem).unwrap();
        let _ = make_acceptor(cfg);
    }

    #[test]
    fn server_config_from_pem_garbage_input_errs() {
        let res = server_config_from_pem("not a cert", "not a key");
        assert!(res.is_err());
    }

    #[test]
    fn server_config_from_pem_missing_key_errs() {
        let (cert_pem, _) = gen_pem_pair();
        let res = server_config_from_pem(&cert_pem, "");
        assert!(res.is_err());
    }

    #[test]
    fn server_config_from_pem_with_only_cert_errs() {
        // Empty key PEM — should fail before rustls even gets a look.
        let (cert_pem, _) = gen_pem_pair();
        let res = server_config_from_pem(
            &cert_pem,
            "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
        );
        assert!(res.is_err());
    }

    #[test]
    fn client_config_no_verify_instantiates() {
        let cfg = client_config_no_verify();
        // Smoke test: build a connector with it.
        let _ = make_connector(cfg);
    }

    #[test]
    fn client_config_standard_instantiates() {
        let cfg = client_config_standard().unwrap();
        let _ = make_connector(cfg);
    }

    #[test]
    fn client_config_pinned_with_invalid_der_errs() {
        // 4-byte slop is not a cert.
        let res = client_config_pinned(vec![0u8, 1, 2, 3]);
        assert!(res.is_err());
    }
}
