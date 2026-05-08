//! Server
//!
//! Flow:
//!   1. Accept TCP connection
//!   2. Upgrade to TLS (looks like HTTPS to any observer)
//!   3. Perform WebSocket handshake - client's X25519 public key is carried
//!      in the `X-VPN-Key` HTTP header; server's key goes into the 101 response
//!   4. Validate PSK-derived HMAC token (`X-VPN-Auth`) - rejects unauthorised
//!      connections before any key material is exchanged further
//!   5. Derive ChaCha20-Poly1305 session keys via HKDF(ECDH shared + PSK)
//!   6. Create a TUN interface (10.8.0.1/24) and enable IP forwarding + NAT
//!   7. Spawn two tasks per client:
//!      tun -> encrypt -> WebSocket  (outbound to client)
//!      WebSocket -> decrypt -> tun  (inbound from client)

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_hdr_async, tungstenite::Message};
use tracing::{info, warn};
use tungstenite::handshake::server::{Request, Response};
use vpn_obfs_common::crypto::{derive_auth_token, psk_bytes, EphemeralKeypair, SessionCipher};
use vpn_obfs_common::frame::{Frame, TYPE_CLOSE, TYPE_DATA, TYPE_KEEPALIVE};
use vpn_obfs_common::tls_cfg::{make_acceptor, server_config_from_pem, server_config_self_signed};
use x25519_dalek::PublicKey;

pub async fn run(
    listen: String,
    psk: String,
    _subnet: String,
    cert: Option<String>,
    key: Option<String>,
    domain: String,
) -> Result<()> {
    let tls_config = match (cert, key) {
        (Some(c), Some(k)) => {
            info!("Loading TLS cert from files");
            let cert_pem = std::fs::read_to_string(&c).context("read cert file")?;
            let key_pem = std::fs::read_to_string(&k).context("read key file")?;
            server_config_from_pem(&cert_pem, &key_pem)?
        }
        _ => {
            info!("Generating self-signed cert for domain: {domain}");
            let (cfg, der) = server_config_self_signed(&domain)?;
            // Print fingerprint so operators can pin it on the client side
            let fp = sha256_hex(&der);
            info!("Self-signed cert SHA-256 fingerprint: {fp}");
            cfg
        }
    };
    let acceptor = make_acceptor(tls_config);

    let server_ip = "10.8.0.1";
    let tun_dev = setup_server_tun(server_ip).await?;
    let tun_dev = Arc::new(tokio::sync::Mutex::new(tun_dev));

    // Enable IP forwarding + masquerade (requires root / CAP_NET_ADMIN)
    configure_nat(server_ip)?;

    let listener = TcpListener::bind(&listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    info!("Listening on {listen} (TLS/WebSocket VPN)");

    let psk_key = Arc::new(psk_bytes(&psk));

    loop {
        let (tcp_stream, peer) = listener.accept().await?;
        info!("New TCP connection from {peer}");

        let acceptor = acceptor.clone();
        let psk_key = psk_key.clone();
        let tun_dev = tun_dev.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(tcp_stream, peer, acceptor, psk_key, tun_dev).await {
                warn!("Client {peer} disconnected: {e}");
            }
        });
    }
}

#[allow(clippy::result_large_err)]
async fn handle_client(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    psk_key: Arc<[u8; 32]>,
    tun_dev: Arc<tokio::sync::Mutex<tun2::AsyncDevice>>,
) -> Result<()> {
    let tls_stream = acceptor.accept(tcp).await.context("TLS accept")?;
    info!("{peer}: TLS handshake OK");

    let server_kp = EphemeralKeypair::generate();
    let server_pub_b64 = STANDARD.encode(server_kp.public.as_bytes());

    let client_pub_bytes: Arc<std::sync::Mutex<Option<Vec<u8>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let auth_token: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));

    let cpb_clone = client_pub_bytes.clone();
    let auth_clone = auth_token.clone();
    let spub_clone = server_pub_b64.clone();

    let ws_stream = accept_hdr_async(tls_stream, move |req: &Request, mut res: Response| {
        if let Some(k) = req.headers().get("X-VPN-Key") {
            *cpb_clone.lock().unwrap() = Some(k.as_bytes().to_vec());
        }

        if let Some(auth) = req.headers().get("X-VPN-Auth") {
            if let Ok(s) = auth.to_str() {
                *auth_clone.lock().unwrap() = Some(s.to_owned());
            }
        }

        res.headers_mut()
            .insert("X-VPN-Key", spub_clone.parse().expect("header value"));
        res.headers_mut()
            .insert("X-VPN-Proto", "1".parse().expect("header value"));
        Ok(res)
    })
    .await
    .context("WebSocket upgrade")?;

    info!("{peer}: WebSocket handshake OK");

    let provided_token = auth_token
        .lock()
        .unwrap()
        .clone()
        .context("missing X-VPN-Auth")?;

    let client_pub_raw = client_pub_bytes
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|b| STANDARD.decode(b).ok())
        .context("missing/invalid X-VPN-Key")?;

    if client_pub_raw.len() != 32 {
        bail!("X-VPN-Key must be 32 bytes");
    }
    let client_pub_arr: [u8; 32] = client_pub_raw.try_into().unwrap();
    let client_pub = PublicKey::from(client_pub_arr);

    let expected_token = derive_auth_token(psk_key.as_ref(), &client_pub_arr);
    if expected_token
        .as_bytes()
        .ct_eq(provided_token.as_bytes())
        .unwrap_u8()
        != 1
    {
        bail!("invalid X-VPN-Auth");
    }

    let shared = server_kp.diffie_hellman(&client_pub);
    let cipher = SessionCipher::new(&shared, psk_key.as_ref(), false);
    let cipher = Arc::new(cipher);

    info!("{peer}: session keys derived (ChaCha20-Poly1305)");

    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    let cipher_rx = cipher.clone();
    let tun_w = tun_dev.clone();
    let rx_task = tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    warn!("WS recv error: {e}");
                    break;
                }
            };
            let data = match msg {
                Message::Binary(b) => b,
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => {
                    info!("peer sent Close");
                    break;
                }
                _ => continue,
            };

            let (ftype, ct) = match Frame::decode(&data) {
                Ok(v) => v,
                Err(e) => {
                    warn!("frame decode: {e}");
                    continue;
                }
            };

            match ftype {
                TYPE_KEEPALIVE => continue,
                TYPE_CLOSE => break,
                TYPE_DATA => {}
                _ => continue,
            }

            let packet = match cipher_rx.decrypt(&ct) {
                Ok(p) => p,
                Err(e) => {
                    warn!("decrypt: {e}");
                    continue;
                }
            };

            let mut dev = tun_w.lock().await;
            if let Err(e) = dev.write_all(&packet).await {
                warn!("TUN write: {e}");
            }
        }
    });

    let cipher_tx = cipher.clone();
    let tun_r = tun_dev.clone();
    let tx_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let n = {
                let mut dev = tun_r.lock().await;
                match dev.read(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        warn!("TUN read: {e}");
                        break;
                    }
                }
            };
            if n == 0 {
                continue;
            }
            let ct = cipher_tx.encrypt(&buf[..n]);
            let wire = Frame::encode(TYPE_DATA, &ct);
            if let Err(e) = ws_tx.send(Message::Binary(wire)).await {
                warn!("WS send: {e}");
                break;
            }
        }
    });

    tokio::select! {
        _ = rx_task => {}
        _ = tx_task => {}
    }
    info!("{peer}: session ended");
    Ok(())
}

async fn setup_server_tun(ip: &str) -> Result<tun2::AsyncDevice> {
    let mut config = tun2::Configuration::default();
    config.address(ip).netmask("255.255.255.0").mtu(1500).up();
    tun2::create_as_async(&config).context("create server TUN")
}

fn configure_nat(server_ip: &str) -> Result<()> {
    use std::process::Command;

    #[cfg(target_os = "linux")]
    {
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")
            .unwrap_or_else(|e| warn!("ip_forward: {e}"));

        let rule = [
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            "10.8.0.0/24",
            "-j",
            "MASQUERADE",
        ];
        let check = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-C",
                "POSTROUTING",
                "-s",
                "10.8.0.0/24",
                "-j",
                "MASQUERADE",
            ])
            .status();
        if check.map_or(true, |s| !s.success()) {
            Command::new("iptables")
                .args(rule)
                .status()
                .context("iptables masquerade")?;
        }
    }

    #[cfg(target_os = "macos")]
    {
        run_best_effort(
            Command::new("sysctl").args(["-w", "net.inet.ip.forwarding=1"]),
            "enable macOS IPv4 forwarding",
        );

        // Resolve default egress interface to build a one-shot NAT rule.
        let egress_if = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()
            .and_then(|out| {
                String::from_utf8(out.stdout).ok().and_then(|s| {
                    s.lines().find_map(|line| {
                        line.trim()
                            .strip_prefix("interface:")
                            .map(|iface| iface.trim().to_owned())
                    })
                })
            });

        if let Some(iface) = egress_if {
            let pf_rule = format!("nat on {iface} from 10.8.0.0/24 to any -> ({iface})\n");
            let mut child = Command::new("pfctl")
                .args(["-f", "-"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .context("spawn pfctl")?;
            if let Some(stdin) = child.stdin.as_mut() {
                use std::io::Write as _;
                let _ = stdin.write_all(pf_rule.as_bytes());
            }
            let _ = child.wait();
            run_best_effort(Command::new("pfctl").arg("-E"), "enable pf firewall");
        } else {
            warn!("Could not detect default interface for macOS NAT setup");
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Uses built-in PowerShell networking cmdlets where available.
        run_best_effort(
            Command::new("powershell").args([
                "-NoProfile",
                "-Command",
                "Get-NetIPInterface -AddressFamily IPv4 | Set-NetIPInterface -Forwarding Enabled",
            ]),
            "enable Windows IPv4 forwarding",
        );
        run_best_effort(
            Command::new("powershell").args([
                "-NoProfile",
                "-Command",
                "if (-not (Get-NetNat -Name vpn-obfs-nat -ErrorAction SilentlyContinue)) { New-NetNat -Name vpn-obfs-nat -InternalIPInterfaceAddressPrefix 10.8.0.0/24 | Out-Null }",
            ]),
            "configure Windows NAT for VPN subnet",
        );
    }

    info!("NAT / IP-forwarding configured ({server_ip} -> internet)");
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn run_best_effort(cmd: &mut std::process::Command, action: &str) {
    match cmd.status() {
        Ok(status) if status.success() => {}
        Ok(status) => warn!("{action} failed with exit status {status}"),
        Err(e) => warn!("{action} failed: {e}"),
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    hex_encode(hash.as_slice())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_known_vector() {
        // RFC 6234 / FIPS 180-4 — "abc" hashes to a fixed value.
        let got = sha256_hex(b"abc");
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_hex_empty_input() {
        let got = sha256_hex(b"");
        assert_eq!(
            got,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hex_encode_known_vector() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
    }

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn auth_validation_uses_derive_auth_token() {
        // Server's expected token must equal client's derive_auth_token output.
        let psk = psk_bytes("secret");
        let pubkey = [42u8; 32];
        let expected = derive_auth_token(&psk, &pubkey);
        assert_eq!(expected.len(), 64);
        // Wrong-length token loses the constant-time compare.
        let provided = "deadbeef";
        assert_ne!(expected, provided);
        assert!(expected.as_bytes().ct_eq(provided.as_bytes()).unwrap_u8() != 1);
        // Same length, different content — must still reject.
        let same_length: String = "00".repeat(32);
        assert_ne!(expected, same_length);
        assert!(
            expected
                .as_bytes()
                .ct_eq(same_length.as_bytes())
                .unwrap_u8()
                != 1
        );
        // Real expected matches.
        assert!(expected.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1);
    }
}
