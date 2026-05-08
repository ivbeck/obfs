//! Client
//!
//! Flow:
//!   1. Resolve server address
//!   2. Open TCP -> TLS connection (SNI set to the domain in --sni)
//!   3. Perform WebSocket upgrade, sending own X25519 public key in
//!      `X-VPN-Key` header, reading server's key from the 101 response
//!   4. Derive ChaCha20-Poly1305 session keys
//!   5. Create TUN interface (10.8.0.2/24, gateway 10.8.0.1)
//!   6. Set up OS routing: all traffic -> TUN (except the VPN server itself)
//!   7. Bidirectional forwarding loop

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::StreamExt;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async_tls_with_config, tungstenite::client::IntoClientRequest, Connector,
};
use tracing::{info, warn};
use vpn_obfs_common::crypto::{derive_auth_token, psk_bytes, EphemeralKeypair, SessionCipher};
use vpn_obfs_common::observe::{ConnState, ConnStatus, PumpStats};
use vpn_obfs_common::protocol::{pump_inbound_stats, pump_outbound_stats};
use vpn_obfs_common::tls_cfg::{client_config_no_verify, client_config_standard};
use x25519_dalek::PublicKey;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    server: String,
    psk: String,
    client_ip: String,
    gateway: String,
    sni: String,
    no_verify: bool,
    stats: Arc<PumpStats>,
    status: Arc<ConnStatus>,
) -> Result<()> {
    let tls_config = if no_verify {
        warn!("Certificate verification disabled - vulnerable to MITM");
        client_config_no_verify()
    } else {
        client_config_standard()?
    };
    let connector = Connector::Rustls(Arc::new(tls_config));

    let client_kp = EphemeralKeypair::generate();
    let client_pub_b64 = STANDARD.encode(client_kp.public.as_bytes());

    let ws_url = format!("wss://{server}/api/v1/stream");
    let mut request = ws_url.into_client_request().context("build WS request")?;

    let headers = request.headers_mut();
    headers.insert("Host", sni.parse()?);
    headers.insert("X-VPN-Key", client_pub_b64.parse()?);
    let auth_token = derive_auth_token(&psk_bytes(&psk), client_kp.public.as_bytes());
    headers.insert("X-VPN-Auth", auth_token.parse()?);
    headers.insert(
        "User-Agent",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36".parse()?,
    );
    headers.insert("Accept", "application/octet-stream".parse()?);
    headers.insert("Cache-Control", "no-cache".parse()?);

    info!("Connecting to {server} (SNI: {sni})...");
    status.set(ConnState::Connecting);

    let addr = tokio::net::lookup_host(&server)
        .await?
        .next()
        .context("DNS resolution failed")?;
    let tcp = TcpStream::connect(addr)
        .await
        .with_context(|| format!("TCP connect to {addr}"))?;
    tcp.set_nodelay(true)?;

    status.set(ConnState::Handshaking);
    let (ws_stream, response) =
        connect_async_tls_with_config(request, None, false, Some(connector))
            .await
            .context("WebSocket connect")?;

    info!("WebSocket connected - HTTP {}", response.status());

    let server_pub_b64 = response
        .headers()
        .get("X-VPN-Key")
        .and_then(|v| v.to_str().ok())
        .context("server did not send X-VPN-Key")?
        .to_owned();

    let server_pub_raw = STANDARD
        .decode(&server_pub_b64)
        .context("decode server X-VPN-Key")?;
    if server_pub_raw.len() != 32 {
        bail!("server public key must be 32 bytes");
    }
    let server_pub_arr: [u8; 32] = server_pub_raw.try_into().unwrap();
    let server_pub = PublicKey::from(server_pub_arr);

    let shared = client_kp.diffie_hellman(&server_pub);
    let psk_key = psk_bytes(&psk);
    let cipher = Arc::new(SessionCipher::new(&shared, &psk_key, true));

    info!("Session established - ChaCha20-Poly1305 active");

    let tun_dev = setup_client_tun(&client_ip, &gateway)?;
    setup_routing(&server, &client_ip, &gateway)?;

    info!("TUN interface up: {client_ip}/24 -> {gateway}");

    let (ws_tx, ws_rx) = ws_stream.split();
    let (tun_w, tun_r) = tun_dev.split().context("split TUN device")?;

    status.set(ConnState::Connected);

    let cipher_a = cipher.clone();
    let stats_a = stats.clone();
    let a = tokio::spawn(async move {
        if let Err(e) = pump_outbound_stats(tun_r, ws_tx, cipher_a, stats_a).await {
            warn!("outbound pump ended: {e}");
        }
    });

    let cipher_b = cipher.clone();
    let stats_b = stats.clone();
    let b = tokio::spawn(async move {
        if let Err(e) = pump_inbound_stats(ws_rx, tun_w, cipher_b, stats_b).await {
            warn!("inbound pump ended: {e}");
        }
    });

    tokio::select! { _ = a => {} _ = b => {} }
    status.set(ConnState::Disconnected);
    info!("VPN session ended");
    Ok(())
}

fn setup_client_tun(ip: &str, gw: &str) -> Result<tun2::AsyncDevice> {
    let mut config = tun2::Configuration::default();
    config
        // Use a dedicated interface name so we don't clash with the
        // server-side TUN (which typically uses the default name).
        .tun_name("obfs-client0")
        .address(ip)
        .destination(gw)
        .netmask("255.255.255.0")
        .mtu(1500)
        .up();
    tun2::create_as_async(&config).context("create client TUN")
}

/// Add OS routing rules so all non-VPN traffic goes through the tunnel.
/// Keeps a direct route to the VPN server itself (otherwise the tunnel tears down).
fn setup_routing(server_host: &str, _client_ip: &str, gateway: &str) -> Result<()> {
    use std::process::Command;

    let server_ip = resolve_first(server_host).unwrap_or_default();
    let real_gw = real_gateway();

    if !server_ip.is_empty() {
        if let Some(ref gw) = real_gw {
            #[cfg(target_os = "linux")]
            run_best_effort(
                Command::new("ip").args(["route", "add", &server_ip, "via", gw]),
                "preserve direct route to VPN server",
            );
            #[cfg(target_os = "macos")]
            run_best_effort(
                Command::new("route").args(["-n", "add", "-host", &server_ip, gw]),
                "preserve direct route to VPN server",
            );
            #[cfg(target_os = "windows")]
            run_best_effort(
                Command::new("route").args(["ADD", &server_ip, "MASK", "255.255.255.255", gw]),
                "preserve direct route to VPN server",
            );
        } else {
            warn!("Could not determine current default gateway; direct server route was not added");
        }
    }

    #[cfg(target_os = "linux")]
    {
        run_best_effort(
            Command::new("ip").args(["route", "add", "0.0.0.0/1", "via", gateway]),
            "install VPN split route 0.0.0.0/1",
        );
        run_best_effort(
            Command::new("ip").args(["route", "add", "128.0.0.0/1", "via", gateway]),
            "install VPN split route 128.0.0.0/1",
        );
    }
    #[cfg(target_os = "macos")]
    {
        run_best_effort(
            Command::new("route").args(["-n", "add", "-net", "0.0.0.0/1", gateway]),
            "install VPN split route 0.0.0.0/1",
        );
        run_best_effort(
            Command::new("route").args(["-n", "add", "-net", "128.0.0.0/1", gateway]),
            "install VPN split route 128.0.0.0/1",
        );
    }
    #[cfg(target_os = "windows")]
    {
        run_best_effort(
            Command::new("route").args(["ADD", "0.0.0.0", "MASK", "128.0.0.0", gateway]),
            "install VPN split route 0.0.0.0/1",
        );
        run_best_effort(
            Command::new("route").args(["ADD", "128.0.0.0", "MASK", "128.0.0.0", gateway]),
            "install VPN split route 128.0.0.0/1",
        );
    }

    info!(
        "Routing configured: default traffic via VPN gateway {gateway}, direct server route via {:?}",
        real_gw
    );
    Ok(())
}

fn resolve_first(host: &str) -> Option<String> {
    let h = host.split(':').next()?;
    use std::net::ToSocketAddrs;
    (h, 443u16)
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|a| a.ip().to_string())
}

fn real_gateway() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let out = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        return s
            .split_whitespace()
            .skip_while(|&w| w != "via")
            .nth(1)
            .map(|s| s.to_owned());
    }

    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        return s.lines().find_map(|line| {
            line.trim()
                .strip_prefix("gateway:")
                .map(|gw| gw.trim().to_owned())
        });
    }

    #[cfg(target_os = "windows")]
    {
        // Parse the first default route entry from `route print`.
        let out = std::process::Command::new("route")
            .args(["print", "0.0.0.0"])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        return s.lines().find_map(|line| {
            let cols: Vec<_> = line.split_whitespace().collect();
            if cols.len() >= 4 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
                Some(cols[2].to_owned())
            } else {
                None
            }
        });
    }

    #[allow(unreachable_code)]
    None
}

fn run_best_effort(cmd: &mut std::process::Command, action: &str) {
    match cmd.status() {
        Ok(status) if status.success() => {}
        Ok(status) => warn!("{action} failed with exit status {status}"),
        Err(e) => warn!("{action} failed: {e}"),
    }
}
