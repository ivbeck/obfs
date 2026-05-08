//! End-to-end pipeline: duplex stream as TCP, real rustls TLS handshake,
//! real tungstenite WebSocket upgrade, real auth header validation, real
//! ChaCha20-Poly1305 frames running through both pumps.  No TUN, no real
//! socket — but every other byte on the wire is the same as production.
//!
//! If this test passes, you have working crypto + protocol + auth.  If
//! it doesn't, find out which layer broke before opening prod logs.

use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use subtle::ConstantTimeEq;
use tokio::io::AsyncReadExt;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::{
    accept_hdr_async, client_async_with_config,
    tungstenite::{
        client::IntoClientRequest,
        handshake::server::{Request, Response},
        Message,
    },
};
use vpn_obfs_common::crypto::{derive_auth_token, psk_bytes, EphemeralKeypair, SessionCipher};
use vpn_obfs_common::protocol::pump_inbound;
use vpn_obfs_common::tls_cfg::{client_config_pinned, make_acceptor, server_config_self_signed};
use x25519_dalek::PublicKey;

const DOMAIN: &str = "test.local";

struct ServerOutcome {
    cipher: Arc<SessionCipher>,
    ws_stream: tokio_tungstenite::WebSocketStream<
        tokio_rustls::server::TlsStream<tokio::io::DuplexStream>,
    >,
}

#[allow(clippy::result_large_err)]
async fn server_handshake(
    tls: tokio_rustls::server::TlsStream<tokio::io::DuplexStream>,
    psk_key: Arc<[u8; 32]>,
) -> Result<ServerOutcome> {
    let server_kp = EphemeralKeypair::generate();
    let server_pub_b64 = STANDARD.encode(server_kp.public.as_bytes());

    let client_pub_bytes: Arc<std::sync::Mutex<Option<Vec<u8>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let auth_token: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));

    let cpb = client_pub_bytes.clone();
    let auth = auth_token.clone();
    let spub = server_pub_b64.clone();

    let ws = accept_hdr_async(tls, move |req: &Request, mut res: Response| {
        if let Some(k) = req.headers().get("X-VPN-Key") {
            *cpb.lock().unwrap() = Some(k.as_bytes().to_vec());
        }
        if let Some(a) = req.headers().get("X-VPN-Auth") {
            if let Ok(s) = a.to_str() {
                *auth.lock().unwrap() = Some(s.to_owned());
            }
        }
        res.headers_mut().insert("X-VPN-Key", spub.parse().unwrap());
        res.headers_mut()
            .insert("X-VPN-Proto", "1".parse().unwrap());
        Ok(res)
    })
    .await
    .map_err(|e| anyhow!("ws upgrade: {e}"))?;

    let provided = auth_token
        .lock()
        .unwrap()
        .clone()
        .context("missing X-VPN-Auth")?;

    let cpr = client_pub_bytes
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|b| STANDARD.decode(b).ok())
        .context("missing/invalid X-VPN-Key")?;
    if cpr.len() != 32 {
        bail!("bad pubkey length");
    }
    let client_pub_arr: [u8; 32] = cpr.try_into().unwrap();
    let client_pub = PublicKey::from(client_pub_arr);

    let expected = derive_auth_token(psk_key.as_ref(), &client_pub_arr);
    if expected.as_bytes().ct_eq(provided.as_bytes()).unwrap_u8() != 1 {
        bail!("invalid X-VPN-Auth");
    }

    let shared = server_kp.diffie_hellman(&client_pub);
    let cipher = Arc::new(SessionCipher::new(&shared, psk_key.as_ref(), false));
    Ok(ServerOutcome {
        cipher,
        ws_stream: ws,
    })
}

async fn client_handshake(
    tcp: tokio::io::DuplexStream,
    sni: &str,
    psk: &[u8; 32],
    override_auth: Option<&str>,
    pinned_der: Vec<u8>,
) -> Result<(
    Arc<SessionCipher>,
    tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::io::DuplexStream>>,
)> {
    let client_cfg = client_config_pinned(pinned_der)?;
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned())?;
    let tls = connector.connect(server_name, tcp).await?;

    let kp = EphemeralKeypair::generate();
    let pub_b64 = STANDARD.encode(kp.public.as_bytes());
    let auth_token = override_auth
        .map(str::to_owned)
        .unwrap_or_else(|| derive_auth_token(psk, kp.public.as_bytes()));

    let url = format!("wss://{sni}/api/v1/stream");
    let mut req = url.into_client_request().context("build req")?;
    let h = req.headers_mut();
    h.insert("Host", sni.parse()?);
    h.insert("X-VPN-Key", pub_b64.parse()?);
    h.insert("X-VPN-Auth", auth_token.parse()?);

    let (ws, resp) = client_async_with_config(req, tls, None)
        .await
        .context("ws client")?;
    let server_pub_b64 = resp
        .headers()
        .get("X-VPN-Key")
        .and_then(|v| v.to_str().ok())
        .context("server didn't send X-VPN-Key")?;
    let server_pub_raw = STANDARD.decode(server_pub_b64)?;
    if server_pub_raw.len() != 32 {
        bail!("bad server pubkey");
    }
    let arr: [u8; 32] = server_pub_raw.try_into().unwrap();
    let server_pub = PublicKey::from(arr);
    let shared = kp.diffie_hellman(&server_pub);
    Ok((Arc::new(SessionCipher::new(&shared, psk, true)), ws))
}

fn server_acceptor() -> (TlsAcceptor, Vec<u8>) {
    let (cfg, der) = server_config_self_signed(DOMAIN).unwrap();
    (make_acceptor(cfg), der)
}

#[tokio::test]
async fn t_e2e_handshake_and_data_exchange() {
    let (acceptor, der) = server_acceptor();
    let psk_str = "shared-psk";
    let psk_arr = psk_bytes(psk_str);
    let psk_arc: Arc<[u8; 32]> = Arc::new(psk_arr);

    let (s_io, c_io) = tokio::io::duplex(64 * 1024);

    let server_psk = psk_arc.clone();
    let server_task = tokio::spawn(async move {
        let tls = acceptor.accept(s_io).await.expect("server tls");
        server_handshake(tls, server_psk).await
    });

    let (client_cipher, mut client_ws) = client_handshake(c_io, DOMAIN, &psk_arr, None, der)
        .await
        .unwrap();
    let server_outcome = server_task.await.unwrap().unwrap();

    let payload = b"e2e ping over the whole stack";
    let ct = client_cipher.encrypt(payload);
    let wire = vpn_obfs_common::frame::Frame::encode(vpn_obfs_common::frame::TYPE_DATA, &ct);
    use futures_util::SinkExt;
    client_ws.send(Message::Binary(wire)).await.unwrap();

    let (s_tun_a, mut s_tun_b) = tokio::io::duplex(8192);
    let server_cipher = server_outcome.cipher.clone();
    let server_pump = tokio::spawn(pump_inbound(
        server_outcome.ws_stream,
        s_tun_a,
        server_cipher,
    ));

    let mut got = vec![0u8; payload.len()];
    s_tun_b.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    drop(client_ws);
    let _ = server_pump.await;
}

#[tokio::test]
async fn t_e2e_rejects_wrong_auth_token() {
    let (acceptor, der) = server_acceptor();
    let psk_arr = psk_bytes("k");
    let psk_arc: Arc<[u8; 32]> = Arc::new(psk_arr);

    let (s_io, c_io) = tokio::io::duplex(8192);
    let server_psk = psk_arc.clone();
    let server_task = tokio::spawn(async move {
        let tls = acceptor.accept(s_io).await?;
        server_handshake(tls, server_psk).await
    });

    let bogus = "00".repeat(32);
    let res = client_handshake(c_io, DOMAIN, &psk_arr, Some(&bogus), der).await;
    let server_res = server_task.await.unwrap();
    // Either side may report the failure — but server must reject.
    assert!(server_res.is_err(), "server let bogus token through");
    let _ = res;
}

#[tokio::test]
async fn t_e2e_rejects_missing_auth_header() {
    // Build a request manually without X-VPN-Auth and confirm the server bails.
    let (acceptor, der) = server_acceptor();
    let psk_arr = psk_bytes("k");
    let psk_arc: Arc<[u8; 32]> = Arc::new(psk_arr);

    let (s_io, c_io) = tokio::io::duplex(8192);
    let server_psk = psk_arc.clone();
    let server_task = tokio::spawn(async move {
        let tls = acceptor.accept(s_io).await?;
        server_handshake(tls, server_psk).await
    });

    let client_cfg = client_config_pinned(der).unwrap();
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let server_name = rustls::pki_types::ServerName::try_from(DOMAIN.to_owned()).unwrap();
    let tls = connector.connect(server_name, c_io).await.unwrap();

    let kp = EphemeralKeypair::generate();
    let pub_b64 = STANDARD.encode(kp.public.as_bytes());
    let url = format!("wss://{DOMAIN}/api/v1/stream");
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert("Host", DOMAIN.parse().unwrap());
    req.headers_mut()
        .insert("X-VPN-Key", pub_b64.parse().unwrap());
    let _ = client_async_with_config::<_, _>(req, tls, None).await;

    let server_res = server_task.await.unwrap();
    assert!(server_res.is_err(), "server accepted no-auth client");
}

#[tokio::test]
async fn t_e2e_rejects_wrong_psk() {
    let (acceptor, der) = server_acceptor();
    let server_psk_arr = psk_bytes("server-key");
    let client_psk_arr = psk_bytes("totally-different-key");
    let server_psk: Arc<[u8; 32]> = Arc::new(server_psk_arr);

    let (s_io, c_io) = tokio::io::duplex(8192);
    let server_psk_clone = server_psk.clone();
    let server_task = tokio::spawn(async move {
        let tls = acceptor.accept(s_io).await?;
        server_handshake(tls, server_psk_clone).await
    });

    let _ = client_handshake(c_io, DOMAIN, &client_psk_arr, None, der).await;
    let server_res = server_task.await.unwrap();
    assert!(server_res.is_err(), "server accepted client with wrong PSK");
}

#[tokio::test]
async fn t_e2e_data_then_close_frame_terminates_session() {
    let (acceptor, der) = server_acceptor();
    let psk_arr = psk_bytes("end-to-end");
    let psk_arc: Arc<[u8; 32]> = Arc::new(psk_arr);

    let (s_io, c_io) = tokio::io::duplex(64 * 1024);
    let server_psk = psk_arc.clone();
    let server_task = tokio::spawn(async move {
        let tls = acceptor.accept(s_io).await.unwrap();
        server_handshake(tls, server_psk).await.unwrap()
    });

    let (_client_cipher, mut client_ws) = client_handshake(c_io, DOMAIN, &psk_arr, None, der)
        .await
        .unwrap();
    let server_outcome = server_task.await.unwrap();

    let close_wire = vpn_obfs_common::frame::Frame::encode(vpn_obfs_common::frame::TYPE_CLOSE, &[]);
    use futures_util::SinkExt;
    client_ws.send(Message::Binary(close_wire)).await.unwrap();

    let (s_tun_a, mut s_tun_b) = tokio::io::duplex(8192);
    let pump = tokio::spawn(pump_inbound(
        server_outcome.ws_stream,
        s_tun_a,
        server_outcome.cipher.clone(),
    ));

    pump.await.unwrap().unwrap();

    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(std::time::Duration::from_millis(50), s_tun_b.read(&mut buf))
        .await
        .map(|r| r.unwrap_or(0))
        .unwrap_or(0);
    assert_eq!(n, 0, "close frame produced data");
    drop(client_ws);
}
