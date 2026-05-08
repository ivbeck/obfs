//! Drive `pump_outbound` and `pump_inbound` against each other in-process.
//! No TUN, no TLS, no socket — just `tokio::io::duplex` standing in for
//! the network and a pair of mpsc channels playing the role of WebSocket.
//! If the pumps survive the duplex meatgrinder, they'll survive a real
//! WebSocket too.

use std::sync::Arc;

use anyhow::Result;
use futures_util::stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{self, Message};
use vpn_obfs_common::crypto::{EphemeralKeypair, SessionCipher};
use vpn_obfs_common::frame::{Frame, TYPE_DATA, TYPE_KEEPALIVE};
use vpn_obfs_common::protocol::{pump_inbound, pump_outbound};

fn paired_ciphers(psk: &[u8]) -> (Arc<SessionCipher>, Arc<SessionCipher>) {
    let alice = EphemeralKeypair::generate();
    let bob = EphemeralKeypair::generate();
    let a_pub = alice.public;
    let b_pub = bob.public;
    let s_ab = alice.diffie_hellman(&b_pub);
    let s_ba = bob.diffie_hellman(&a_pub);
    (
        Arc::new(SessionCipher::new(&s_ab, psk, true)),
        Arc::new(SessionCipher::new(&s_ba, psk, false)),
    )
}

#[tokio::test]
async fn t_pump_outbound_then_inbound_via_duplex() {
    // Setup: a TUN on each side modeled as a duplex pair, and a
    // futures-channel mpsc as the "WebSocket" carrying Messages.
    let (init_cipher, resp_cipher) = paired_ciphers(b"pump");

    let (mut client_tun_a, client_tun_b) = tokio::io::duplex(8192);
    let (server_tun_a, mut server_tun_b) = tokio::io::duplex(8192);

    let (ws_tx, ws_rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    let sink_out = Box::pin(futures_util::sink::unfold(
        ws_tx,
        |tx, msg: Message| async move {
            tx.send(msg)
                .map_err(|_| tungstenite::Error::ConnectionClosed)?;
            Ok::<_, tungstenite::Error>(tx)
        },
    ));
    let stream_in = futures_util::StreamExt::map(
        tokio_stream::wrappers::UnboundedReceiverStream::new(ws_rx),
        Ok::<_, tungstenite::Error>,
    );

    let outbound = tokio::spawn(pump_outbound(client_tun_b, sink_out, init_cipher));
    let inbound = tokio::spawn(pump_inbound(stream_in, server_tun_a, resp_cipher));

    let payload = b"who put the bytes in the pipeline";
    client_tun_a.write_all(payload).await.unwrap();
    client_tun_a.shutdown().await.unwrap();
    drop(client_tun_a);

    let mut got = vec![0u8; payload.len()];
    server_tun_b.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    let _ = outbound.await;
    let _ = inbound.await;
}

#[tokio::test]
async fn t_pump_inbound_drops_garbage_keeps_running() {
    // Toss random bytes at pump_inbound; it must shrug them off and exit cleanly.
    let (_init_cipher, resp_cipher) = paired_ciphers(b"x");
    let (server_tun_a, mut server_tun_b) = tokio::io::duplex(4096);

    let garbage = Message::Binary(vec![0xFFu8; 64]);
    let stream = stream::iter(vec![Ok::<_, tungstenite::Error>(garbage)]);

    let task = tokio::spawn(pump_inbound(stream, server_tun_a, resp_cipher));
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .expect("pump deadlocked")
        .expect("join")
        .expect("pump errored");

    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        server_tun_b.read(&mut buf),
    )
    .await
    .map(|r| r.unwrap_or(0))
    .unwrap_or(0);
    assert_eq!(n, 0, "garbage produced output: {n} bytes");
}

#[tokio::test]
async fn t_pump_inbound_handles_keepalive_then_data() -> Result<()> {
    let (init_cipher, resp_cipher) = paired_ciphers(b"k");
    let (server_tun_a, mut server_tun_b) = tokio::io::duplex(4096);

    let ka_wire = Frame::encode(TYPE_KEEPALIVE, &[]);
    let payload = b"after-keepalive";
    let ct = init_cipher.encrypt(payload);
    let data_wire = Frame::encode(TYPE_DATA, &ct);

    let stream = stream::iter(vec![
        Ok::<_, tungstenite::Error>(Message::Binary(ka_wire)),
        Ok::<_, tungstenite::Error>(Message::Binary(data_wire)),
    ]);

    let task = tokio::spawn(pump_inbound(stream, server_tun_a, resp_cipher));

    let mut got = vec![0u8; payload.len()];
    server_tun_b.read_exact(&mut got).await?;
    assert_eq!(got, payload);

    drop(server_tun_b);
    let _ = task.await;
    Ok(())
}
