//! Frame-pump loops shared by client and server.
//!
//! Both endpoints do the same dance: shovel bytes from a TUN-like reader,
//! encrypt them, encode a frame, push into a WebSocket sink — and the
//! mirror operation in the other direction.  Generic over the I/O so
//! tests can wire `tokio::io::duplex` into the same code path that ships.

use std::sync::Arc;

use anyhow::Result;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tracing::warn;

use crate::crypto::SessionCipher;
use crate::frame::{Frame, TYPE_CLOSE, TYPE_DATA, TYPE_KEEPALIVE};

pub const DEFAULT_READ_BUF: usize = 4096;

pub async fn pump_outbound<R, S, E>(
    mut reader: R,
    mut sink: S,
    cipher: Arc<SessionCipher>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    S: Sink<Message, Error = E> + Unpin,
    E: std::fmt::Display + Send + 'static,
{
    let mut buf = vec![0u8; DEFAULT_READ_BUF];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                warn!("pump_outbound read: {e}");
                break;
            }
        };
        let ct = cipher.encrypt(&buf[..n]);
        let wire = Frame::encode(TYPE_DATA, &ct);
        if let Err(e) = sink.send(Message::Binary(wire)).await {
            warn!("pump_outbound send: {e}");
            break;
        }
    }
    let _ = sink.close().await;
    Ok(())
}

pub async fn pump_inbound<St, W, E>(
    mut stream: St,
    mut writer: W,
    cipher: Arc<SessionCipher>,
) -> Result<()>
where
    St: Stream<Item = Result<Message, E>> + Unpin,
    W: AsyncWrite + Unpin,
    E: std::fmt::Display + Send + 'static,
{
    while let Some(msg) = stream.next().await {
        let data = match msg {
            Ok(Message::Binary(b)) => b,
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => continue,
            Ok(Message::Close(_)) => break,
            Ok(_) => continue,
            Err(e) => {
                warn!("pump_inbound recv: {e}");
                break;
            }
        };

        let (ftype, ct) = match Frame::decode(&data) {
            Ok(v) => v,
            Err(e) => {
                warn!("pump_inbound frame decode: {e}");
                continue;
            }
        };

        match ftype {
            TYPE_KEEPALIVE => continue,
            TYPE_CLOSE => break,
            TYPE_DATA => {}
            _ => continue,
        }

        let packet = match cipher.decrypt(&ct) {
            Ok(p) => p,
            Err(e) => {
                warn!("pump_inbound decrypt: {e}");
                continue;
            }
        };

        if let Err(e) = writer.write_all(&packet).await {
            warn!("pump_inbound write: {e}");
            break;
        }
    }
    Ok(())
}
