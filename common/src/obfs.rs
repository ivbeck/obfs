//! Obfuscation layer
//!
//! Every VPN frame is prefixed with realistic-looking HTTP/1.1 headers
//! so that a passive DPI device sees what appears to be ordinary HTTP
//! traffic riding inside the WebSocket stream.
//!
//! Additionally, random padding is appended to each frame to normalise
//! payload sizes and frustrate traffic-analysis classifiers that rely
//! on packet-length fingerprints.

use base64::{engine::general_purpose::STANDARD, Engine};
use rand::Rng;
use uuid::Uuid;

static CDN_HOSTS: &[&str] = &[
    "cdn.cloudflare.com",
    "cdn.jsdelivr.net",
    "ajax.googleapis.com",
    "fonts.gstatic.com",
    "storage.googleapis.com",
    "assets.akamaized.net",
    "media.fastly.net",
    "s3.us-east-1.amazonaws.com",
    "static.cloudfront.net",
    "edge.azureedge.net",
    "api.segment.io",
    "events.launchdarkly.com",
];

static API_PATHS: &[&str] = &[
    "/api/v1/stream",
    "/api/v2/events",
    "/ws/live",
    "/push/v3",
    "/realtime/updates",
    "/api/graphql",
    "/v1/subscribe",
    "/stream/socket",
    "/metrics/ingest",
    "/sdk/events",
];

static CONTENT_TYPES: &[&str] = &[
    "application/octet-stream",
    "application/x-protobuf",
    "application/grpc-web+proto",
    "application/msgpack",
    "application/x-binary",
];

static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "okhttp/4.12.0",
    "Dart/3.3 (dart:io)",
    "grpc-go/1.63.0",
];

/// Generate a fake HTTP/1.1 request header block (ending with \r\n\r\n)
/// to prepend to each VPN frame.  The headers look like a CDN API call.
pub fn generate_prefix(payload_len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let host = CDN_HOSTS[rng.gen_range(0..CDN_HOSTS.len())];
    let path = API_PATHS[rng.gen_range(0..API_PATHS.len())];
    let ct = CONTENT_TYPES[rng.gen_range(0..CONTENT_TYPES.len())];
    let ua = USER_AGENTS[rng.gen_range(0..USER_AGENTS.len())];

    // random opaque blobs for extension headers - gives entropy to the prefix
    let blob_len: usize = rng.gen_range(8..48);
    let mut blob = vec![0u8; blob_len];
    rng.fill(&mut blob[..]);
    let blob_b64 = STANDARD.encode(&blob);

    // monotonic-ish timestamp (Unix seconds, slightly jittered)
    let ts = unix_ts_jittered();

    let header = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: {ct}\r\n\
         Content-Length: {payload_len}\r\n\
         User-Agent: {ua}\r\n\
         X-Request-ID: {}\r\n\
         X-Trace-ID: {}\r\n\
         X-Timestamp: {ts}\r\n\
         Cache-Control: no-cache, no-store\r\n\
         X-Data: {blob_b64}\r\n\
         \r\n",
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    header.into_bytes()
}

/// Skip past the fake HTTP header at the start of a received frame.
/// Returns a sub-slice that begins immediately after the "\r\n\r\n" terminator.
/// Falls back to the full slice if no marker is found (should not happen).
#[allow(dead_code)]
pub fn strip_prefix(data: &[u8]) -> &[u8] {
    const MARKER: &[u8] = b"\r\n\r\n";
    if let Some(pos) = data.windows(4).position(|w| w == MARKER) {
        &data[pos + 4..]
    } else {
        data // malformed - caller will see auth failure on decrypt
    }
}

/// Round up `current_len` to a "bucketed" size and return how many bytes
/// of random padding to append.  Buckets: 512 / 1024 / 1280 / 1500 bytes
/// (chosen to mimic common MTU-aligned traffic).
pub fn padding_needed(current_len: usize) -> usize {
    const BUCKETS: &[usize] = &[512, 1024, 1280, 1500, 2048, 4096];
    let mut rng = rand::thread_rng();

    for &b in BUCKETS {
        if current_len < b {
            // add a small extra random delta so not every packet hits the
            // exact bucket boundary (avoids its own fingerprint)
            let jitter: usize = rng.gen_range(0..32);
            return (b - current_len) + jitter;
        }
    }
    // Larger than all buckets - just add a small random tail
    rng.gen_range(16..64)
}

pub fn random_padding(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen()).collect()
}

fn unix_ts_jittered() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut rng = rand::thread_rng();
    let base = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // +/- 2 s jitter defeats exact timing correlation
    let delta: i64 = rng.gen_range(-2..=2);
    (base as i64 + delta).max(0) as u64
}
