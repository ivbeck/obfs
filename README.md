# vpn-obfs — Obfuscated VPN over HTTPS/WebSocket

Traffic from this VPN is indistinguishable from normal HTTPS + WebSocket
traffic to a passive observer or Deep Packet Inspection system.

---

## Architecture

```
 CLIENT                                INTERNET
 ┌────────────────────────────────┐
 │ Applications                   │
 │      ↕ (normal IP traffic)     │
 │ TUN interface (10.8.0.2/24)    │
 │      ↕                         │
 │ ChaCha20-Poly1305 encryption   │
 │      ↕                         │
 │ Fake HTTP header prefix        │  TLS (looks like HTTPS)
 │      ↕                         │ ══════════════════════ SERVER
 │ WebSocket frame                │ →  ┌──────────────────────┐
 │      ↕                         │    │ TUN (10.8.0.1/24)    │
 │ TLS 1.3 transport (port 443)   │    │ IP forward + NAT     │
 └────────────────────────────────┘    └──────────────────────┘
```

### Obfuscation layers

| Layer | Technique | Hides |
|-------|-----------|-------|
| TLS 1.3 | Legitimate certificate + SNI | Traffic content |
| WebSocket upgrade | Standard HTTP `Upgrade:` request | Tunnel protocol |
| Fake HTTP headers | Realistic CDN/API headers on every frame | Frame boundaries |
| ChaCha20-Poly1305 | Per-direction AEAD encryption | Payload semantics |
| Packet padding | Size-bucketing to MTU boundaries | Payload length |
| Timestamp jitter | ±2 s random offset on header timestamps | Timing correlation |
| X25519 ECDH | Key exchange hidden in WebSocket headers | Key material |

### Key exchange

```
Client                                    Server
  │                                           │
  │── HTTP GET /api/v1/stream ───────────────→│
  │   Upgrade: websocket                      │
  │   X-VPN-Key: <client_x25519_pubkey_b64>  │
  │   X-VPN-Auth: <HKDF(PSK, pubkey) hex>    │
  │                                           │
  │←─ 101 Switching Protocols ───────────────│
  │   X-VPN-Key: <server_x25519_pubkey_b64>  │
  │                                           │
  ╔═══════════════════════════════════════════╗
  ║  shared = X25519(client_secret, server_pub)
  ║  send_key, recv_key = HKDF(shared, PSK)  ║
  ╚═══════════════════════════════════════════╝
```

Both sides derive independent send/recv keys via HKDF-SHA256 so a
compromised receive key cannot forge traffic in the other direction.
The PSK acts as a shared secret mixed into HKDF, ensuring only parties
who know the PSK can complete the handshake.

---

## Build

```bash
# Prerequisites: Rust 1.77+, root or CAP_NET_ADMIN at runtime
cargo build --release
# Binaries:
#   ./target/release/vpn-obfs-server
#   ./target/release/vpn-obfs-client
#   ./target/release/vpn-obfs-gui
```

---

## Usage

### Server

```bash
# Auto-generate a self-signed TLS cert (prints fingerprint for pinning)
sudo ./vpn-obfs-server \
    --listen 0.0.0.0:443 \
    --psk "choose-a-long-random-passphrase" \
    --domain "cdn.cloudflare.com"

# Use your own Let's Encrypt / real certificate
sudo ./vpn-obfs-server \
    --listen 0.0.0.0:443 \
    --psk "choose-a-long-random-passphrase" \
    --cert /etc/letsencrypt/live/example.com/fullchain.pem \
    --key  /etc/letsencrypt/live/example.com/privkey.pem
```

The server automatically configures IPv4 forwarding and NAT for the VPN
subnet using OS-specific system commands (Linux/macOS/Windows).

### Client

```bash
sudo ./vpn-obfs-client \
    --server your.server.com:443 \
    --psk "choose-a-long-random-passphrase" \
    --sni "cdn.cloudflare.com"   # must match server's cert CN

# With self-signed cert (skip verify — use only on trusted networks)
sudo ./vpn-obfs-client \
    --server 1.2.3.4:443 \
    --psk "choose-a-long-random-passphrase" \
    --no-verify
```

The client automatically adds OS routing rules so all traffic flows
through the tunnel (except the VPN server's IP, which stays direct).

### GUI client (desktop)

```bash
# Linux / macOS
sudo ./vpn-obfs-gui

# Windows (run terminal as Administrator)
.\vpn-obfs-gui.exe
```

The GUI wraps the same client engine and connection parameters as the CLI.
Use it to configure server, PSK, IP, gateway, SNI, and TLS verification.

### Environment variables

```bash
export VPN_PSK="choose-a-long-random-passphrase"
sudo vpn-obfs-server --listen 0.0.0.0:443
```

---

## Security notes

- **PSK length**: Use at least 20 random characters. The PSK is the only
  authentication factor besides the TLS certificate.
- **Self-signed cert**: Suitable for dedicated private VPN servers. Use
  `--no-verify` only in controlled environments — it is vulnerable to MITM.
- **Real cert (recommended)**: Obtain one via Let's Encrypt on a domain you
  control. This makes TLS fingerprinting indistinguishable from any other
  HTTPS site.
- **Port 443**: Running on 443 means the traffic profile matches ordinary
  HTTPS and is unlikely to be singled out by traffic shapers.
- **MTU**: The TUN MTU is set to 1500; encapsulation overhead (TLS + WS
  framing + obfs prefix) means effective payload MTU is ~1300 bytes.
  PMTUD will handle this automatically for TCP. For UDP-heavy workloads
  you may want to lower the client-side TUN MTU to 1280.
- **Privilege handling**: `vpn-obfs-client`, `vpn-obfs-server`, and
  `vpn-obfs-gui` try to auto-elevate privileges at startup. If elevation
  is denied/unavailable, they terminate with a clear message explaining
  that TUN creation and route/NAT changes require root/admin rights.

---

## Platform support

| Platform | Status |
|----------|--------|
| Linux    | ✅ Full support (TUN + route setup + iptables NAT) |
| macOS    | ✅ Supported (TUN + route setup + `pfctl` NAT) |
| Windows  | ✅ Supported (TUN + route setup + PowerShell NAT) |

> Note: all platforms require elevated privileges for creating TUN devices and
> changing system routing/NAT state.

---

## Project layout

```
common/src/
├── crypto.rs    X25519 ECDH + HKDF + ChaCha20-Poly1305
├── obfs.rs      Fake HTTP header generation + packet padding
├── frame.rs     Wire frame codec (prefix | type | payload | padding)
└── tls_cfg.rs   rustls ServerConfig / ClientConfig builders + rcgen

server/src/
├── main.rs      server CLI entry point
└── server.rs    TLS acceptor → WebSocket → TUN forwarding

client/src/
├── main.rs      client CLI entry point
└── client.rs    TLS connector → WebSocket → TUN + routing setup

gui/src/
└── main.rs      desktop GUI for the client
```

## Source code

- GitHub: [ivbeck/obfs](https://github.com/ivbeck/obfs)
