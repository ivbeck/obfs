# vpn-obfs Protocol Specification

## 1. Purpose

`vpn-obfs` tunnels IP packets over a TLS + WebSocket channel and makes traffic resemble normal HTTPS API traffic.

The protocol has four layers:

1. TLS transport (`wss://`)
2. WebSocket message transport
3. `vpn-obfs` frame format
4. Encrypted payload carrying raw IP packets from a TUN device

## 2. Roles

- Client: initiates TCP, TLS, and WebSocket handshake
- Server: accepts connections and forwards traffic between WebSocket and TUN

Both sides derive symmetric session keys from:

- X25519 ECDH shared secret
- pre-shared key (PSK), mixed with HKDF

## 3. Connection Establishment

### 3.1 Transport setup

1. Client opens TCP to `server:port`
2. Client performs TLS handshake (SNI set by client configuration)
3. Client sends HTTP WebSocket upgrade request to path `/api/v1/stream`

### 3.2 WebSocket upgrade headers

Client request includes:

- `X-VPN-Key`: base64 encoded 32-byte X25519 public key
- `X-VPN-Auth`: 64-char lowercase hex token derived from PSK and client public key

Server `101 Switching Protocols` response includes:

- `X-VPN-Key`: base64 encoded 32-byte X25519 public key
- `X-VPN-Proto: 1`

### 3.3 Authentication token

Client computes:

- `psk_key = HKDF-SHA256(salt=None, ikm=psk, info="vpn-obfs/psk", len=32)`
- `auth = HKDF-SHA256(salt=psk_key, ikm=client_public_key, info="vpn-obfs/auth-token", len=32)`
- `X-VPN-Auth = hex(auth)`

Current server behavior validates presence and expected length/shape of `X-VPN-Auth` before proceeding.

## 4. Key Agreement and Session Keys

After key exchange:

1. Client parses server `X-VPN-Key`
2. Server parses client `X-VPN-Key`
3. Both compute `shared_secret = X25519(own_secret, peer_public)`
4. Both derive two 32-byte stream keys with HKDF-SHA256:
   - `key_a = HKDF(shared_secret, salt=psk_key, info="vpn-obfs/stream-a/v1", len=32)`
   - `key_b = HKDF(shared_secret, salt=psk_key, info="vpn-obfs/stream-b/v1", len=32)`

Direction assignment:

- Client (initiator): send = `key_a`, recv = `key_b`
- Server (responder): send = `key_b`, recv = `key_a`

## 5. Payload Encryption

Encryption algorithm: ChaCha20-Poly1305.

For each outbound packet:

1. Generate random 12-byte nonce
2. Encrypt plaintext (IP packet) with side-specific send key
3. Transmit blob: `nonce (12 bytes) || ciphertext_with_tag`

On receive:

1. Split first 12 bytes as nonce
2. Decrypt remainder with side-specific recv key
3. Authentication failure causes packet drop

## 6. Frame Format

Each WebSocket binary message contains one `vpn-obfs` frame:

```
u16  obfs_prefix_len   (little-endian)
u8[] obfs_prefix       (fake HTTP-like headers)
u8   frame_type
u32  payload_len       (little-endian)
u8[] payload           (encrypted blob: nonce || ciphertext+tag)
u16  padding_len       (little-endian)
u8[] padding           (random bytes)
```

`frame_type` values:

- `0x01`: DATA
- `0x02`: KEEPALIVE
- `0x03`: CLOSE

Unknown frame types are ignored.

## 7. Obfuscation Prefix and Padding

Each frame carries a generated HTTP-like header block in `obfs_prefix`:

- method/path like API traffic
- common headers (`Host`, `User-Agent`, `Content-Type`, etc.)
- random trace/request identifiers
- jittered timestamp
- random opaque metadata field

Padding is added so packet sizes cluster around common bucket sizes:

- 512, 1024, 1280, 1500, 2048, 4096 bytes
- plus a small random jitter

## 8. Data Plane

### 8.1 Client to server

1. Read packet from client TUN
2. Encrypt packet
3. Wrap in DATA frame
4. Send as WebSocket binary message

### 8.2 Server to client

1. Read packet from server TUN
2. Encrypt packet
3. Wrap in DATA frame
4. Send as WebSocket binary message

### 8.3 Receive path

1. Read WebSocket binary message
2. Decode frame
3. If DATA: decrypt payload and write to local TUN
4. If KEEPALIVE: ignore
5. If CLOSE: terminate session

## 9. Error Handling

- Truncated or malformed frames are dropped
- Decryption failures are dropped
- WebSocket close or transport failure ends session

## 10. Versioning

`X-VPN-Proto: 1` indicates protocol version 1 semantics for handshake and frame layout.

