# Akkoro — post-quantum, low-latency L3 tunnel (WireGuard-class clone)

**Codename:** Akkoro · **Protocol:** `Akkoro v1` · **Lab-only** research artifact.

A from-scratch Rust clone of WireGuard's model (UDP + TUN L3 tunnel) with three
upgrades over WireGuard:

| Goal | Akkoro | WireGuard |
|---|---|---|
| **More secure** | Hybrid **X25519 + ML-KEM-768** key exchange (quantum-resistant) + **PQ forward secrecy** · **Rust** (memory-safe, no C memory-corruption class) · per-key domain separation | X25519 only (quantum-broken) · C kernel module |
| **Lower latency** | **AEGIS-128L** AEAD (≈3–5× faster than ChaCha20-Poly1305 on AES-NI/ARM crypto) · **batched UDP I/O** (`recvmmsg`/`sendmmsg` + TUN `poll`, amortizes the 2-syscall-per-packet cost) · **GSO/GRO offload** (virtio_net_hdr, kernel coalesces/segments large packets) · 1-RTT handshake | ChaCha20-Poly1305 |
| **Offline / local IP** | Direct RFC1918 UDP endpoints, static peer config + optional **mDNS discovery** (no DNS/STUN/TURN) | Same, but without PQ |

> **Honest caveats:** the "more secure" claim is about *design properties* (PQ +
> memory safety) — Akkoro is new and unaudited, so it lacks WireGuard's 7+ years
> of external scrutiny; a formal audit is required before trusting it with
> production traffic. The "lower latency" claim is about the *cipher and data
> path*: batched I/O amortizes the per-packet syscall overhead, and GSO/GRO
> offload lets the kernel coalesce/segment super-packets across the tunnel
> (Docker: ~0.16 ms avg ping-flood RTT, 0% loss; ~4.5 Gbps TCP through the
> tunnel), but as a userspace daemon it still cannot beat kernel WireGuard's
> in-kernel zero-copy forwarding; kernel parity requires the deferred AF_XDP path.

## Status

- ✅ Crypto core: handshake, session keys, replay window, data AEAD — **tested**
  (`cargo test` — 11 tests).
- ✅ **Post-quantum forward secrecy**: ephemeral ML-KEM-768 in the response
  (hybrid X25519+ML-KEM is mixed into every session key).
- ✅ **Cookie anti-DoS** (MAC1/MAC2, BLAKE3 + AEGIS-128L) + **handshake
  replay/flood enforcement** (20 ms rate limit + monotonic TAI64N timestamp).
- ✅ **Ingress reverse-path check** (decrypted source IP must be in the peer's
  `allowed_ips`).
- ✅ **Time-based rekey/reject** (120 s / 180 s) + counter rekey (2^60) +
  **padding** (16-byte multiple, anti traffic-analysis).
- ✅ **Cipher fallback**: `aegis128l` (default) or `chacha20poly1305` via config.
- ✅ **mDNS peer discovery** for offline LAN (config `mdns = true`) — verified in
  Docker (peer endpoint auto-populated, no static endpoint).
- ✅ **Batched UDP I/O** (`recvmmsg`/`sendmmsg` + poll, 64-datagram batches).
- ✅ **GSO/GRO offload** (`IFF_VNET_HDR` + `TUNSETOFFLOAD` on Linux): the
  10-byte virtio_net_hdr is preserved end-to-end so the kernel coalesces/segments
  super-packets across the tunnel — verified in Docker (~4.5 Gbps TCP).
- ✅ CLI: `keygen`, `pubkey`, `run`.
- ✅ Daemon: UDP + TUN data path (Linux + macOS via `tun` crate).
- ⚠️ TUN + mDNS paths require **root** / a real 2-host LAN to exercise end-to-end;
  the crypto path is fully verified by the integration tests.

## Build & test

```sh
cargo build --release
cargo test
```

## Usage (two LAN hosts)

### 1. Generate identities (both hosts)

```sh
./target/release/akkoro keygen --out identity.toml
./target/release/akkoro pubkey --identity identity.toml
# prints dh_public and kem_ek
```

### 2. Write `akkoro.toml`

Host A (`10.9.0.1`):

```toml
listen = "0.0.0.0:51820"
interface = "akkoro0"
address = "10.9.0.1/24"
mtu = 1420
identity_file = "identity.toml"
psk = ""                      # optional shared hex PSK
cipher = "aegis128l"          # or "chacha20poly1305"
cookie_required = false       # true = require MAC2 cookie (anti-DoS)
mdns = false                  # true = auto-discover peers on the LAN

[[peers]]
name = "host-b"
endpoint = "192.168.8.20:51820"     # peer's LAN IP (no DNS)
dh_pub = "<host-b dh_public>"
ek = "<host-b kem_ek>"
allowed_ips = ["10.9.0.2/32"]
```

Host B is the mirror image (`10.9.0.2`, endpoint `192.168.8.10:51820`,
`allowed_ips = ["10.9.0.1/32"]`, peer keys = host A).

### 3. Run (as root, TUN needs CAP_NET_ADMIN)

```sh
sudo ./target/release/akkoro run --config akkoro.toml
```

Ping the peer's inner IP to verify: `ping 10.9.0.2`.

## Test with Docker (2-node, no physical LAN needed)

Build the image and run two containers that tunnel to each other over a Docker
bridge network (needs Docker Desktop + `--cap-add NET_ADMIN --device /dev/net/tun`):

```sh
docker build -t akkoro .

# 1. generate identities + configs for both nodes (host binary, hex is portable)
./target/release/akkoro keygen --out a-id.toml
./target/release/akkoro keygen --out b-id.toml
# ... write a.toml / b.toml (10.9.0.1/10.9.0.2, peer endpoint = container IP)

docker network create --subnet=172.30.0.0/24 akkoro-test
docker run -d --name akkoro-a --network akkoro-test --ip 172.30.0.10 \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$PWD/a-id.toml:/etc/akkoro/identity.toml:ro" -v "$PWD/a.toml:/etc/akkoro/akkoro.toml:ro" \
  akkoro run --config /etc/akkoro/akkoro.toml
docker run -d --name akkoro-b --network akkoro-test --ip 172.30.0.11 \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$PWD/b-id.toml:/etc/akkoro/identity.toml:ro" -v "$PWD/b.toml:/etc/akkoro/akkoro.toml:ro" \
  akkoro run --config /etc/akkoro/akkoro.toml

docker exec akkoro-a ping -c 4 10.9.0.2   # encrypted tunnel A -> B
```

Verified end-to-end: AEGIS-128L and ChaCha20-Poly1305 ciphers, cookie anti-DoS
(MAC1/MAC2) mode, the hybrid PQ handshake, and mDNS peer discovery all carry real
ICMP through the tunnel (~1–2.5 ms over the bridge).

## Layout

| File | Purpose |
|---|---|
| [src/crypto.rs](src/crypto.rs) | X25519, ML-KEM-768, BLAKE3 transcript, HKDF, AEGIS-128L + ChaCha20-Poly1305 AEAD |
| [src/protocol.rs](src/protocol.rs) | Wire message formats + (de)serialization |
| [src/handshake.rs](src/handshake.rs) | 1-RTT hybrid handshake + PQ forward secrecy |
| [src/session.rs](src/session.rs) | Session keys, RFC6479 replay window, data AEAD + padding |
| [src/cookie.rs](src/cookie.rs) | Cookie anti-DoS (MAC1/MAC2) |
| [src/route.rs](src/route.rs) | CIDR matching + IP packet helpers |
| [src/discovery.rs](src/discovery.rs) | mDNS peer discovery |
| [src/config.rs](src/config.rs) | TOML config + identity files + hex helpers |
| [src/tun.rs](src/tun.rs) | TUN device (Linux + macOS) |
| [src/daemon.rs](src/daemon.rs) | UDP + TUN data path (2 threads) |
| [src/main.rs](src/main.rs) | CLI |
| [tests/loopback.rs](tests/loopback.rs) | End-to-end crypto integration test |

Full protocol spec: [DESIGN.md](DESIGN.md).
