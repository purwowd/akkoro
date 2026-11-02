# Akkoro v1 — protocol design

## 1. Security goals & honest properties

| Property | Status |
|---|---|
| Confidentiality + integrity | AEGIS-128L AEAD (or ChaCha20-Poly1305 fallback) |
| Authentication | Static X25519 + static ML-KEM-768 (mutual, via encrypted static keys + decapsulation) |
| Forward secrecy | Classical PFS via ephemeral X25519 **and** PQ PFS via an ephemeral ML-KEM-768 in the response |
| **Post-quantum** | Hybrid X25519 + ML-KEM-768 mixed into every session secret; PQ forward secrecy provided (both handshake secrets are ephemeral) |
| Replay protection | RFC6479 8192-bit window + monotonic TAI64N timestamps + handshake flood rate limit |
| Anti-DoS | Cookie mechanism (MAC1/MAC2) |
| Memory safety | Rust (no unsafe in crypto path) |

## 2. Primitives

- X25519 (x25519-dalek)
- ML-KEM-768 (RustCrypto `ml-kem`) — ciphertext 1088 B, ek 1184 B, shared secret 32 B
- BLAKE3 — transcript hash
- HKDF-SHA256 — key derivation (salt = `b"Akkoro v1"`)
- AEGIS-128L — AEAD (16-byte key, 16-byte nonce, 16-byte tag)

## 3. Messages (UDP, little-endian)

```
Initiation (2420 B):
  type=1(u32) | sender_index(u32) | eph_dh(32) | kem_ct(1088)
  | enc_static(1232 = 32+1184+16) | enc_ts(28 = 12+16) | macs(32)

Response (1180 B):
  type=2(u32) | sender_index(u32) | receiver_index(u32) | eph_dh(32)
  | kem_ct2(1088) | enc_empty(16) | macs(32)

Cookie (56 B):
  type=3(u32) | receiver_index(u32) | nonce(16) | encrypted_cookie(32)

Data (>= 32 B overhead):
  type=4(u32) | receiver_index(u32) | counter(u64) | AEAD(inner_ip || padding)
```

## 4. Handshake (1-RTT)

```
shared_secret ss = X25519(eph_priv, peer_static_dh)   # classical DH (ephemeral)
                 || ML-KEM_decaps(kem_ct)             # post-quantum KEM (static ek)
                 || psk                                # optional

k1 = KDF(ss, "akkoro-hs-key-1", 16)   # seal initiator static identity
k2 = KDF(ss, "akkoro-hs-key-2", 16)   # seal timestamp
k3 = KDF(ss, "akkoro-hs-key-3", 16)   # seal response empty

response adds: kem_ct2 = ML-KEM_encaps(initiator_static_ek)
final session secret = ss || ML-KEM_decaps(kem_ct2)   # PQ forward secrecy
```

Three distinct keys with a fixed zero nonce ⇒ **no nonce reuse**.

Transcript (both sides hash identical bytes):

```
t = BLAKE3(NAME || eph_dh || kem_ct || enc_static || enc_ts || eph_dh_r || kem_ct2 || enc_empty)
```

Session keys bind the full transcript:

```
master  = KDF(ss_final || t, "akkoro-master", 32)
send    = KDF(master, "akkoro-send", 32)   # initiator: send=A, recv=B
recv    = KDF(master, "akkoro-recv", 16)   # responder:  send=B, recv=A
```

## 5. Data path

- Nonce = `LE64(counter) || 0^8` (16 bytes), unique per (key, counter).
- `REKEY_AFTER_MESSAGES = 2^60`, `REJECT_AFTER_MESSAGES = 2^64 − 8129`.
- Replay window: 8192-bit RFC6479 bitmap.
- **Ingress reverse-path check**: decrypted packet source IP must be within the
  sending peer's `allowed_ips` (anti inner-IP spoofing).
- **Handshake replay/flood**: monotonic TAI64N timestamp (quantized to 16.7 ms)
  + 20 ms per-peer initiation rate limit.

## 6. Known gaps / next steps (lab roadmap)

Implemented since v0.1: **PQ forward secrecy** (ephemeral ML-KEM in the response),
**cookie anti-DoS** (MAC1/MAC2), **rekey timers** (120 s/180 s), **mDNS discovery**,
**padding**, and **ChaCha20-Poly1305 fallback**.

Remaining:

1. **AF_XDP fast path** (Linux-only) for sub-100 µs forwarding — the data path is
   already split so a zero-copy backend can replace the UDP socket. Deferred:
   Linux-specific and not exercisable in this lab without a dedicated NIC setup.
2. **macOS TUN (utun) end-to-end validation** — requires `sudo` on macOS; the
   Linux TUN + UDP + mDNS paths are already verified end-to-end in Docker.
3. **Full PQ handshake (e.g., X-Wing)** — the current design is a hybrid
   (classical X25519 PFS + PQ via static KEM + ephemeral KEM); a fully
   PQ-composed handshake would drop the classical component.
