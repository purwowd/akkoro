//! Wire message formats and (de)serialization for the Akkoro protocol.
//!
//! All integers are little-endian. Messages:
//!
//! - Initiation (type 1):
//!   `type(4) | sender_index(4) | eph_dh(32) | kem_ct(1088) | enc_static(1232) | enc_ts(28) | macs(32)`
//! - Response (type 2):
//!   `type(4) | sender_index(4) | receiver_index(4) | eph_dh(32) | enc_empty(16) | macs(32)`
//! - Cookie (type 3):
//!   `type(4) | receiver_index(4) | nonce(16) | encrypted_cookie(32)`
//! - Data (type 4):
//!   `type(4) | receiver_index(4) | counter(8) | AEAD(inner || padding)`

use crate::crypto::*;

pub const MESSAGE_HANDSHAKE_INITIATION: u32 = 1;
pub const MESSAGE_HANDSHAKE_RESPONSE: u32 = 2;
pub const MESSAGE_HANDSHAKE_COOKIE: u32 = 3;
pub const MESSAGE_DATA: u32 = 4;

pub const COOKIE_LEN: usize = 16;
pub const COOKIE_NONCE_LEN: usize = 16;

pub const INITIATION_LEN: usize = 4 + 4 + X25519_KEY_LEN + MLKEM_CT_LEN + MLKEM_EK_LEN
    + (X25519_KEY_LEN + MLKEM_EK_LEN + AEAD_TAG_LEN)
    + (12 + AEAD_TAG_LEN)
    + (2 * COOKIE_LEN);
pub const RESPONSE_LEN: usize = 4 + 4 + 4 + X25519_KEY_LEN + MLKEM_CT_LEN + AEAD_TAG_LEN + (2 * COOKIE_LEN);
pub const COOKIE_MSG_LEN: usize = 4 + 4 + COOKIE_NONCE_LEN + (COOKIE_LEN + AEAD_TAG_LEN);
pub const DATA_HEADER_LEN: usize = 4 + 4 + 8;
pub const DATA_OVERHEAD: usize = DATA_HEADER_LEN + AEAD_TAG_LEN;

/// Static payload encrypted in the initiation: initiator's X25519 pub + ML-KEM ek.
pub const STATIC_PT_LEN: usize = X25519_KEY_LEN + MLKEM_EK_LEN;
/// Timestamp payload length (TAI64N-style: u64 seconds + u32 nanos).
pub const TIMESTAMP_LEN: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MessageMacs {
    pub mac1: [u8; COOKIE_LEN],
    pub mac2: [u8; COOKIE_LEN],
}

impl MessageMacs {
    pub fn encode(&self) -> [u8; 2 * COOKIE_LEN] {
        let mut out = [0u8; 2 * COOKIE_LEN];
        out[..COOKIE_LEN].copy_from_slice(&self.mac1);
        out[COOKIE_LEN..].copy_from_slice(&self.mac2);
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != 2 * COOKIE_LEN {
            return None;
        }
        let mut mac1 = [0u8; COOKIE_LEN];
        mac1.copy_from_slice(&buf[..COOKIE_LEN]);
        let mut mac2 = [0u8; COOKIE_LEN];
        mac2.copy_from_slice(&buf[COOKIE_LEN..]);
        Some(Self { mac1, mac2 })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageInitiation {
    pub sender_index: u32,
    pub eph_dh: [u8; X25519_KEY_LEN],
    pub kem_ct: [u8; MLKEM_CT_LEN],
    /// Ephemeral ML-KEM-768 encapsulation key (fresh per handshake) — the
    /// responder encapsulates its ephemeral KEM to THIS key, giving true
    /// post-quantum forward secrecy (not the static identity key).
    pub eph_ek: [u8; MLKEM_EK_LEN],
    pub enc_static: Vec<u8>, // AEAD(static_dh_pub || static_ek)
    pub enc_ts: Vec<u8>,     // AEAD(timestamp)
    pub macs: MessageMacs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageResponse {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub eph_dh: [u8; X25519_KEY_LEN],
    /// Ephemeral ML-KEM-768 ciphertext (post-quantum forward secrecy).
    pub kem_ct: [u8; MLKEM_CT_LEN],
    pub enc_empty: Vec<u8>, // AEAD(empty)
    pub macs: MessageMacs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageCookie {
    pub receiver_index: u32,
    pub nonce: [u8; COOKIE_NONCE_LEN],
    pub encrypted_cookie: Vec<u8>, // AEAD(cookie), 16 + 16 tag
}

impl MessageInitiation {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(INITIATION_LEN);
        v.extend_from_slice(&MESSAGE_HANDSHAKE_INITIATION.to_le_bytes());
        v.extend_from_slice(&self.sender_index.to_le_bytes());
        v.extend_from_slice(&self.eph_dh);
        v.extend_from_slice(&self.kem_ct);
        v.extend_from_slice(&self.eph_ek);
        v.extend_from_slice(&self.enc_static);
        v.extend_from_slice(&self.enc_ts);
        v.extend_from_slice(&self.macs.encode());
        v
    }

    /// Encode the message WITHOUT the trailing macs (the input to MAC1/MAC2).
    pub fn mac_input(&self) -> Vec<u8> {
        let full = self.encode();
        full[..full.len() - 2 * COOKIE_LEN].to_vec()
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != INITIATION_LEN || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MESSAGE_HANDSHAKE_INITIATION {
            return None;
        }
        let mut eph_dh = [0u8; X25519_KEY_LEN];
        eph_dh.copy_from_slice(&buf[8..8 + X25519_KEY_LEN]);
        let mut kem_ct = [0u8; MLKEM_CT_LEN];
        kem_ct.copy_from_slice(&buf[8 + X25519_KEY_LEN..8 + X25519_KEY_LEN + MLKEM_CT_LEN]);
        let mut eph_ek = [0u8; MLKEM_EK_LEN];
        let eph_ek_start = 8 + X25519_KEY_LEN + MLKEM_CT_LEN;
        eph_ek.copy_from_slice(&buf[eph_ek_start..eph_ek_start + MLKEM_EK_LEN]);
        let enc_start = eph_ek_start + MLKEM_EK_LEN;
        let enc_static = buf[enc_start..enc_start + X25519_KEY_LEN + MLKEM_EK_LEN + AEAD_TAG_LEN].to_vec();
        let enc_ts = buf[enc_start + X25519_KEY_LEN + MLKEM_EK_LEN + AEAD_TAG_LEN..buf.len() - 2 * COOKIE_LEN].to_vec();
        let macs = MessageMacs::decode(&buf[buf.len() - 2 * COOKIE_LEN..])?;
        Some(Self {
            sender_index: u32::from_le_bytes(buf[4..8].try_into().ok()?),
            eph_dh,
            kem_ct,
            eph_ek,
            enc_static,
            enc_ts,
            macs,
        })
    }
}

impl MessageResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(RESPONSE_LEN);
        v.extend_from_slice(&MESSAGE_HANDSHAKE_RESPONSE.to_le_bytes());
        v.extend_from_slice(&self.sender_index.to_le_bytes());
        v.extend_from_slice(&self.receiver_index.to_le_bytes());
        v.extend_from_slice(&self.eph_dh);
        v.extend_from_slice(&self.kem_ct);
        v.extend_from_slice(&self.enc_empty);
        v.extend_from_slice(&self.macs.encode());
        v
    }

    pub fn mac_input(&self) -> Vec<u8> {
        let full = self.encode();
        full[..full.len() - 2 * COOKIE_LEN].to_vec()
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != RESPONSE_LEN || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MESSAGE_HANDSHAKE_RESPONSE {
            return None;
        }
        let mut eph_dh = [0u8; X25519_KEY_LEN];
        eph_dh.copy_from_slice(&buf[12..12 + X25519_KEY_LEN]);
        let mut kem_ct = [0u8; MLKEM_CT_LEN];
        kem_ct.copy_from_slice(&buf[12 + X25519_KEY_LEN..12 + X25519_KEY_LEN + MLKEM_CT_LEN]);
        let body_end = buf.len() - 2 * COOKIE_LEN;
        let enc_empty = buf[12 + X25519_KEY_LEN + MLKEM_CT_LEN..body_end].to_vec();
        let macs = MessageMacs::decode(&buf[body_end..])?;
        Some(Self {
            sender_index: u32::from_le_bytes(buf[4..8].try_into().ok()?),
            receiver_index: u32::from_le_bytes(buf[8..12].try_into().ok()?),
            eph_dh,
            kem_ct,
            enc_empty,
            macs,
        })
    }
}

impl MessageCookie {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(COOKIE_MSG_LEN);
        v.extend_from_slice(&MESSAGE_HANDSHAKE_COOKIE.to_le_bytes());
        v.extend_from_slice(&self.receiver_index.to_le_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.encrypted_cookie);
        v
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != COOKIE_MSG_LEN || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MESSAGE_HANDSHAKE_COOKIE {
            return None;
        }
        let mut nonce = [0u8; COOKIE_NONCE_LEN];
        nonce.copy_from_slice(&buf[8..8 + COOKIE_NONCE_LEN]);
        let encrypted_cookie = buf[8 + COOKIE_NONCE_LEN..].to_vec();
        Some(Self { receiver_index: u32::from_le_bytes(buf[4..8].try_into().ok()?), nonce, encrypted_cookie })
    }
}

/// Timestamp: TAI64N-like (u64 seconds since epoch + u32 nanoseconds), big-endian
/// seconds with the TAI64 tag, mirroring WireGuard's tai64n. The nanosecond part
/// is quantized (ALIGN_DOWN to the largest power-of-two ≤ 1s/50) to prevent
/// timer precision from leaking — same anti-infoleak trick as WireGuard.
pub fn timestamp_now() -> [u8; TIMESTAMP_LEN] {
    use std::time::{SystemTime, UNIX_EPOCH};
    const QUANTUM: u32 = 16_777_216; // rounddown_pow_of_two(1_000_000_000 / 50)
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let nanos = now.subsec_nanos() - (now.subsec_nanos() % QUANTUM);
    let mut out = [0u8; TIMESTAMP_LEN];
    out[0..8].copy_from_slice(&(0x4000_0000_0000_000a_u64.wrapping_add(secs)).to_be_bytes());
    out[8..12].copy_from_slice(&nanos.to_be_bytes());
    out
}
