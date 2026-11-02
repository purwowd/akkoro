//! Session keys, replay protection, and data-packet AEAD.

use crate::crypto::*;
use crate::protocol::{DATA_HEADER_LEN, MESSAGE_DATA};

pub const COUNTER_WINDOW_SIZE: u64 = 8192 - 64;
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - COUNTER_WINDOW_SIZE - 1;
/// Time-based rekey / reject thresholds.
pub const REKEY_AFTER_TIME_SECS: u64 = 120;
pub const REJECT_AFTER_TIME_SECS: u64 = 180;
/// Data padding multiple (anti traffic-analysis).
pub const MESSAGE_PADDING_MULTIPLE: usize = 16;

/// Derived symmetric session keys (32 bytes; AEGIS-128L uses the first 16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionKeys {
    pub send_key: [u8; SESSION_KEY_LEN],
    pub recv_key: [u8; SESSION_KEY_LEN],
}

impl SessionKeys {
    pub fn derive(shared_secret: &[u8], final_transcript: &[u8; HASH_LEN], is_initiator: bool) -> Self {
        let mut ikm = Vec::with_capacity(shared_secret.len() + HASH_LEN);
        ikm.extend_from_slice(shared_secret);
        ikm.extend_from_slice(final_transcript);

        let mut master = [0u8; HASH_LEN];
        kdf(&ikm, b"akkoro-master", &mut master);
        let mut a = [0u8; SESSION_KEY_LEN];
        kdf(&master, b"akkoro-send", &mut a);
        let mut b = [0u8; SESSION_KEY_LEN];
        kdf(&master, b"akkoro-recv", &mut b);

        if is_initiator {
            Self { send_key: a, recv_key: b }
        } else {
            Self { send_key: b, recv_key: a }
        }
    }
}

/// RFC6479-style replay window (8192-bit bitmap).
#[derive(Clone)]
pub struct ReplayWindow {
    counter: u64,
    bitmap: [u64; (COUNTER_WINDOW_SIZE as usize / 64) + 1],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self { counter: 0, bitmap: [0; (COUNTER_WINDOW_SIZE as usize / 64) + 1] }
    }
}

impl ReplayWindow {
    /// Returns true if `ctr` is fresh (not replayed).
    pub fn validate(&mut self, ctr: u64) -> bool {
        if self.counter >= REJECT_AFTER_MESSAGES + 1 || ctr >= REJECT_AFTER_MESSAGES {
            return false;
        }
        let their = ctr + 1;
        if COUNTER_WINDOW_SIZE + their < self.counter {
            return false; // too old
        }
        let index = (their >> 6) as usize & (self.bitmap.len() - 1);
        if their > self.counter {
            let old_index = (self.counter >> 6) as usize & (self.bitmap.len() - 1);
            let diff = (index as i64 - old_index as i64).rem_euclid(self.bitmap.len() as i64) as usize;
            for i in 1..=diff.min(self.bitmap.len() - 1) {
                self.bitmap[(old_index + i) & (self.bitmap.len() - 1)] = 0;
            }
            self.counter = their;
        }
        let bit = their & 63;
        let mask = 1u64 << bit;
        if self.bitmap[index] & mask != 0 {
            false
        } else {
            self.bitmap[index] |= mask;
            true
        }
    }
}

/// Construct the 16-byte nonce from a 64-bit counter.
pub fn data_nonce(counter: u64) -> [u8; AEAD_NONCE_LEN] {
    let mut n = [0u8; AEAD_NONCE_LEN];
    n[0..8].copy_from_slice(&counter.to_le_bytes());
    n
}

/// Pad a plaintext to a multiple of MESSAGE_PADDING_MULTIPLE with zero bytes.
fn pad(plaintext: &[u8]) -> Vec<u8> {
    let mut out = plaintext.to_vec();
    let rem = (MESSAGE_PADDING_MULTIPLE - (out.len() % MESSAGE_PADDING_MULTIPLE)) % MESSAGE_PADDING_MULTIPLE;
    if rem > 0 {
        out.resize(out.len() + rem, 0);
    }
    out
}

/// Encrypt an inner IP packet (with padding) into a full data message.
pub fn encrypt_data(session: &SessionKeys, cipher: Cipher, receiver_index: u32, counter: u64, inner: &[u8]) -> Vec<u8> {
    let plaintext = pad(inner);
    let nonce16 = data_nonce(counter);
    let ct = match cipher {
        Cipher::Aegis128L => {
            let mut k = [0u8; AEAD_KEY_LEN];
            k.copy_from_slice(&session.send_key[..AEAD_KEY_LEN]);
            aead_seal(&k, &nonce16, &plaintext, &[])
        }
        Cipher::ChaCha20Poly1305 => {
            let mut n12 = [0u8; 12];
            n12.copy_from_slice(&nonce16[..12]);
            chacha_seal(&session.send_key, &n12, &plaintext, &[])
        }
    };
    let mut out = Vec::with_capacity(DATA_HEADER_LEN + ct.len());
    out.extend_from_slice(&MESSAGE_DATA.to_le_bytes());
    out.extend_from_slice(&receiver_index.to_le_bytes());
    out.extend_from_slice(&counter.to_le_bytes());
    out.extend_from_slice(&ct);
    out
}

/// Decrypt a data message body (after the 4-byte type) into the padded inner
/// packet. Returns None on authentication failure.
pub fn decrypt_data(recv_key: &[u8; SESSION_KEY_LEN], cipher: Cipher, counter: u64, body: &[u8]) -> Option<Vec<u8>> {
    let nonce16 = data_nonce(counter);
    match cipher {
        Cipher::Aegis128L => {
            let mut k = [0u8; AEAD_KEY_LEN];
            k.copy_from_slice(&recv_key[..AEAD_KEY_LEN]);
            aead_open(&k, &nonce16, body, &[])
        }
        Cipher::ChaCha20Poly1305 => {
            let mut n12 = [0u8; 12];
            n12.copy_from_slice(&nonce16[..12]);
            chacha_open(recv_key, &n12, body, &[])
        }
    }
}
