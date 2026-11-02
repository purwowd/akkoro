//! Cookie anti-DoS (WireGuard MAC1/MAC2 analogue: BLAKE3 keyed MACs + AEGIS-128L
//! cookie encryption). Protects the responder from CPU-DoS by spoofed-source
//! handshakes under load.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::crypto::*;
use crate::protocol::*;

pub const COOKIE_SECRET_MAX_AGE_SECS: u64 = 120;

/// Outcome of validating a handshake packet's MACs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacState {
    Invalid,
    ValidNoCookie,
    ValidWithCookie,
    NeedsCookie,
}

/// Constant-time byte comparison (no early exit).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0 && a.len() == b.len()
}

/// MAC1 = first 16 bytes of BLAKE3 keyed with `mac1_key`.
pub fn compute_mac1(mac1_key: &[u8; HASH_LEN], msg_without_macs: &[u8]) -> [u8; COOKIE_LEN] {
    let h = blake3_keyed(mac1_key, msg_without_macs);
    h[..COOKIE_LEN].try_into().expect("16")
}

/// MAC2 = first 16 bytes of BLAKE3 keyed with a key derived from the cookie.
pub fn compute_mac2(cookie: &[u8; COOKIE_LEN], msg_without_macs: &[u8]) -> [u8; COOKIE_LEN] {
    let mut key = [0u8; HASH_LEN];
    key.copy_from_slice(blake3::hash(cookie).as_bytes());
    let h = blake3_keyed(&key, msg_without_macs);
    h[..COOKIE_LEN].try_into().expect("16")
}

/// Responder-side cookie checker (keyed on the responder's own static pubkey).
pub struct CookieChecker {
    secret: [u8; HASH_LEN],
    secret_birth: Instant,
    mac1_key: [u8; HASH_LEN],
    encryption_key: [u8; HASH_LEN],
}

impl CookieChecker {
    pub fn new(static_dh_pub: &[u8; X25519_KEY_LEN]) -> Self {
        let mac1_key = cookie_key(b"mac1----", static_dh_pub);
        let encryption_key = cookie_key(b"cookie--", static_dh_pub);
        let mut secret = [0u8; HASH_LEN];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut secret);
        Self { secret, secret_birth: Instant::now(), mac1_key, encryption_key }
    }

    fn refresh_secret(&mut self) {
        if self.secret_birth.elapsed().as_secs() >= COOKIE_SECRET_MAX_AGE_SECS {
            use rand::RngCore;
            rand::rng().fill_bytes(&mut self.secret);
            self.secret_birth = Instant::now();
        }
    }

    /// Cookie bound to (source IP, source port) under the rotating secret.
    pub fn make_cookie(&mut self, src: IpAddr, src_port: u16) -> [u8; COOKIE_LEN] {
        self.refresh_secret();
        let mut data = Vec::with_capacity(18);
        match src {
            IpAddr::V4(a) => data.extend_from_slice(&a.octets()),
            IpAddr::V6(a) => data.extend_from_slice(&a.octets()),
        }
        data.extend_from_slice(&src_port.to_le_bytes());
        let h = blake3_keyed(&self.secret, &data);
        h[..COOKIE_LEN].try_into().expect("16")
    }

    /// Validate a handshake packet. `under_load` decides whether mac2 is required.
    pub fn validate(&mut self, msg_without_macs: &[u8], macs: &MessageMacs, src: IpAddr, src_port: u16, under_load: bool) -> MacState {
        let mac1 = compute_mac1(&self.mac1_key, msg_without_macs);
        if !ct_eq(&mac1, &macs.mac1) {
            return MacState::Invalid;
        }
        if !under_load {
            return MacState::ValidNoCookie;
        }
        let cookie = self.make_cookie(src, src_port);
        let mac2 = compute_mac2(&cookie, msg_without_macs);
        if !ct_eq(&mac2, &macs.mac2) {
            return MacState::NeedsCookie;
        }
        MacState::ValidWithCookie
    }

    /// Build a cookie-reply message for an initiator that needs one.
    pub fn create_cookie_message(&mut self, mac1: &[u8; COOKIE_LEN], src: IpAddr, src_port: u16, receiver_index: u32) -> MessageCookie {
        let cookie = self.make_cookie(src, src_port);
        let mut nonce = [0u8; COOKIE_NONCE_LEN];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut nonce);
        let mut key = [0u8; AEAD_KEY_LEN];
        key.copy_from_slice(&self.encryption_key[..AEAD_KEY_LEN]);
        let encrypted_cookie = aead_seal(&key, &nonce, &cookie, mac1);
        MessageCookie { receiver_index, nonce, encrypted_cookie }
    }

    /// Decrypt a received cookie reply (initiator side, using the peer's
    /// cookie-encryption key — see `peer_cookie_decryption_key`).
    pub fn open_cookie(decryption_key: &[u8; HASH_LEN], msg: &MessageCookie, mac1_sent: &[u8; COOKIE_LEN]) -> Option<[u8; COOKIE_LEN]> {
        let mut key = [0u8; AEAD_KEY_LEN];
        key.copy_from_slice(&decryption_key[..AEAD_KEY_LEN]);
        let pt = aead_open(&key, &msg.nonce, &msg.encrypted_cookie, mac1_sent)?;
        if pt.len() != COOKIE_LEN {
            return None;
        }
        let mut c = [0u8; COOKIE_LEN];
        c.copy_from_slice(&pt);
        Some(c)
    }
}

/// Per-peer MAC1 key (used to tag outgoing handshakes to that peer).
pub fn peer_mac1_key(peer_dh_pub: &[u8; X25519_KEY_LEN]) -> [u8; HASH_LEN] {
    cookie_key(b"mac1----", peer_dh_pub)
}

/// Per-peer cookie-decryption key (used to decrypt cookie replies from that peer).
pub fn peer_cookie_decryption_key(peer_dh_pub: &[u8; X25519_KEY_LEN]) -> [u8; HASH_LEN] {
    cookie_key(b"cookie--", peer_dh_pub)
}

/// How long a received cookie stays valid.
pub fn cookie_fresh(birth: Instant) -> bool {
    birth.elapsed() < Duration::from_secs(COOKIE_SECRET_MAX_AGE_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentityKeys;
    use std::net::Ipv4Addr;

    #[test]
    fn mac_and_cookie_flow() {
        let b = IdentityKeys::generate();
        let b_pub = b.dh_public_bytes();

        let mut checker = CookieChecker::new(&b_pub);
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 8, 10));
        let msg = b"handshake-initiation-bytes";

        // initiator A tags with B's mac1 key
        let mac1 = compute_mac1(&peer_mac1_key(&b_pub), msg);
        let macs = MessageMacs { mac1, mac2: [0; 16] };

        assert_eq!(checker.validate(msg, &macs, src, 51820, false), MacState::ValidNoCookie);
        assert_eq!(checker.validate(msg, &macs, src, 51820, true), MacState::NeedsCookie);

        // cookie reply -> initiator decrypts -> mac2
        let reply = checker.create_cookie_message(&mac1, src, 51820, 42);
        let cookie = CookieChecker::open_cookie(&peer_cookie_decryption_key(&b_pub), &reply, &mac1).unwrap();
        let mac2 = compute_mac2(&cookie, msg);
        let macs2 = MessageMacs { mac1, mac2 };
        assert_eq!(checker.validate(msg, &macs2, src, 51820, true), MacState::ValidWithCookie);

        // tampered mac1 -> invalid
        let bad = MessageMacs { mac1: [0xAA; 16], mac2: [0; 16] };
        assert_eq!(checker.validate(msg, &bad, src, 51820, false), MacState::Invalid);
    }
}
