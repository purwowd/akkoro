//! Configuration, identity files, and hex encoding helpers.

use serde::{Deserialize, Serialize};

/// Hex-encode bytes.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Hex-decode into a fixed-size array.
pub fn hex_decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.trim();
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Identity file: long-term secret keys for this node.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct IdentityFile {
    /// X25519 static private key (hex, 32 bytes).
    pub dh_private: String,
    /// ML-KEM-768 decapsulation key seed (hex, 64 bytes).
    pub kem_seed: String,
}

/// Peer entry in the configuration file.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct PeerConfig {
    pub name: String,
    /// `IP:port` endpoint on the local network (no DNS, no STUN).
    pub endpoint: String,
    /// Peer X25519 static public key (hex, 32 bytes).
    pub dh_pub: String,
    /// Peer ML-KEM-768 encapsulation key (hex, 1184 bytes).
    pub ek: String,
    /// Allowed inner IPs for this peer (CIDR strings).
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Seconds between empty keepalive datagrams. 0 disables. Default 21.
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: u64,
}

/// Top-level configuration.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Config {
    /// Local UDP listen address, e.g. `0.0.0.0:51820`.
    pub listen: String,
    /// TUN interface name (Linux) — macOS auto-assigns a utun device.
    pub interface: String,
    /// Inner IP address + prefix for this node, e.g. `10.9.0.1/24`.
    pub address: String,
    /// MTU for the TUN device (default 1420).
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Data cipher: `aegis128l` (default, fast) or `chacha20poly1305` (fallback).
    #[serde(default = "default_cipher")]
    pub cipher: String,
    /// Require a valid cookie (MAC2) for handshakes — enables anti-DoS.
    #[serde(default)]
    pub cookie_required: bool,
    /// Enable mDNS peer discovery on the local network.
    #[serde(default)]
    pub mdns: bool,
    /// Path to the identity file (TOML with `dh_private` + `kem_seed` hex).
    pub identity_file: String,
    /// Optional pre-shared key (hex, any length) shared with all peers.
    pub psk: Option<String>,
    /// Peers.
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

fn default_mtu() -> u16 {
    1420
}

fn default_cipher() -> String {
    "aegis128l".to_string()
}

fn default_keepalive() -> u64 {
    crate::session::KEEPALIVE_DEFAULT_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_defaults_to_21() {
        let t = r#"
            name = "x"
            endpoint = "1.2.3.4:1"
            dh_pub = "00"
            ek = "00"
        "#;
        let p: PeerConfig = toml::from_str(t).unwrap();
        assert_eq!(
            p.persistent_keepalive,
            crate::session::KEEPALIVE_DEFAULT_SECS
        );
        let t0 = r#"
            name = "x"
            endpoint = "1.2.3.4:1"
            dh_pub = "00"
            ek = "00"
            persistent_keepalive = 0
        "#;
        let p0: PeerConfig = toml::from_str(t0).unwrap();
        assert_eq!(p0.persistent_keepalive, 0);
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let text = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&text)?;
        Ok(cfg)
    }

    pub fn load_identity(&self) -> Result<crate::crypto::IdentityKeys, Box<dyn std::error::Error>> {
        let text = std::fs::read_to_string(&self.identity_file)?;
        let idf: IdentityFile = toml::from_str(&text)?;
        let dh: [u8; 32] = hex_decode(&idf.dh_private).ok_or("invalid dh_private hex")?;
        let seed: [u8; 64] = hex_decode(&idf.kem_seed).ok_or("invalid kem_seed hex")?;
        crate::crypto::IdentityKeys::from_parts(dh, seed).ok_or_else(|| "bad identity".into())
    }

    pub fn psk_bytes(&self) -> Option<Vec<u8>> {
        self.psk.as_ref().and_then(|p| {
            let p = p.trim();
            if p.is_empty() {
                return None;
            }
            let mut out = Vec::with_capacity(p.len() / 2);
            for i in 0..p.len() / 2 {
                out.push(u8::from_str_radix(&p[i * 2..i * 2 + 2], 16).ok()?);
            }
            Some(out)
        })
    }

    pub fn cipher(&self) -> crate::crypto::Cipher {
        crate::crypto::Cipher::from_str(&self.cipher).unwrap_or(crate::crypto::Cipher::Aegis128L)
    }
}
