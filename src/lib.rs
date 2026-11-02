//! Akkoro — a post-quantum, low-latency L3 VPN tunnel.
//!
//! Protocol "Akkoro v1": hybrid X25519 + ML-KEM-768 key exchange, BLAKE3
//! transcript, HKDF-SHA256 key derivation, AEGIS-128L data encryption.
//!
//! Lab-only research artifact. See DESIGN.md.

pub mod batch;
pub mod config;
pub mod cookie;
pub mod crypto;
pub mod daemon;
pub mod discovery;
pub mod handshake;
pub mod protocol;
pub mod route;
pub mod session;
pub mod tun;

pub use crypto::*;
pub use protocol::*;
pub use session::*;
