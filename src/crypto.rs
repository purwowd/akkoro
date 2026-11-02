//! Crypto primitives and key derivation for the Akkoro protocol.
//!
//! - X25519        : ephemeral/static DH (classical)
//! - ML-KEM-768    : post-quantum KEM (static encapsulation key)
//! - BLAKE3        : transcript hash (fast, strong)
//! - HKDF-SHA256   : key derivation with domain separation
//! - AEGIS-128L    : data/handshake AEAD (16-byte key, 16-byte nonce, 16-byte tag)

use aegis::aegis128l::Aegis128L;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Protocol name used as HKDF salt + transcript prefix (domain separation).
pub const PROTOCOL_NAME: &[u8] = b"Akkoro v1";

pub const X25519_KEY_LEN: usize = 32;
pub const MLKEM_SHARED_LEN: usize = 32;
pub const MLKEM_CT_LEN: usize = 1088; // ML-KEM-768 ciphertext
pub const MLKEM_EK_LEN: usize = 1184; // ML-KEM-768 encapsulation (public) key
pub const MLKEM_SEED_LEN: usize = 64; // decapsulation key seed
pub const AEAD_KEY_LEN: usize = 16;
pub const AEAD_NONCE_LEN: usize = 16;
pub const AEAD_TAG_LEN: usize = 16;
pub const HASH_LEN: usize = 32;
/// Session key length (32 bytes regardless of cipher; AEGIS-128L uses the
/// first 16 bytes, ChaCha20-Poly1305 uses all 32).
pub const SESSION_KEY_LEN: usize = 32;

pub type MlKemDecapKey = ml_kem::DecapsulationKey768;
pub type MlKemEncapKey = ml_kem::EncapsulationKey768;

/// ML-KEM-768 keypair: decapsulation key (private) + encapsulation key (public).
pub struct MlKemKeypair {
    pub decap: MlKemDecapKey,
    pub encap: MlKemEncapKey,
}

impl MlKemKeypair {
    pub fn generate() -> Self {
        use ml_kem::kem::Kem;
        let (dk, ek) = ml_kem::MlKem768::generate_keypair();
        Self { decap: dk, encap: ek }
    }

    /// Serialize the encapsulation key (1184 bytes).
    pub fn encap_bytes(&self) -> Vec<u8> {
        use ml_kem::kem::KeyExport;
        self.encap.to_bytes().as_slice().to_vec()
    }

    /// Serialize the decapsulation key as a 64-byte seed.
    pub fn seed_bytes(&self) -> [u8; MLKEM_SEED_LEN] {
        let seed: ml_kem::Seed = self.decap.to_seed().expect("seed");
        seed.into()
    }
}

/// Identity long-term keys: X25519 static + ML-KEM-768 static.
pub struct IdentityKeys {
    pub dh_private: x25519_dalek::StaticSecret,
    pub dh_public: x25519_dalek::PublicKey,
    pub kem: MlKemKeypair,
}

impl IdentityKeys {
    pub fn generate() -> Self {
        let dh_private = x25519_dalek::StaticSecret::random();
        let dh_public = x25519_dalek::PublicKey::from(&dh_private);
        let kem = MlKemKeypair::generate();
        Self { dh_private, dh_public, kem }
    }

    pub fn dh_public_bytes(&self) -> [u8; X25519_KEY_LEN] {
        self.dh_public.to_bytes()
    }

    pub fn from_parts(dh_private: [u8; X25519_KEY_LEN], kem_seed: [u8; MLKEM_SEED_LEN]) -> Option<Self> {
        let dh_private = x25519_dalek::StaticSecret::from(dh_private);
        let dh_public = x25519_dalek::PublicKey::from(&dh_private);
        let seed: ml_kem::Seed = kem_seed.into();
        let decap = MlKemDecapKey::from_seed(seed);
        let encap = decap.encapsulation_key().clone();
        Some(Self { dh_private, dh_public, kem: MlKemKeypair { decap, encap } })
    }
}

/// X25519 scalar multiplication returning the 32-byte shared secret.
pub fn x25519(private: &x25519_dalek::StaticSecret, public: &[u8; X25519_KEY_LEN]) -> [u8; X25519_KEY_LEN] {
    let pubkey = x25519_dalek::PublicKey::from(*public);
    private.diffie_hellman(&pubkey).to_bytes()
}

/// ML-KEM-768 encapsulation (initiator side): returns (ciphertext, shared secret).
pub fn mlkem_encapsulate(encap: &[u8; MLKEM_EK_LEN]) -> Option<([u8; MLKEM_CT_LEN], [u8; MLKEM_SHARED_LEN])> {
    use ml_kem::kem::Encapsulate;
    let key: ml_kem::kem::Key<MlKemEncapKey> = encap.as_slice().try_into().ok()?;
    let ek = MlKemEncapKey::new(&key).ok()?;
    let (ct, ss) = ek.encapsulate();
    let mut ct_out = [0u8; MLKEM_CT_LEN];
    ct_out.copy_from_slice(ct.as_slice());
    let mut ss_out = [0u8; MLKEM_SHARED_LEN];
    ss_out.copy_from_slice(ss.as_slice());
    Some((ct_out, ss_out))
}

/// ML-KEM-768 decapsulation (responder side): returns the shared secret.
pub fn mlkem_decapsulate(decap: &MlKemDecapKey, ct: &[u8; MLKEM_CT_LEN]) -> [u8; MLKEM_SHARED_LEN] {
    use ml_kem::kem::Decapsulate;
    let ct: ml_kem::Ciphertext<ml_kem::MlKem768> = ct.as_slice().try_into().expect("ct len");
    let ss = decap.decapsulate(&ct);
    let mut out = [0u8; MLKEM_SHARED_LEN];
    out.copy_from_slice(ss.as_slice());
    out
}

/// HKDF-SHA256 with the protocol name as salt.
pub fn kdf(ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(PROTOCOL_NAME), ikm);
    hk.expand(info, out).expect("hkdf expand");
}

/// BLAKE3 transcript hasher.
#[derive(Clone)]
pub struct Transcript {
    hasher: blake3::Hasher,
}

impl Transcript {
    pub fn new() -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PROTOCOL_NAME);
        Self { hasher }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    pub fn finalize(&self) -> [u8; HASH_LEN] {
        *self.hasher.finalize().as_bytes()
    }
}

/// AEGIS-128L AEAD seal: returns ciphertext || tag.
pub fn aead_seal(key: &[u8; AEAD_KEY_LEN], nonce: &[u8; AEAD_NONCE_LEN], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    let c = Aegis128L::<16>::new(key, nonce);
    let (mut ct, tag) = c.encrypt(plaintext, ad);
    ct.extend_from_slice(&tag);
    ct
}

/// AEGIS-128L AEAD open: verifies tag and returns plaintext, or None.
pub fn aead_open(key: &[u8; AEAD_KEY_LEN], nonce: &[u8; AEAD_NONCE_LEN], ciphertext: &[u8], ad: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < AEAD_TAG_LEN {
        return None;
    }
    let (ct, tag_bytes) = ciphertext.split_at(ciphertext.len() - AEAD_TAG_LEN);
    let mut tag = [0u8; AEAD_TAG_LEN];
    tag.copy_from_slice(tag_bytes);
    let c = Aegis128L::<16>::new(key, nonce);
    c.decrypt(ct, &tag, ad).ok()
}

/// Wipe a byte slice.
pub fn wipe(data: &mut [u8]) {
    data.zeroize();
}

/// Data-path cipher selection (negotiated out-of-band via config; both peers
/// must agree).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    Aegis128L,
    ChaCha20Poly1305,
}

impl Cipher {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aegis128l" | "aegis" => Some(Self::Aegis128L),
            "chacha20poly1305" | "chacha" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aegis128L => "aegis128l",
            Self::ChaCha20Poly1305 => "chacha20poly1305",
        }
    }
}

/// ChaCha20-Poly1305 seal (32-byte key, 12-byte nonce).
pub fn chacha_seal(key: &[u8; 32], nonce12: &[u8; 12], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let nonce = Nonce::from(*nonce12);
    cipher.encrypt(&nonce, Payload { msg: plaintext, aad: ad }).unwrap_or_default()
}

/// ChaCha20-Poly1305 open. Returns None on authentication failure.
pub fn chacha_open(key: &[u8; 32], nonce12: &[u8; 12], ciphertext: &[u8], ad: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let nonce = Nonce::from(*nonce12);
    cipher.decrypt(&nonce, Payload { msg: ciphertext, aad: ad }).ok()
}

/// BLAKE3 keyed hash (32-byte output).
pub fn blake3_keyed(key: &[u8; 32], data: &[u8]) -> [u8; HASH_LEN] {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// Cookie key = BLAKE3(label || public_key).
pub fn cookie_key(label: &[u8], pubkey: &[u8]) -> [u8; HASH_LEN] {
    let mut data = Vec::with_capacity(label.len() + pubkey.len());
    data.extend_from_slice(label);
    data.extend_from_slice(pubkey);
    *blake3::hash(&data).as_bytes()
}
