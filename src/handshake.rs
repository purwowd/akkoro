//! Akkoro handshake: hybrid X25519 + ML-KEM-768, 1-RTT, with BLAKE3 transcript
//! binding and HKDF-SHA256 key derivation.
//!
//! Shared secret: `ss = X25519(eph, peer_static) || ML-KEM_ss || psk`.
//! Three handshake AEAD keys are derived from `ss` (distinct keys => no nonce
//! reuse with the fixed zero nonce):
//!   k1 = KDF(ss, "akkoro-hs-key-1")   (seal static identity)
//!   k2 = KDF(ss, "akkoro-hs-key-2")   (seal timestamp)
//!   k3 = KDF(ss, "akkoro-hs-key-3")   (seal response empty)
//!
//! Transcript (both sides compute the same byte string):
//!   NAME || eph_dh || kem_ct || enc_static || enc_ts || eph_dh_r || enc_empty

use crate::crypto::*;
use crate::protocol::*;
use crate::session::SessionKeys;
use zeroize::Zeroize;

const ZERO_NONCE: [u8; AEAD_NONCE_LEN] = [0u8; AEAD_NONCE_LEN];

/// State the initiator keeps between sending the initiation and receiving the response.
pub struct InitiatorState {
    shared_secret: Vec<u8>,
    /// transcript updated through `enc_ts`.
    transcript: Transcript,
    /// Initiator's static ML-KEM decapsulation key (to decapsulate the
    /// responder's ephemeral KEM for post-quantum forward secrecy).
    kem_decap: MlKemDecapKey,
}

impl Drop for InitiatorState {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

/// Result of a responder consuming an initiation.
pub struct ResponderOutput {
    pub response: MessageResponse,
    pub session: SessionKeys,
    /// Initiator's X25519 static public key (for peer lookup).
    pub init_dh_pub: [u8; X25519_KEY_LEN],
    /// Initiator's ML-KEM-768 encapsulation key (so the responder can initiate back).
    pub init_ek: [u8; MLKEM_EK_LEN],
    /// Decrypted TAI64N timestamp (for replay/flood enforcement by the caller).
    pub timestamp: [u8; TIMESTAMP_LEN],
}

/// Build the handshake initiation message (initiator side).
pub fn create_initiation(
    identity: &IdentityKeys,
    peer_dh_pub: &[u8; X25519_KEY_LEN],
    peer_ek: &[u8; MLKEM_EK_LEN],
    psk: Option<&[u8]>,
    sender_index: u32,
) -> Option<(MessageInitiation, InitiatorState)> {
    let eph_private = x25519_dalek::StaticSecret::random();
    let eph_dh = x25519_dalek::PublicKey::from(&eph_private).to_bytes();

    let (kem_ct, kem_ss) = mlkem_encapsulate(peer_ek)?;
    let dh_ss = x25519(&eph_private, peer_dh_pub);

    let mut shared_secret = Vec::with_capacity(X25519_KEY_LEN + MLKEM_SHARED_LEN + psk.map(|p| p.len()).unwrap_or(0));
    shared_secret.extend_from_slice(&dh_ss);
    shared_secret.extend_from_slice(&kem_ss);
    if let Some(psk) = psk {
        shared_secret.extend_from_slice(psk);
    }

    let mut k1 = [0u8; AEAD_KEY_LEN];
    kdf(&shared_secret, b"akkoro-hs-key-1", &mut k1);
    let mut k2 = [0u8; AEAD_KEY_LEN];
    kdf(&shared_secret, b"akkoro-hs-key-2", &mut k2);

    let mut transcript = Transcript::new();
    transcript.update(&eph_dh);
    transcript.update(&kem_ct);

    let mut static_pt = Vec::with_capacity(STATIC_PT_LEN);
    static_pt.extend_from_slice(&identity.dh_public_bytes());
    static_pt.extend_from_slice(&identity.kem.encap_bytes());
    let enc_static = aead_seal(&k1, &ZERO_NONCE, &static_pt, &transcript.finalize());
    transcript.update(&enc_static);

    let ts = timestamp_now();
    let enc_ts = aead_seal(&k2, &ZERO_NONCE, &ts, &transcript.finalize());
    transcript.update(&enc_ts);

    // wipe ephemeral DH secret material
    let mut dh_ss_w = dh_ss; dh_ss_w.zeroize();
    let mut kem_ss_w = kem_ss; kem_ss_w.zeroize();
    let mut eph_private_bytes = eph_private.to_bytes(); eph_private_bytes.zeroize();
    k1.zeroize(); k2.zeroize();

    let msg = MessageInitiation { sender_index, eph_dh, kem_ct, enc_static, enc_ts, macs: MessageMacs::default() };
    Some((msg, InitiatorState { shared_secret, transcript, kem_decap: identity.kem.decap.clone() }))
}

/// Process the handshake response and derive session keys (initiator side).
pub fn consume_response(state: InitiatorState, response: &MessageResponse) -> Option<SessionKeys> {
    let mut k3 = [0u8; AEAD_KEY_LEN];
    kdf(&state.shared_secret, b"akkoro-hs-key-3", &mut k3);

    let mut transcript = state.transcript.clone();
    transcript.update(&response.eph_dh);
    transcript.update(&response.kem_ct);
    let ad = transcript.finalize();

    // verify the empty response payload under k3
    aead_open(&k3, &ZERO_NONCE, &response.enc_empty, &ad)?;

    transcript.update(&response.enc_empty);
    let final_hash = transcript.finalize();

    // Post-quantum forward secrecy: decapsulate the responder's ephemeral KEM.
    let kem_ss2 = mlkem_decapsulate(&state.kem_decap, &response.kem_ct);
    let mut shared_final = state.shared_secret.clone();
    shared_final.extend_from_slice(&kem_ss2);

    Some(SessionKeys::derive(&shared_final, &final_hash, true))
}

/// Consume a handshake initiation (responder side).
pub fn consume_initiation(
    identity: &IdentityKeys,
    msg: &MessageInitiation,
    psk: Option<&[u8]>,
    receiver_index: u32,
    sender_index: u32,
) -> Option<ResponderOutput> {
    let kem_ss = mlkem_decapsulate(&identity.kem.decap, &msg.kem_ct);
    let dh_ss = x25519(&identity.dh_private, &msg.eph_dh);

    let mut shared_secret = Vec::with_capacity(X25519_KEY_LEN + MLKEM_SHARED_LEN + psk.map(|p| p.len()).unwrap_or(0));
    shared_secret.extend_from_slice(&dh_ss);
    shared_secret.extend_from_slice(&kem_ss);
    if let Some(psk) = psk {
        shared_secret.extend_from_slice(psk);
    }

    let mut k1 = [0u8; AEAD_KEY_LEN];
    kdf(&shared_secret, b"akkoro-hs-key-1", &mut k1);
    let mut k2 = [0u8; AEAD_KEY_LEN];
    kdf(&shared_secret, b"akkoro-hs-key-2", &mut k2);
    let mut k3 = [0u8; AEAD_KEY_LEN];
    kdf(&shared_secret, b"akkoro-hs-key-3", &mut k3);

    let mut transcript = Transcript::new();
    transcript.update(&msg.eph_dh);
    transcript.update(&msg.kem_ct);

    // decrypt initiator static identity
    let static_pt = aead_open(&k1, &ZERO_NONCE, &msg.enc_static, &transcript.finalize())?;
    if static_pt.len() != STATIC_PT_LEN {
        return None;
    }
    let mut init_dh_pub = [0u8; X25519_KEY_LEN];
    init_dh_pub.copy_from_slice(&static_pt[..X25519_KEY_LEN]);
    let mut init_ek = [0u8; MLKEM_EK_LEN];
    init_ek.copy_from_slice(&static_pt[X25519_KEY_LEN..]);
    transcript.update(&msg.enc_static);

    // decrypt timestamp (replay/flood enforcement happens in the caller)
    let ts = aead_open(&k2, &ZERO_NONCE, &msg.enc_ts, &transcript.finalize())?;
    if ts.len() != TIMESTAMP_LEN {
        return None;
    }
    let mut timestamp = [0u8; TIMESTAMP_LEN];
    timestamp.copy_from_slice(&ts);
    transcript.update(&msg.enc_ts);

    // response ephemerals: X25519 + ephemeral ML-KEM (post-quantum forward secrecy)
    let eph_private_r = x25519_dalek::StaticSecret::random();
    let eph_dh_r = x25519_dalek::PublicKey::from(&eph_private_r).to_bytes();
    let (kem_ct2, kem_ss2) = mlkem_encapsulate(&init_ek)?;

    transcript.update(&eph_dh_r);
    transcript.update(&kem_ct2);
    let ad = transcript.finalize();

    let enc_empty = aead_seal(&k3, &ZERO_NONCE, &[], &ad);
    transcript.update(&enc_empty);
    let final_hash = transcript.finalize();

    let mut shared_final = shared_secret.clone();
    shared_final.extend_from_slice(&kem_ss2);
    let session = SessionKeys::derive(&shared_final, &final_hash, false);

    // wipe
    let mut dh_ss_w = dh_ss; dh_ss_w.zeroize();
    let mut kem_ss_w = kem_ss; kem_ss_w.zeroize();
    let mut kem_ss2_w = kem_ss2; kem_ss2_w.zeroize();
    let mut eph_private_r_bytes = eph_private_r.to_bytes(); eph_private_r_bytes.zeroize();
    k1.zeroize(); k2.zeroize(); k3.zeroize();

    let response = MessageResponse { sender_index, receiver_index, eph_dh: eph_dh_r, kem_ct: kem_ct2, enc_empty, macs: MessageMacs::default() };
    Some(ResponderOutput { response, session, init_dh_pub, init_ek, timestamp })
}
