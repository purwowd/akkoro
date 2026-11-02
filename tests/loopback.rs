//! End-to-end crypto test: handshake + session + data path, in-process.

use akkoro::crypto::*;
use akkoro::handshake::{consume_initiation, consume_response, create_initiation};
use akkoro::protocol::*;
use akkoro::session::*;

#[test]
fn handshake_and_data_roundtrip() {
    let a = IdentityKeys::generate();
    let b = IdentityKeys::generate();

    let a_dh = a.dh_public_bytes();
    let b_dh = b.dh_public_bytes();
    let b_ek: [u8; MLKEM_EK_LEN] = b.kem.encap_bytes().as_slice().try_into().unwrap();

    // 1. initiator A -> B
    let (init, state) = create_initiation(&a, &b_dh, &b_ek, None, 42).expect("create initiation");

    // wire encode/decode roundtrip
    let wire = init.encode();
    let init2 = MessageInitiation::decode(&wire).expect("decode initiation");
    assert_eq!(init, init2);

    // 2. responder B consumes
    let out = consume_initiation(&b, &init2, None, 42, 99).expect("consume initiation");
    assert_eq!(out.init_dh_pub, a_dh);
    assert_eq!(&out.init_ek[..], &a.kem.encap_bytes()[..]);

    let resp_wire = out.response.encode();
    let resp = MessageResponse::decode(&resp_wire).expect("decode response");

    // 3. initiator A finishes
    let session_a = consume_response(state, &resp).expect("consume response");

    // 4. key agreement symmetric
    assert_eq!(session_a.send_key, out.session.recv_key);
    assert_eq!(session_a.recv_key, out.session.send_key);

    // 5. data A -> B
    let payload = b"hello over akkoro";
    let ct = encrypt_data(&session_a, Cipher::Aegis128L, 99, 0, payload);
    let pt = decrypt_data(&out.session.recv_key, Cipher::Aegis128L, 0, &ct[16..]).expect("decrypt a->b");
    assert_eq!(&pt[..payload.len()], payload);
    assert_eq!(pt.len() % 16, 0); // padded to a multiple of 16

    // 6. data B -> A
    let payload2 = b"reply from responder";
    let ct2 = encrypt_data(&out.session, Cipher::Aegis128L, 42, 0, payload2);
    let pt2 = decrypt_data(&session_a.recv_key, Cipher::Aegis128L, 0, &ct2[16..]).expect("decrypt b->a");
    assert_eq!(&pt2[..payload2.len()], payload2);

    // 7. tamper -> auth failure
    let mut bad = ct.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0xff;
    assert!(decrypt_data(&out.session.recv_key, Cipher::Aegis128L, 0, &bad[16..]).is_none());

    // 8. wrong key -> auth failure
    let other = IdentityKeys::generate();
    let other_session = SessionKeys::derive(&[0u8; 64], &[0u8; 32], true);
    assert!(decrypt_data(&other_session.recv_key, Cipher::Aegis128L, 0, &ct[16..]).is_none());
    let _ = other;
}

#[test]
fn replay_window_rejects_replays() {
    let mut w = ReplayWindow::default();
    assert!(w.validate(0));
    assert!(!w.validate(0)); // replay
    assert!(w.validate(1));
    assert!(w.validate(5));
    assert!(w.validate(2)); // old but in window
    assert!(!w.validate(2)); // replay
    // far-future counter beyond reject bound
    let mut w2 = ReplayWindow::default();
    assert!(!w2.validate(REJECT_AFTER_MESSAGES));
}

#[test]
fn mlkem_serialization_roundtrip() {
    let k = MlKemKeypair::generate();
    let ek_bytes = k.encap_bytes();
    assert_eq!(ek_bytes.len(), MLKEM_EK_LEN);

    let ek: [u8; MLKEM_EK_LEN] = ek_bytes.as_slice().try_into().unwrap();
    let (ct, ss_encap) = mlkem_encapsulate(&ek).expect("encapsulate");
    let ss_decap = mlkem_decapsulate(&k.decap, &ct);
    assert_eq!(ss_encap, ss_decap);

    let seed = k.seed_bytes();
    assert_eq!(seed.len(), MLKEM_SEED_LEN);
}

#[test]
fn timestamp_layout() {
    let ts = timestamp_now();
    assert_eq!(ts.len(), TIMESTAMP_LEN);
}

#[test]
fn chacha_fallback_roundtrip() {
    let initiator = SessionKeys::derive(&[1u8; 64], &[2u8; 32], true);
    let responder = SessionKeys::derive(&[1u8; 64], &[2u8; 32], false);
    let payload = b"chacha fallback test";
    let ct = encrypt_data(&initiator, Cipher::ChaCha20Poly1305, 7, 5, payload);
    let pt = decrypt_data(&responder.recv_key, Cipher::ChaCha20Poly1305, 5, &ct[16..]).unwrap();
    assert_eq!(&pt[..payload.len()], payload);
}

#[test]
fn full_cookie_handshake_and_data() {
    use akkoro::cookie::{self, CookieChecker, MacState};
    use std::net::IpAddr;

    let a = IdentityKeys::generate();
    let b = IdentityKeys::generate();
    let a_dh = a.dh_public_bytes();
    let b_dh = b.dh_public_bytes();
    let b_ek: [u8; MLKEM_EK_LEN] = b.kem.encap_bytes().as_slice().try_into().unwrap();

    let src = IpAddr::V4("172.30.0.10".parse().unwrap());
    let src_port = 51820u16;

    let mut checker_b = CookieChecker::new(&b_dh);
    let a_mac1_key = cookie::peer_mac1_key(&b_dh);
    let a_cookie_dec_key = cookie::peer_cookie_decryption_key(&b_dh);

    // 1. initiator sends initiation without mac2
    let (mut init, _state) = create_initiation(&a, &b_dh, &b_ek, None, 42).unwrap();
    let mi = init.mac_input();
    init.macs.mac1 = cookie::compute_mac1(&a_mac1_key, &mi);
    init.macs.mac2 = [0; COOKIE_LEN];
    let msg1 = MessageInitiation::decode(&init.encode()).unwrap();

    // 2. responder requires cookie
    assert_eq!(checker_b.validate(&msg1.mac_input(), &msg1.macs, src, src_port, true), MacState::NeedsCookie);

    // 3. responder sends cookie reply; initiator opens it
    let reply = checker_b.create_cookie_message(&msg1.macs.mac1, src, src_port, msg1.sender_index);
    let cookie = CookieChecker::open_cookie(&a_cookie_dec_key, &MessageCookie::decode(&reply.encode()).unwrap(), &init.macs.mac1).unwrap();

    // 4. initiator re-sends with mac2
    let (mut init2, state) = create_initiation(&a, &b_dh, &b_ek, None, 42).unwrap();
    let mi2 = init2.mac_input();
    init2.macs.mac1 = cookie::compute_mac1(&a_mac1_key, &mi2);
    init2.macs.mac2 = cookie::compute_mac2(&cookie, &mi2);
    let msg2 = MessageInitiation::decode(&init2.encode()).unwrap();

    // 5. responder accepts with cookie
    assert_eq!(checker_b.validate(&msg2.mac_input(), &msg2.macs, src, src_port, true), MacState::ValidWithCookie);

    // 6. responder consumes and responds with mac1
    let out = consume_initiation(&b, &msg2, None, msg2.sender_index, 99).unwrap();
    let mut resp = out.response;
    let rm = resp.mac_input();
    resp.macs.mac1 = cookie::compute_mac1(&cookie::peer_mac1_key(&a_dh), &rm);
    let rmsg = MessageResponse::decode(&resp.encode()).unwrap();

    // 7. initiator validates response mac1 (own key) and completes the session
    let mut checker_a = CookieChecker::new(&a_dh);
    assert_eq!(checker_a.validate(&rmsg.mac_input(), &rmsg.macs, src, src_port, false), MacState::ValidNoCookie);
    let session_a = consume_response(state, &rmsg).unwrap();

    assert_eq!(session_a.send_key, out.session.recv_key);
    assert_eq!(session_a.recv_key, out.session.send_key);

    // 8. data both ways
    let payload = b"cookie-mode data";
    let ct = encrypt_data(&session_a, Cipher::Aegis128L, 99, 0, payload);
    let pt = decrypt_data(&out.session.recv_key, Cipher::Aegis128L, 0, &ct[16..]).unwrap();
    assert_eq!(&pt[..payload.len()], payload);
}
