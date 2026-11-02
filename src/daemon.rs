//! Akkoro daemon: UDP transport + TUN data path (synchronous, 2 threads).
//!
//! - Thread "rx": blocking UDP receive → handle handshakes / decrypt data → write inner to TUN.
//! - Thread "tx": non-blocking TUN read → route by inner dst IP → encrypt → UDP send.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::cookie::{self, CookieChecker, MacState};
use crate::crypto::*;
use crate::handshake::{consume_initiation, consume_response, create_initiation, InitiatorState};
use crate::protocol::*;
use crate::route::{cidr_match, inner_dst_ip, inner_src_ip, parse_cidr, trim_inner_packet};
use crate::session::*;
use crate::tun::TunDevice;

struct Peer {
    dh_pub: [u8; X25519_KEY_LEN],
    ek: [u8; MLKEM_EK_LEN],
    endpoint: SocketAddr,
    allowed_ips: Vec<(std::net::IpAddr, u8)>,
    session: Option<SessionKeys>,
    session_birth: Option<Instant>,
    local_index: u32,
    remote_index: u32,
    send_counter: u64,
    recv_window: ReplayWindow,
    pending: Option<InitiatorState>,
    latest_timestamp: [u8; TIMESTAMP_LEN],
    last_initiation: Option<Instant>,
    mac1_key: [u8; HASH_LEN],
    cookie_decryption_key: [u8; HASH_LEN],
    cookie: Option<([u8; COOKIE_LEN], Instant)>,
    last_mac1_sent: Option<[u8; COOKIE_LEN]>,
}

struct Shared {
    identity: IdentityKeys,
    psk: Option<Vec<u8>>,
    cipher: Cipher,
    cookie_required: bool,
    cookie_checker: Mutex<CookieChecker>,
    peers: Mutex<HashMap<String, Peer>>,
}

fn random_index() -> u32 {
    use rand::Rng;
    rand::rng().random::<u32>()
}

fn route(peers: &HashMap<String, Peer>, dst: std::net::IpAddr) -> Option<String> {
    let mut best: Option<(String, u8)> = None;
    for (name, p) in peers {
        for (net, prefix) in &p.allowed_ips {
            if cidr_match(net, *prefix, dst) && best.as_ref().map(|(_, p)| *prefix > *p).unwrap_or(true) {
                best = Some((name.clone(), *prefix));
            }
        }
    }
    best.map(|(n, _)| n)
}

pub fn run(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let identity = cfg.load_identity()?;
    let identity_dh_pub = identity.dh_public_bytes();
    let psk = cfg.psk_bytes();

    let udp = UdpSocket::bind(&cfg.listen)?;

    let tun = TunDevice::create(
        &cfg.interface,
        cfg.address.split('/').next().unwrap_or("10.9.0.1"),
        "255.255.255.0",
        cfg.mtu,
    )?;
    eprintln!("[akkoro] TUN device {} up (mtu {})", tun.name(), cfg.mtu);
    tun.set_nonblock()?;
    let (mut tun_reader, tun_writer) = tun.into_split();

    let mut peers = HashMap::new();
    for pc in &cfg.peers {
        let dh_pub: [u8; X25519_KEY_LEN] = crate::config::hex_decode(&pc.dh_pub).ok_or("bad peer dh_pub hex")?;
        let ek: [u8; MLKEM_EK_LEN] = crate::config::hex_decode(&pc.ek).ok_or("bad peer ek hex")?;
        let endpoint: SocketAddr = pc.endpoint.parse()?;
        let mut allowed_ips = Vec::new();
        for cidr in &pc.allowed_ips {
            allowed_ips.push(parse_cidr(cidr)?);
        }
        peers.insert(
            pc.name.clone(),
            Peer {
                dh_pub,
                ek,
                endpoint,
                allowed_ips,
                session: None,
                session_birth: None,
                local_index: random_index(),
                remote_index: 0,
                send_counter: 0,
                recv_window: ReplayWindow::default(),
                pending: None,
                latest_timestamp: [0u8; TIMESTAMP_LEN],
                last_initiation: None,
                mac1_key: cookie::peer_mac1_key(&dh_pub),
                cookie_decryption_key: cookie::peer_cookie_decryption_key(&dh_pub),
                cookie: None,
                last_mac1_sent: None,
            },
        );
    }

    let shared = Arc::new(Shared {
        identity,
        psk,
        cipher: cfg.cipher(),
        cookie_required: cfg.cookie_required,
        cookie_checker: Mutex::new(CookieChecker::new(&identity_dh_pub)),
        peers: Mutex::new(peers),
    });
    let tun_writer = Arc::new(Mutex::new(tun_writer));

    // --- mDNS discovery thread (offline LAN peer auto-discovery) ---
    if cfg.mdns {
        let listen_addr: SocketAddr = cfg.listen.parse()?;
        let listen_ip = listen_addr.ip();
        let listen_port = listen_addr.port();
        let dh_hex = crate::config::hex_encode(&identity_dh_pub);
        let ek_hex = crate::config::hex_encode(&shared.identity.kem.encap_bytes());
        let instance = format!("akkoro-{}", &dh_hex[..8]); // unique per node
        let mdns_shared = shared.clone();
        thread::spawn(move || match mdns_sd::ServiceDaemon::new() {
            Ok(d) => {
                if let Err(e) = crate::discovery::register(&d, &instance, listen_ip, listen_port, &dh_hex, &ek_hex) {
                    eprintln!("[akkoro] mDNS register failed: {e}");
                }
                let _ = crate::discovery::browse(&d, move |dh_hex, ek_hex, endpoint| {
                    let dh: Option<[u8; X25519_KEY_LEN]> = crate::config::hex_decode(&dh_hex);
                    let ek: Option<[u8; MLKEM_EK_LEN]> = crate::config::hex_decode(&ek_hex);
                    if let (Some(dh), Some(ek)) = (dh, ek) {
                        let mut peers = mdns_shared.peers.lock().unwrap();
                        for p in peers.values_mut() {
                            if p.dh_pub == dh {
                                p.endpoint = endpoint;
                                p.ek = ek;
                                p.session = None;
                                p.session_birth = None;
                            }
                        }
                    }
                });
            }
            Err(e) => eprintln!("[akkoro] mDNS init failed: {e}"),
        });
    }

    // --- UDP receive thread ---
    let udp_rx = udp.try_clone()?;
    let rx_shared = shared.clone();
    let rx_writer = tun_writer.clone();
    let rx = thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            match udp_rx.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if let Some(inner) = handle_udp(&rx_shared, &udp_rx, &buf[..n], from) {
                        let _ = rx_writer.lock().unwrap().write_all(&inner);
                    }
                }
                Err(e) => eprintln!("[akkoro] udp recv: {e}"),
            }
        }
    });

    // --- TUN read (transmit) thread ---
    let udp_tx = udp.try_clone()?;
    let tx_shared = shared.clone();
    let tx = thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            match tun_reader.read(&mut buf) {
                Ok(n) => {
                    let (out, endpoint) = {
                        let mut peers = tx_shared.peers.lock().unwrap();
                        let dst = match inner_dst_ip(&buf[..n]) {
                            Some(d) => d,
                            None => continue,
                        };
                        let name = match route(&peers, dst) {
                            Some(nm) => nm,
                            None => continue,
                        };
                        let peer = match peers.get_mut(&name) {
                            Some(p) => p,
                            None => continue,
                        };
                        // Time-based / counter-based rekey: drop the session so a
                        // fresh handshake is triggered on the next packet.
                        let need_rekey = match (&peer.session, &peer.session_birth) {
                            (Some(_), Some(b)) => {
                                b.elapsed().as_secs() >= REKEY_AFTER_TIME_SECS
                                    || peer.send_counter >= REKEY_AFTER_MESSAGES
                            }
                            _ => false,
                        };
                        if need_rekey {
                            peer.session = None;
                            peer.session_birth = None;
                        }
                        if peer.session.is_none() && peer.pending.is_none() {
                            let idx = peer.local_index;
                            if let Some((mut msg, st)) = create_initiation(
                                &tx_shared.identity,
                                &peer.dh_pub,
                                &peer.ek,
                                tx_shared.psk.as_deref(),
                                idx,
                            ) {
                                let mac_input = msg.mac_input();
                                let mac1 = cookie::compute_mac1(&peer.mac1_key, &mac_input);
                                let mac2 = match &peer.cookie {
                                    Some((c, birth)) if cookie::cookie_fresh(*birth) => {
                                        cookie::compute_mac2(c, &mac_input)
                                    }
                                    _ => [0u8; COOKIE_LEN],
                                };
                                msg.macs = MessageMacs { mac1, mac2 };
                                peer.last_mac1_sent = Some(mac1);
                                let bytes = msg.encode();
                                let _ = udp_tx.send_to(&bytes, peer.endpoint);
                                peer.pending = Some(st);
                            }
                        }
                        let session = match &peer.session {
                            Some(s) => s.clone(),
                            None => continue,
                        };
                        let counter = peer.send_counter;
                        if counter >= REJECT_AFTER_MESSAGES {
                            continue;
                        }
                        peer.send_counter = peer.send_counter.wrapping_add(1);
                        (encrypt_data(&session, tx_shared.cipher, peer.remote_index, counter, &buf[..n]), peer.endpoint)
                    };
                    let _ = udp_tx.send_to(&out, endpoint);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => eprintln!("[akkoro] tun read: {e}"),
            }
        }
    });

    rx.join().unwrap();
    tx.join().unwrap();
    Ok(())
}

/// Handle one inbound UDP datagram. Returns the decrypted inner packet (for
/// TUN) when it was a data message; handshake messages are answered here.
fn handle_udp(shared: &Shared, sock: &UdpSocket, buf: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    if buf.len() < 4 {
        return None;
    }
    let msg_type = u32::from_le_bytes(buf[0..4].try_into().ok()?);

    match msg_type {
        MESSAGE_HANDSHAKE_INITIATION => {
            let msg = MessageInitiation::decode(buf)?;
            let mac_input = msg.mac_input();
            let src = from.ip();
            let src_port = from.port();

            // Validate MACs (and require cookie if configured) BEFORE the expensive KEM.
            let mac_state = shared
                .cookie_checker
                .lock()
                .unwrap()
                .validate(&mac_input, &msg.macs, src, src_port, shared.cookie_required);
            match mac_state {
                MacState::Invalid => return None,
                MacState::NeedsCookie => {
                    let mut cc = shared.cookie_checker.lock().unwrap();
                    let reply = cc.create_cookie_message(&msg.macs.mac1, src, src_port, msg.sender_index);
                    let _ = sock.send_to(&reply.encode(), from);
                    return None;
                }
                _ => {}
            }

            let our_index = random_index();
            let mut out = consume_initiation(&shared.identity, &msg, shared.psk.as_deref(), msg.sender_index, our_index)?;

            let mut peers = shared.peers.lock().unwrap();
            let name = match peers.iter().find(|(_, p)| p.dh_pub == out.init_dh_pub) {
                Some((n, _)) => n.clone(),
                None => return None, // unknown initiator: drop, no response
            };
            let p = peers.get_mut(&name).unwrap();

            // Handshake replay + flood enforcement (after authentication, as in WireGuard).
            let now = Instant::now();
            let flood = p
                .last_initiation
                .map(|t| now.duration_since(t) < Duration::from_millis(20))
                .unwrap_or(false);
            let replay = out.timestamp <= p.latest_timestamp;
            if flood || replay {
                return None;
            }
            p.latest_timestamp = out.timestamp;
            p.last_initiation = Some(now);

            p.session = Some(out.session.clone());
            p.session_birth = Some(now);
            p.remote_index = msg.sender_index;
            p.local_index = our_index;
            p.pending = None;
            p.endpoint = from;

            // Tag the response with MAC1 keyed on the initiator's public key.
            let resp_mac_input = out.response.mac_input();
            out.response.macs.mac1 = cookie::compute_mac1(&p.mac1_key, &resp_mac_input);
            drop(peers);

            let _ = sock.send_to(&out.response.encode(), from);
            None
        }
        MESSAGE_HANDSHAKE_RESPONSE => {
            let msg = MessageResponse::decode(buf)?;
            // Validate MAC1 (keyed on our own public key) before consuming.
            let mac_input = msg.mac_input();
            let mac_state = shared
                .cookie_checker
                .lock()
                .unwrap()
                .validate(&mac_input, &msg.macs, from.ip(), from.port(), false);
            if mac_state == MacState::Invalid {
                return None;
            }

            let mut peers = shared.peers.lock().unwrap();
            let name = peers.iter().find(|(_, p)| p.local_index == msg.receiver_index).map(|(n, _)| n.clone())?;
            let p = peers.get_mut(&name)?;
            let st = p.pending.take()?;
            let session = consume_response(st, &msg)?;
            p.session = Some(session);
            p.session_birth = Some(Instant::now());
            p.remote_index = msg.sender_index;
            None
        }
        MESSAGE_HANDSHAKE_COOKIE => {
            let msg = MessageCookie::decode(buf)?;
            let mut peers = shared.peers.lock().unwrap();
            let name = peers.iter().find(|(_, p)| p.local_index == msg.receiver_index).map(|(n, _)| n.clone())?;
            let p = peers.get_mut(&name)?;
            let mac1 = p.last_mac1_sent?;
            let cookie = CookieChecker::open_cookie(&p.cookie_decryption_key, &msg, &mac1)?;
            p.cookie = Some((cookie, Instant::now()));

            // Immediately re-send the initiation, now carrying MAC2 (the cookie).
            let idx = p.local_index;
            let endpoint = p.endpoint;
            let (mut new_msg, st) = create_initiation(&shared.identity, &p.dh_pub, &p.ek, shared.psk.as_deref(), idx)?;
            let mac_input = new_msg.mac_input();
            let mac1 = cookie::compute_mac1(&p.mac1_key, &mac_input);
            let mac2 = cookie::compute_mac2(&cookie, &mac_input);
            new_msg.macs = MessageMacs { mac1, mac2 };
            p.last_mac1_sent = Some(mac1);
            p.pending = Some(st);
            let bytes = new_msg.encode();
            drop(peers);
            let _ = sock.send_to(&bytes, endpoint);
            None
        }
        MESSAGE_DATA => {
            if buf.len() < DATA_HEADER_LEN + AEAD_TAG_LEN {
                return None;
            }
            let receiver_index = u32::from_le_bytes(buf[4..8].try_into().ok()?);
            let counter = u64::from_le_bytes(buf[8..16].try_into().ok()?);
            let mut peers = shared.peers.lock().unwrap();
            let name = peers.iter().find(|(_, p)| p.local_index == receiver_index).map(|(n, _)| n.clone())?;
            let p = peers.get_mut(&name)?;
            // Reject if the session is too old (time-based reject).
            if let Some(b) = p.session_birth {
                if b.elapsed().as_secs() >= REJECT_AFTER_TIME_SECS {
                    p.session = None;
                    p.session_birth = None;
                    return None;
                }
            }
            let recv_key = p.session.as_ref()?.recv_key;
            if !p.recv_window.validate(counter) {
                return None;
            }
            let inner = decrypt_data(&recv_key, shared.cipher, counter, &buf[16..])?;
            let inner = trim_inner_packet(&inner).to_vec();
            // Reverse-path check: the inner source IP must belong to this peer's
            // allowed_ips (prevents one peer spoofing another's inner addresses).
            let src = inner_src_ip(&inner)?;
            if !p.allowed_ips.iter().any(|(net, prefix)| cidr_match(net, *prefix, src)) {
                return None;
            }
            Some(inner)
        }
        _ => None,
    }
}
