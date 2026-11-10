//! Akkoro daemon: UDP transport + TUN data path (synchronous, 2 threads).
//!
//! - Thread "rx": blocking UDP receive → handle handshakes / decrypt data → write inner to TUN.
//! - Thread "tx": poll TUN (250 ms timeout) → encrypt → UDP send; also handshake retry + keepalive.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::batch::{recv_batch, send_batch, BATCH_SIZE, DATAGRAM_SIZE};
use crate::config::Config;
use crate::cookie::{self, CookieChecker, MacState};
use crate::crypto::*;
use crate::handshake::{consume_initiation, consume_response, create_initiation, InitiatorState};
use crate::protocol::*;
use crate::route::{cidr_match, inner_dst_ip, inner_src_ip, parse_cidr, trim_inner_packet};
use crate::session::*;
use crate::tun::TunDevice;

const TICK_MS: i32 = 250;

struct Keypair {
    session: SessionKeys,
    birth: Instant,
    local_index: u32,
    remote_index: u32,
    send_counter: u64,
    recv_window: ReplayWindow,
    we_initiated: bool,
    /// Set after a data packet decrypts under this keypair. Until then TX stays on previous.
    confirmed: bool,
}

impl Keypair {
    fn expired(&self) -> bool {
        self.birth.elapsed().as_secs() >= REJECT_AFTER_TIME_SECS
    }

    fn needs_rekey(&self) -> bool {
        self.birth.elapsed().as_secs() >= REKEY_AFTER_TIME_SECS
            || self.send_counter >= REKEY_AFTER_MESSAGES
    }
}

struct Peer {
    dh_pub: [u8; X25519_KEY_LEN],
    ek: [u8; MLKEM_EK_LEN],
    endpoint: SocketAddr,
    allowed_ips: Vec<(std::net::IpAddr, u8)>,
    current: Option<Keypair>,
    previous: Option<Keypair>,
    pending: Option<InitiatorState>,
    pending_local_index: u32,
    tx_queue: VecDeque<Vec<u8>>,
    keepalive: Duration,
    last_tx: Option<Instant>,
    latest_timestamp: [u8; TIMESTAMP_LEN],
    last_initiation: Option<Instant>,
    last_rx_initiation: Option<Instant>,
    born: Instant,
    init_retry: Duration,
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

fn ipv4_netmask(prefix: u8) -> String {
    let prefix = prefix.min(32);
    let m = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix)
    };
    let b = m.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn inner_ip(pkt: &[u8]) -> Option<&[u8]> {
    Some(pkt)
}

fn tun_write_payload(ip: &[u8]) -> Vec<u8> {
    ip.to_vec()
}

fn route(peers: &HashMap<String, Peer>, dst: std::net::IpAddr) -> Option<String> {
    let mut best: Option<(String, u8)> = None;
    for (name, p) in peers {
        for (net, prefix) in &p.allowed_ips {
            if cidr_match(net, *prefix, dst)
                && best.as_ref().map(|(_, p)| *prefix > *p).unwrap_or(true)
            {
                best = Some((name.clone(), *prefix));
            }
        }
    }
    best.map(|(n, _)| n)
}

fn index_in_use(peer: &Peer, idx: u32) -> bool {
    peer.current.as_ref().map(|k| k.local_index) == Some(idx)
        || peer.previous.as_ref().map(|k| k.local_index) == Some(idx)
        || (peer.pending.is_some() && peer.pending_local_index == idx)
}

fn fresh_index(peer: &Peer) -> u32 {
    loop {
        let idx = random_index();
        if !index_in_use(peer, idx) {
            return idx;
        }
    }
}

fn handshake_due(peer: &Peer) -> bool {
    match peer.last_initiation {
        None => true,
        Some(t) => t.elapsed() >= peer.init_retry,
    }
}

/// The peer with the lexicographically smaller static X25519 key initiates.
fn is_designated_initiator(our_dh: &[u8; X25519_KEY_LEN], peer_dh: &[u8; X25519_KEY_LEN]) -> bool {
    our_dh.as_slice() < peer_dh.as_slice()
}

fn want_initiation(shared: &Shared, peer: &Peer) -> bool {
    if peer.pending.is_some() {
        return handshake_due(peer);
    }
    let designated = is_designated_initiator(&shared.identity.dh_public_bytes(), &peer.dh_pub);
    let no_sess = peer.current.is_none();
    let rekey = peer.current.as_ref().map(|k| k.needs_rekey()).unwrap_or(false);
    if designated {
        return no_sess || rekey;
    }
    // Responder waits. If the initiator is silent after startup, recover.
    if no_sess {
        return peer.born.elapsed() >= Duration::from_millis(INIT_RETRY_MAX_MS);
    }
    false
}

fn enqueue_tx(peer: &mut Peer, pkt: &[u8]) {
    if peer.tx_queue.len() >= TX_QUEUE_CAP {
        peer.tx_queue.pop_front();
    }
    peer.tx_queue.push_back(pkt.to_vec());
}

fn install_session(
    peer: &mut Peer,
    session: SessionKeys,
    local_index: u32,
    remote_index: u32,
    we_initiated: bool,
    confirmed: bool,
) {
    if let Some(cur) = peer.current.take() {
        if !cur.expired() {
            peer.previous = Some(cur);
        }
    }
    peer.current = Some(Keypair {
        session,
        birth: Instant::now(),
        local_index,
        remote_index,
        send_counter: 0,
        recv_window: ReplayWindow::default(),
        we_initiated,
        confirmed,
    });
    peer.pending = None;
    peer.init_retry = Duration::from_millis(INIT_RETRY_MIN_MS);
    eprintln!(
        "[akkoro] session {} local={local_index} remote={remote_index}",
        if we_initiated { "initiator" } else { "responder" }
    );
}

fn tx_use_previous(peer: &Peer) -> bool {
    let prev_ok = peer
        .previous
        .as_ref()
        .is_some_and(|k| !k.expired() && k.send_counter < REJECT_AFTER_MESSAGES);
    if !prev_ok {
        return false;
    }
    match &peer.current {
        None => true,
        Some(k) => !k.confirmed,
    }
}

fn flush_tx_queue(peer: &mut Peer, cipher: Cipher, sock: &UdpSocket) {
    let endpoint = peer.endpoint;
    let mut q = std::mem::take(&mut peer.tx_queue);
    let mut sent = 0u32;
    {
        let kp = if tx_use_previous(peer) {
            peer.previous.as_mut()
        } else {
            peer.current.as_mut()
        };
        let Some(kp) = kp else {
            peer.tx_queue = q;
            return;
        };
        while let Some(pkt) = q.pop_front() {
            if kp.send_counter >= REJECT_AFTER_MESSAGES {
                q.push_front(pkt);
                break;
            }
            let c = kp.send_counter;
            kp.send_counter += 1;
            let wire = encrypt_data(&kp.session, cipher, kp.remote_index, c, &pkt);
            let _ = sock.send_to(&wire, endpoint);
            sent += 1;
        }
    }
    peer.tx_queue = q;
    if sent > 0 {
        peer.last_tx = Some(Instant::now());
    }
}

fn send_initiation(shared: &Shared, sock: &UdpSocket, peer: &mut Peer) {
    if !handshake_due(peer) {
        return;
    }
    let retrying = peer.pending.is_some();
    let idx = fresh_index(peer);
    let Some((mut msg, st)) = create_initiation(
        &shared.identity,
        &peer.dh_pub,
        &peer.ek,
        shared.psk.as_deref(),
        idx,
    ) else {
        return;
    };
    let mac_input = msg.mac_input();
    let mac1 = cookie::compute_mac1(&peer.mac1_key, &mac_input);
    let mac2 = match &peer.cookie {
        Some((c, birth)) if cookie::cookie_fresh(*birth) => cookie::compute_mac2(c, &mac_input),
        _ => [0u8; COOKIE_LEN],
    };
    msg.macs = MessageMacs { mac1, mac2 };
    peer.last_mac1_sent = Some(mac1);
    let bytes = msg.encode();
    let _ = sock.send_to(&bytes, peer.endpoint);
    peer.pending = Some(st);
    peer.pending_local_index = idx;
    peer.last_initiation = Some(Instant::now());
    if retrying {
        peer.init_retry =
            (peer.init_retry.saturating_mul(2)).min(Duration::from_millis(INIT_RETRY_MAX_MS));
    } else {
        peer.init_retry = Duration::from_millis(INIT_RETRY_MIN_MS);
    }
}

fn tick_peers(shared: &Shared, sock: &UdpSocket) {
    let mut peers = shared.peers.lock().unwrap();
    for p in peers.values_mut() {
        if p.previous.as_ref().map(|k| k.expired()).unwrap_or(false) {
            p.previous = None;
        }
        if p.current.as_ref().map(|k| k.expired()).unwrap_or(false) {
            p.current = None;
        }

        if want_initiation(shared, p) {
            send_initiation(shared, sock, p);
        }

        if p.keepalive == Duration::ZERO {
            continue;
        }
        let idle = p.last_tx.map(|t| t.elapsed()).unwrap_or(Duration::MAX);
        if idle < p.keepalive {
            continue;
        }
        let endpoint = p.endpoint;
        let cipher = shared.cipher;
        let wire = {
            let kp = if tx_use_previous(p) {
                p.previous.as_mut()
            } else {
                p.current.as_mut()
            };
            let Some(kp) = kp else {
                continue;
            };
            if kp.expired() || kp.send_counter >= REJECT_AFTER_MESSAGES {
                continue;
            }
            let c = kp.send_counter;
            kp.send_counter += 1;
            encrypt_data(&kp.session, cipher, kp.remote_index, c, &[])
        };
        let _ = sock.send_to(&wire, endpoint);
        p.last_tx = Some(Instant::now());
    }
}

fn keypair_mut(peer: &mut Peer, idx: u32) -> Option<&mut Keypair> {
    if peer.current.as_ref().is_some_and(|k| k.local_index == idx) {
        if peer.current.as_ref().is_some_and(|k| k.expired()) {
            peer.current = None;
            return None;
        }
        return peer.current.as_mut();
    }
    if peer.previous.as_ref().is_some_and(|k| k.local_index == idx) {
        if peer.previous.as_ref().is_some_and(|k| k.expired()) {
            peer.previous = None;
            return None;
        }
        return peer.previous.as_mut();
    }
    None
}

fn peer_name_by_data_index(peers: &HashMap<String, Peer>, idx: u32) -> Option<String> {
    peers
        .iter()
        .find(|(_, p)| {
            p.current.as_ref().is_some_and(|k| k.local_index == idx)
                || p.previous.as_ref().is_some_and(|k| k.local_index == idx)
        })
        .map(|(n, _)| n.clone())
}

fn peer_name_by_pending_index(peers: &HashMap<String, Peer>, idx: u32) -> Option<String> {
    peers
        .iter()
        .find(|(_, p)| p.pending.is_some() && p.pending_local_index == idx)
        .map(|(n, _)| n.clone())
}

pub fn run(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let identity = cfg.load_identity()?;
    let identity_dh_pub = identity.dh_public_bytes();
    let psk = cfg.psk_bytes();

    let udp = UdpSocket::bind(&cfg.listen)?;

    let inner_addr = cfg.address.split('/').next().unwrap_or("10.9.0.1");
    let prefix: u8 = cfg
        .address
        .split('/')
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(24);
    let netmask = ipv4_netmask(prefix);
    let destination = cfg.peers.iter().find_map(|p| {
        p.allowed_ips
            .first()
            .and_then(|cidr| cidr.split('/').next())
            .map(str::to_string)
    });
    let tun = TunDevice::create(
        &cfg.interface,
        inner_addr,
        &netmask,
        cfg.mtu,
        destination.as_deref(),
    )?;
    eprintln!("[akkoro] TUN device {} up (mtu {})", tun.name(), cfg.mtu);
    tun.set_nonblock()?;
    let (mut tun_reader, tun_writer) = tun.into_split();

    let mut peers = HashMap::new();
    for pc in &cfg.peers {
        let dh_pub: [u8; X25519_KEY_LEN] =
            crate::config::hex_decode(&pc.dh_pub).ok_or("bad peer dh_pub hex")?;
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
                current: None,
                previous: None,
                pending: None,
                pending_local_index: 0,
                tx_queue: VecDeque::new(),
                keepalive: Duration::from_secs(pc.persistent_keepalive),
                last_tx: None,
                latest_timestamp: [0u8; TIMESTAMP_LEN],
                last_initiation: None,
                last_rx_initiation: None,
                born: Instant::now(),
                init_retry: Duration::from_millis(INIT_RETRY_MIN_MS),
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

    if cfg.mdns {
        let listen_addr: SocketAddr = cfg.listen.parse()?;
        let listen_ip = listen_addr.ip();
        let listen_port = listen_addr.port();
        let dh_hex = crate::config::hex_encode(&identity_dh_pub);
        let ek_hex = crate::config::hex_encode(&shared.identity.kem.encap_bytes());
        let instance = format!("akkoro-{}", &dh_hex[..8]);
        let mdns_shared = shared.clone();
        thread::spawn(move || match mdns_sd::ServiceDaemon::new() {
            Ok(d) => {
                if let Err(e) = crate::discovery::register(
                    &d,
                    &instance,
                    listen_ip,
                    listen_port,
                    &dh_hex,
                    &ek_hex,
                ) {
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
                            }
                        }
                    }
                });
            }
            Err(e) => eprintln!("[akkoro] mDNS init failed: {e}"),
        });
    }

    let udp_rx = udp.try_clone()?;
    let rx_fd = udp_rx.as_raw_fd();
    let rx_shared = shared.clone();
    let rx_writer = tun_writer.clone();
    let rx = thread::spawn(move || {
        let mut chunk = vec![0u8; BATCH_SIZE * DATAGRAM_SIZE];
        let mut out: Vec<(usize, SocketAddr)> = Vec::with_capacity(BATCH_SIZE);
        loop {
            match recv_batch(rx_fd, &mut chunk, BATCH_SIZE, &mut out) {
                Ok(n) => {
                    for i in 0..n {
                        let (len, from) = out[i];
                        let pkt = &chunk[i * DATAGRAM_SIZE..i * DATAGRAM_SIZE + len];
                        if let Some(inner) = handle_udp(&rx_shared, &udp_rx, pkt, from) {
                            let _ = rx_writer.lock().unwrap().write_all(&inner);
                        }
                    }
                }
                Err(e) => eprintln!("[akkoro] udp recv: {e}"),
            }
        }
    });

    let udp_tx = udp.try_clone()?;
    let tx_fd = udp_tx.as_raw_fd();
    let tun_fd = tun_reader.as_raw_fd();
    let tx_shared = shared.clone();
    let tx = thread::spawn(move || {
        let mut buf = vec![0u8; 70000];
        let mut batch: Vec<(Vec<u8>, SocketAddr)> = Vec::with_capacity(BATCH_SIZE);
        let mut pfd = libc::pollfd {
            fd: tun_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let pr = unsafe { libc::poll(&mut pfd, 1, TICK_MS) };
            if pr < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::Interrupted {
                    eprintln!("[akkoro] tun poll error: {e}");
                }
                continue;
            }
            batch.clear();
            if pr > 0 {
                for _ in 0..BATCH_SIZE {
                    match tun_reader.read(&mut buf) {
                        Ok(n) => {
                            if let Some(x) = encrypt_tx_packet(&tx_shared, &udp_tx, &buf[..n]) {
                                batch.push(x);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            eprintln!("[akkoro] tun read: {e}");
                            break;
                        }
                    }
                }
                if !batch.is_empty() {
                    if let Err(e) = send_batch(tx_fd, &batch) {
                        eprintln!("[akkoro] tx sendmmsg error: {e}");
                    }
                }
            }
            tick_peers(&tx_shared, &udp_tx);
        }
    });

    rx.join().unwrap();
    tx.join().unwrap();
    Ok(())
}

/// Route + encrypt one inner IP packet; returns (wire_datagram, destination).
/// Without a live session the packet is queued (up to TX_QUEUE_CAP) and a handshake is started.
fn encrypt_tx_packet(
    shared: &Shared,
    sock: &UdpSocket,
    pkt_with_vhdr: &[u8],
) -> Option<(Vec<u8>, SocketAddr)> {
    let ip_pkt = trim_inner_packet(inner_ip(pkt_with_vhdr)?);
    let mut peers = shared.peers.lock().unwrap();
    let dst = inner_dst_ip(ip_pkt)?;
    let name = route(&peers, dst)?;
    let peer = peers.get_mut(&name)?;

    if peer.current.as_ref().is_some_and(|k| k.expired()) {
        peer.current = None;
    }
    if want_initiation(shared, peer) {
        send_initiation(shared, sock, peer);
    }
    if peer.current.is_none() && !tx_use_previous(peer) {
        enqueue_tx(peer, ip_pkt);
        return None;
    }

    let endpoint = peer.endpoint;
    let cipher = shared.cipher;
    let use_prev = tx_use_previous(peer);
    let wire = {
        let kp = if use_prev {
            peer.previous.as_mut()
        } else {
            peer.current.as_mut()
        }?;
        if kp.send_counter >= REJECT_AFTER_MESSAGES {
            return None;
        }
        let c = kp.send_counter;
        kp.send_counter += 1;
        encrypt_data(&kp.session, cipher, kp.remote_index, c, ip_pkt)
    };
    peer.last_tx = Some(Instant::now());
    Some((wire, endpoint))
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

            let mac_state = shared.cookie_checker.lock().unwrap().validate(
                &mac_input,
                &msg.macs,
                src,
                src_port,
                shared.cookie_required,
            );
            match mac_state {
                MacState::Invalid => return None,
                MacState::NeedsCookie => {
                    let mut cc = shared.cookie_checker.lock().unwrap();
                    let reply =
                        cc.create_cookie_message(&msg.macs.mac1, src, src_port, msg.sender_index);
                    let _ = sock.send_to(&reply.encode(), from);
                    return None;
                }
                _ => {}
            }

            let mut our_index = random_index();
            let mut out = consume_initiation(
                &shared.identity,
                &msg,
                shared.psk.as_deref(),
                msg.sender_index,
                our_index,
            )?;

            let mut peers = shared.peers.lock().unwrap();
            let name = match peers.iter().find(|(_, p)| p.dh_pub == out.init_dh_pub) {
                Some((n, _)) => n.clone(),
                None => return None,
            };
            let p = peers.get_mut(&name).unwrap();

            let now = Instant::now();
            let flood = p
                .last_rx_initiation
                .map(|t| now.duration_since(t) < Duration::from_millis(20))
                .unwrap_or(false);
            let replay = out.timestamp <= p.latest_timestamp;
            if flood || replay {
                return None;
            }
            p.latest_timestamp = out.timestamp;
            p.last_rx_initiation = Some(now);
            p.endpoint = from;
            let designated =
                is_designated_initiator(&shared.identity.dh_public_bytes(), &p.dh_pub);
            if designated
                && (p.pending.is_some()
                    || p.current.as_ref().is_some_and(|k| k.we_initiated))
            {
                return None;
            }
            if !designated {
                p.pending = None;
            }
            while index_in_use(p, our_index) {
                our_index = random_index();
            }
            out.response.sender_index = our_index;

            install_session(p, out.session, our_index, msg.sender_index, false, false);
            flush_tx_queue(p, shared.cipher, sock);

            let resp_mac_input = out.response.mac_input();
            out.response.macs.mac1 = cookie::compute_mac1(&p.mac1_key, &resp_mac_input);
            drop(peers);

            let _ = sock.send_to(&out.response.encode(), from);
            None
        }
        MESSAGE_HANDSHAKE_RESPONSE => {
            let msg = MessageResponse::decode(buf)?;
            let mac_input = msg.mac_input();
            let mac_state = shared.cookie_checker.lock().unwrap().validate(
                &mac_input,
                &msg.macs,
                from.ip(),
                from.port(),
                false,
            );
            if mac_state == MacState::Invalid {
                return None;
            }

            let mut peers = shared.peers.lock().unwrap();
            let name = peer_name_by_pending_index(&peers, msg.receiver_index)?;
            let p = peers.get_mut(&name)?;
            let st = p.pending.take()?;
            let session = consume_response(st, &msg)?;
            let local_index = p.pending_local_index;
            install_session(p, session, local_index, msg.sender_index, true, true);
            flush_tx_queue(p, shared.cipher, sock);
            None
        }
        MESSAGE_HANDSHAKE_COOKIE => {
            let msg = MessageCookie::decode(buf)?;
            let mut peers = shared.peers.lock().unwrap();
            let name = peer_name_by_pending_index(&peers, msg.receiver_index)?;
            let p = peers.get_mut(&name)?;
            let mac1 = p.last_mac1_sent?;
            let cookie = CookieChecker::open_cookie(&p.cookie_decryption_key, &msg, &mac1)?;
            p.cookie = Some((cookie, Instant::now()));

            let idx = p.pending_local_index;
            let endpoint = p.endpoint;
            let (mut new_msg, st) = create_initiation(
                &shared.identity,
                &p.dh_pub,
                &p.ek,
                shared.psk.as_deref(),
                idx,
            )?;
            let mac_input = new_msg.mac_input();
            let mac1 = cookie::compute_mac1(&p.mac1_key, &mac_input);
            let mac2 = cookie::compute_mac2(&cookie, &mac_input);
            new_msg.macs = MessageMacs { mac1, mac2 };
            p.last_mac1_sent = Some(mac1);
            p.pending = Some(st);
            p.last_initiation = Some(Instant::now());
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
            let name = peer_name_by_data_index(&peers, receiver_index)?;
            let p = peers.get_mut(&name)?;
            let cipher = shared.cipher;
            let inner = {
                let kp = keypair_mut(p, receiver_index)?;
                if !kp.recv_window.validate(counter) {
                    return None;
                }
                kp.confirmed = true;
                decrypt_data(&kp.session.recv_key, cipher, counter, &buf[16..])?
            };
            let ip_pkt = trim_inner_packet(&inner);
            if ip_pkt.is_empty() {
                return None;
            }
            let src = inner_src_ip(ip_pkt)?;
            if !p
                .allowed_ips
                .iter()
                .any(|(net, prefix)| cidr_match(net, *prefix, src))
            {
                return None;
            }
            Some(tun_write_payload(ip_pkt))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::is_designated_initiator;

    #[test]
    fn designated_initiator_is_lexicographic() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1;
        assert!(is_designated_initiator(&a, &b));
        assert!(!is_designated_initiator(&b, &a));
        assert!(!is_designated_initiator(&a, &a));
    }
}
