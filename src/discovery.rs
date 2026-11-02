//! mDNS peer discovery for offline LAN operation (no DNS/STUN/TURN).
//!
//! Each node advertises `_akkoro._udp.local.` with TXT keys:
//!   - `dh` : X25519 public key (hex, 64 chars)
//!   - `ekN`: ML-KEM-768 encapsulation key, chunked into 120-hex-char pieces
//!            (a single mDNS TXT value is limited to 255 bytes; 1184-byte keys
//!            are 2368 hex chars, so they must be split)
//!   - `ekn`: number of `ekN` chunks
//!
//! Requires a real LAN/bridge to observe.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

pub const SERVICE_TYPE: &str = "_akkoro._udp.local.";
/// Max hex chars per TXT chunk (120 is safely below the 255-byte TXT limit).
const EK_CHUNK: usize = 120;

/// Register this node under `_akkoro._udp.local.`.
pub fn register(
    daemon: &ServiceDaemon,
    instance_name: &str,
    ip: IpAddr,
    port: u16,
    dh_hex: &str,
    ek_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut props = HashMap::new();
    props.insert("dh".to_string(), dh_hex.to_string());

    let mut chunks = 0usize;
    for (i, chunk) in ek_hex.as_bytes().chunks(EK_CHUNK).enumerate() {
        props.insert(format!("ek{i}"), String::from_utf8(chunk.to_vec())?);
        chunks += 1;
    }
    props.insert("ekn".to_string(), chunks.to_string());

    let info = ServiceInfo::new(
        SERVICE_TYPE,
        instance_name,
        &format!("{instance_name}.local."),
        ip,
        port,
        props,
    )?;
    daemon.register(info)?;
    Ok(())
}

/// Browse forever; `on_peer` is invoked with (dh_hex, ek_hex, endpoint) for each
/// resolved peer.
pub fn browse(
    daemon: &ServiceDaemon,
    mut on_peer: impl FnMut(String, String, SocketAddr),
) -> Result<(), Box<dyn std::error::Error>> {
    let rx = daemon.browse(SERVICE_TYPE)?;
    while let Ok(event) = rx.recv() {
        if let ServiceEvent::ServiceResolved(info) = event {
            let mut dh = None;
            let mut ek_chunks: Vec<(usize, String)> = Vec::new();
            let mut ekn = 0usize;
            for p in info.get_properties().iter() {
                match p.key() {
                    "dh" => dh = (!p.val_str().is_empty()).then(|| p.val_str().to_string()),
                    "ekn" => ekn = p.val_str().parse().unwrap_or(0),
                    k if k.starts_with("ek") => {
                        if let Ok(idx) = k[2..].parse::<usize>() {
                            if !p.val_str().is_empty() {
                                ek_chunks.push((idx, p.val_str().to_string()));
                            }
                        }
                    }
                    _ => {}
                }
            }
            ek_chunks.sort_by_key(|(i, _)| *i);
            let ek: String = ek_chunks.into_iter().take(ekn).map(|(_, s)| s).collect();

            if let (Some(dh), true) = (dh, !ek.is_empty()) {
                if let Some(ip) = info.get_addresses_v4().into_iter().next() {
                    on_peer(dh, ek, SocketAddr::new(std::net::IpAddr::V4(ip), info.get_port()));
                }
            }
        }
    }
    Ok(())
}
