//! IP packet helpers and CIDR matching (pure, testable).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Longest-prefix CIDR containment check.
pub fn cidr_match(net: &IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(d)) => {
            let n = u32::from_be_bytes(n.octets());
            let d = u32::from_be_bytes(d.octets());
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            (n & mask) == (d & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(d)) => {
            let n = u128::from_be_bytes(n.octets());
            let d = u128::from_be_bytes(d.octets());
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            (n & mask) == (d & mask)
        }
        _ => false,
    }
}

/// Destination IP from the start of an IPv4/IPv6 packet.
pub fn inner_dst_ip(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first().map(|v| v >> 4) {
        Some(4) if pkt.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))),
        Some(6) if pkt.len() >= 40 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&pkt[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

/// Source IP from the start of an IPv4/IPv6 packet.
pub fn inner_src_ip(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first().map(|v| v >> 4) {
        Some(4) if pkt.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))),
        Some(6) if pkt.len() >= 40 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&pkt[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

/// Trim a decrypted (possibly zero-padded) IP packet to its self-declared length.
pub fn trim_inner_packet(pkt: &[u8]) -> &[u8] {
    match pkt.first().map(|v| v >> 4) {
        Some(4) if pkt.len() >= 20 => {
            let len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            &pkt[..len.min(pkt.len())]
        }
        Some(6) if pkt.len() >= 40 => {
            let len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize + 40;
            &pkt[..len.min(pkt.len())]
        }
        _ => pkt,
    }
}

pub fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), Box<dyn std::error::Error>> {
    let (addr, prefix) = cidr.split_once('/').ok_or("cidr must be a.b.c.d/n")?;
    let ip: IpAddr = addr.parse()?;
    let prefix: u8 = prefix.parse()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err("cidr prefix too large".into());
    }
    Ok((ip, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn cidr_ipv4() {
        let net = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 0));
        assert!(cidr_match(&net, 24, IpAddr::V4(Ipv4Addr::new(10, 9, 0, 5))));
        assert!(!cidr_match(&net, 24, IpAddr::V4(Ipv4Addr::new(10, 9, 1, 5))));
        assert!(cidr_match(&net, 0, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(cidr_match(&net, 32, IpAddr::V4(Ipv4Addr::new(10, 9, 0, 0))));
        assert!(!cidr_match(&net, 32, IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1))));
    }

    #[test]
    fn cidr_ipv6() {
        let net = IpAddr::V6("fd00::".parse::<Ipv6Addr>().unwrap());
        assert!(cidr_match(&net, 64, IpAddr::V6("fd00::1234:5678:9abc:def0".parse::<Ipv6Addr>().unwrap())));
        assert!(!cidr_match(&net, 64, IpAddr::V6("fd00:0:0:1::1".parse::<Ipv6Addr>().unwrap())));
        assert!(cidr_match(&net, 0, IpAddr::V6("::1".parse::<Ipv6Addr>().unwrap())));
    }

    #[test]
    fn ip_src_dst() {
        // minimal IPv4 header, src=1.2.3.4, dst=5.6.7.8
        let pkt = [0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(inner_src_ip(&pkt), Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert_eq!(inner_dst_ip(&pkt), Some(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))));
    }
}
