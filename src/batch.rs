//! Batched UDP I/O (Linux `recvmmsg`/`sendmmsg`) to amortize syscall overhead
//! on the hot data path. On non-Linux platforms this falls back to single
//! `recvfrom`/`sendto`.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::os::fd::RawFd;

pub const BATCH_SIZE: usize = 64;
/// Per-datagram buffer size. Must exceed the largest wire message: a GSO
/// super-packet can be ~64 KB (plus the 10-byte vnet_hdr and AEAD overhead).
pub const DATAGRAM_SIZE: usize = 70000;

/// Receive up to `max` datagrams. Blocks until at least one arrives, then
/// drains whatever else is queued. `chunk` must hold `max * DATAGRAM_SIZE` bytes.
/// On success, `out` is filled with `(len, src_addr)` and the count is returned.
pub fn recv_batch(
    fd: RawFd,
    chunk: &mut [u8],
    max: usize,
    out: &mut Vec<(usize, SocketAddr)>,
) -> io::Result<usize> {
    out.clear();
    if max == 0 {
        return Ok(0);
    }
    let max = max.min(BATCH_SIZE);

    #[cfg(target_os = "linux")]
    {
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(max);
        let mut addrs: Vec<libc::sockaddr_storage> = vec![unsafe { mem::zeroed() }; max];
        let mut hdrs: Vec<libc::mmsghdr> = Vec::with_capacity(max);
        for i in 0..max {
            let base = i * DATAGRAM_SIZE;
            iovecs.push(libc::iovec {
                iov_base: unsafe { chunk.as_mut_ptr().add(base) } as *mut _,
                iov_len: DATAGRAM_SIZE,
            });
        }
        for i in 0..max {
            hdrs.push(libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &mut addrs[i] as *mut _ as *mut _,
                    msg_namelen: mem::size_of::<libc::sockaddr_storage>() as u32,
                    msg_iov: &mut iovecs[i],
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            });
        }

        // A blocking recvmmsg() blocks until vlen messages arrive (not "up to
        // vlen"), so poll for readability first, then drain non-blocking.
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        loop {
            let pr = unsafe { libc::poll(&mut pfd, 1, -1) };
            if pr < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if pr > 0 {
                break;
            }
        }

        let n = unsafe {
            libc::recvmmsg(
                fd,
                hdrs.as_mut_ptr(),
                max as u32,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        for i in 0..n as usize {
            let len = hdrs[i].msg_len as usize;
            let sa = unsafe { &*(&addrs[i] as *const _ as *const libc::sockaddr) };
            let addr = sockaddr_to_addr(sa).unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
            out.push((len, addr));
        }
        Ok(n as usize)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let cap = (max * DATAGRAM_SIZE).min(chunk.len());
        let mut sa: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut slen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                fd,
                chunk.as_mut_ptr() as *mut _,
                cap,
                0,
                &mut sa as *mut _ as *mut _,
                &mut slen,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let addr = sockaddr_to_addr(unsafe { &*(&sa as *const _ as *const libc::sockaddr) })
            .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
        out.push((n as usize, addr));
        Ok(1)
    }
}

/// Send a batch of (bytes, destination) datagrams in as few syscalls as
/// possible. Returns the number of datagrams fully sent.
pub fn send_batch(fd: RawFd, packets: &[(Vec<u8>, SocketAddr)]) -> io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }

    #[cfg(target_os = "linux")]
    {
        let mut hdrs: Vec<libc::mmsghdr> = Vec::with_capacity(packets.len());
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(packets.len());
        let mut addrs: Vec<libc::sockaddr_storage> = Vec::with_capacity(packets.len());
        for (bytes, addr) in packets {
            let mut sa: libc::sockaddr_storage = unsafe { mem::zeroed() };
            addr_to_sockaddr(*addr, &mut sa);
            addrs.push(sa);
            iovecs.push(libc::iovec {
                iov_base: bytes.as_ptr() as *mut _,
                iov_len: bytes.len(),
            });
        }
        for i in 0..packets.len() {
            hdrs.push(libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &mut addrs[i] as *mut _ as *mut _,
                    msg_namelen: sockaddr_len(&addrs[i]),
                    msg_iov: &mut iovecs[i],
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            });
        }
        let n = unsafe {
            libc::sendmmsg(fd, hdrs.as_mut_ptr(), hdrs.len() as u32, 0)
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut sent = 0;
        for (bytes, addr) in packets {
            let mut sa: libc::sockaddr_storage = unsafe { mem::zeroed() };
            addr_to_sockaddr(*addr, &mut sa);
            let r = unsafe {
                libc::sendto(
                    fd,
                    bytes.as_ptr() as *const _,
                    bytes.len(),
                    0,
                    &sa as *const _ as *const libc::sockaddr,
                    sockaddr_len(&sa),
                )
            };
            if r < 0 {
                break;
            }
            sent += 1;
        }
        Ok(sent)
    }
}

fn sockaddr_to_addr(sa: &libc::sockaddr) -> Option<SocketAddr> {
    match sa.sa_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(sa as *const _ as *const libc::sockaddr_in) };
            // s_addr is stored in network byte order; to_ne_bytes() yields the
            // octets in the correct order.
            let ip = sin.sin_addr.s_addr.to_ne_bytes();
            Some(SocketAddr::from(([ip[0], ip[1], ip[2], ip[3]], u16::from_be(sin.sin_port))))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(sa as *const _ as *const libc::sockaddr_in6) };
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&sin6.sin6_addr.s6_addr);
            Some(SocketAddr::from((
                std::net::Ipv6Addr::from(octets),
                u16::from_be(sin6.sin6_port),
            )))
        }
        _ => None,
    }
}

fn addr_to_sockaddr(addr: SocketAddr, out: &mut libc::sockaddr_storage) {
    unsafe {
        match addr {
            SocketAddr::V4(v4) => {
                let sin = out as *mut _ as *mut libc::sockaddr_in;
                (*sin).sin_family = libc::AF_INET as _;
                (*sin).sin_port = v4.port().to_be();
                // s_addr must hold the octets in network byte order, i.e. the
                // native-endian u32 whose memory bytes are the octets.
                (*sin).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
                {
                    (*sin).sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
                }
            }
            SocketAddr::V6(v6) => {
                let sin6 = out as *mut _ as *mut libc::sockaddr_in6;
                (*sin6).sin6_family = libc::AF_INET6 as _;
                (*sin6).sin6_port = v6.port().to_be();
                (*sin6).sin6_addr.s6_addr = v6.ip().octets();
                (*sin6).sin6_scope_id = 0;
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
                {
                    (*sin6).sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
                }
            }
        }
    }
}

fn sockaddr_len(sa: &libc::sockaddr_storage) -> u32 {
    match sa.ss_family as libc::c_int {
        libc::AF_INET => mem::size_of::<libc::sockaddr_in>() as u32,
        libc::AF_INET6 => mem::size_of::<libc::sockaddr_in6>() as u32,
        _ => mem::size_of::<libc::sockaddr_storage>() as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_roundtrip() {
        for addr in [
            "10.9.0.1:51820".parse().unwrap(),
            "172.30.0.11:51820".parse().unwrap(),
            "8.8.8.8:53".parse().unwrap(),
            "[fd00::1]:51820".parse().unwrap(),
        ] {
            let mut sa: libc::sockaddr_storage = unsafe { mem::zeroed() };
            addr_to_sockaddr(addr, &mut sa);
            let back = sockaddr_to_addr(unsafe { &*(&sa as *const _ as *const libc::sockaddr) }).unwrap();
            assert_eq!(addr, back, "roundtrip failed for {addr}");
        }
    }
}
