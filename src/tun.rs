//! TUN device abstraction (Linux + macOS) via the `tun` crate.

use tun::{Configuration, Device, Layer};
use std::io::{Read, Write};

/// Linux `virtio_net_hdr` size. When IFF_VNET_HDR is enabled, TUN reads/writes
/// are prefixed with this 10-byte header (carrying GSO/GRO metadata).
pub const VNET_HDR_LEN: usize = 10;

// TUNSETOFFLOAD = _IOW('T', 208, unsigned int)
#[cfg(target_os = "linux")]
const TUNSETOFFLOAD: libc::c_ulong = 0x4004_54D0;
#[cfg(target_os = "linux")]
const TUN_F_CSUM: libc::c_uint = 0x01;
#[cfg(target_os = "linux")]
const TUN_F_TSO4: libc::c_uint = 0x02;
#[cfg(target_os = "linux")]
const TUN_F_TSO6: libc::c_uint = 0x04;

pub struct TunDevice {
    dev: Device,
}

impl TunDevice {
    /// Create an L3 TUN device, assign the inner address, and bring it up.
    /// On Linux, GSO/GRO offload (IFF_VNET_HDR + TUNSETOFFLOAD) is enabled so
    /// the kernel can coalesce/segment large packets across the tunnel.
    pub fn create(name: &str, address: &str, netmask: &str, mtu: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = Configuration::default();
        config
            .tun_name(name)
            .address(address)
            .netmask(netmask)
            .mtu(mtu)
            .up()
            .layer(Layer::L3);

        // On macOS, disable the 4-byte address-family prefix so reads/writes
        // are raw IP packets, matching Linux.
        #[cfg(target_os = "macos")]
        config.platform_config(|pc| {
            pc.packet_information(false);
        });

        // On Linux, enable GSO/GRO offload (virtio_net_hdr + TUNSETOFFLOAD).
        #[cfg(target_os = "linux")]
        config.platform_config(|pc| {
            pc.vnet_hdr(true);
        });

        let dev = tun::create(&config)?;

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            // NOTE: unlike the _IOW macro suggests, the kernel reads this arg
            // as the offload bitmask VALUE directly, not as a pointer.
            let offload: libc::c_ulong = (TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6) as libc::c_ulong;
            let rc = unsafe { libc::ioctl(dev.as_raw_fd(), TUNSETOFFLOAD, offload) };
            if rc < 0 {
                eprintln!("[akkoro] TUNSETOFFLOAD failed (GSO/GRO disabled): {}", std::io::Error::last_os_error());
            }
        }

        Ok(Self { dev })
    }

    pub fn name(&self) -> String {
        use tun::AbstractDevice;
        self.dev.tun_name().unwrap_or_default()
    }

    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.dev.read(buf)
    }

    pub fn write(&mut self, pkt: &[u8]) -> std::io::Result<usize> {
        self.dev.write(pkt)
    }

    /// Split the device into an independent reader and writer (both platforms).
    pub fn into_split(self) -> (tun::Reader, tun::Writer) {
        self.dev.split()
    }

    /// Put the device into non-blocking mode.
    pub fn set_nonblock(&self) -> std::io::Result<()> {
        self.dev.set_nonblock()
    }
}
