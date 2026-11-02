//! TUN device abstraction (Linux + macOS) via the `tun` crate.

use tun::{Configuration, Device, Layer};
use std::io::{Read, Write};

pub struct TunDevice {
    dev: Device,
}

impl TunDevice {
    /// Create an L3 TUN device, assign the inner address, and bring it up.
    /// `destination` is the point-to-point peer; macOS needs it to install a
    /// utun route.
    pub fn create(
        name: &str,
        address: &str,
        netmask: &str,
        mtu: u16,
        destination: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = Configuration::default();
        // Linux accepts akkoro0. macOS only accepts utunN; omit the name and
        // let the kernel pick one.
        #[cfg(not(target_os = "macos"))]
        config.tun_name(name);
        #[cfg(target_os = "macos")]
        let _ = name;
        config
            .address(address)
            .netmask(netmask)
            .mtu(mtu)
            .up()
            .layer(Layer::L3);
        if let Some(dst) = destination {
            config.destination(dst);
        }

        // utun always prefixes a 4-byte AF header; PI must stay on so the crate strips it.
        #[cfg(target_os = "macos")]
        config.platform_config(|pc| {
            pc.packet_information(true);
        });

        // Do not enable IFF_VNET_HDR / TUNSETOFFLOAD. Checksum offload leaves a
        // placeholder TCP checksum on the wire; macOS utun drops those packets
        // (ICMP still works, SSH hangs).
        let dev = tun::create(&config)?;

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
