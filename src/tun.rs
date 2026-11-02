//! TUN device abstraction (Linux + macOS) via the `tun` crate.

use tun::{Configuration, Device, Layer};
use std::io::{Read, Write};

pub struct TunDevice {
    dev: Device,
}

impl TunDevice {
    /// Create an L3 TUN device, assign the inner address, and bring it up.
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
