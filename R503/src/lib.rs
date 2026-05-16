#![no_std]

use defmt::{error, info, trace, warn};
use embedded_io_async::{Read, Write};
use zerocopy::{IntoBytes, TryFromBytes};

use crate::types::{CommandCode, ConfirmationCode, Error, Package, PackageHeader, Pid};
mod types;

pub struct R503<T: Read + Write> {
    serial: T,
    pwd: u32,
    authenticated: bool,
    address: u32,
}

impl<T: Read + Write> R503<T> {
    /// Create a new R503 struct.
    /// If `pwd` is not supplied the default password `0x00000000` is used.
    pub fn new(serial: T, pwd: Option<u32>, addr: Option<u32>) -> R503<T> {
        R503 {
            serial,
            pwd: pwd.unwrap_or_default(),
            authenticated: false,
            address: addr.unwrap_or(0xFFFFFFFF),
        }
    }
    /// Read a packet from the module. The checksum is verified automatically.
    async fn read_packet<'a>(&mut self, buf: &'a mut [u8]) -> Result<Package<'a>, Error<T::Error>> {
        let header_buf = buf
            .get_mut(0..size_of::<PackageHeader>())
            .ok_or(Error::BufTooSmall)?;
        self.serial.read_exact(header_buf).await?;
        let pckg_header = PackageHeader::try_read_from_bytes(header_buf).map_err(|_| {
            warn!("Failed to parse header from buffer: {:02x}", header_buf);
            Error::InvalidPid
        })?;
        if pckg_header.header != PackageHeader::HEADER {
            let magic = pckg_header.header;
            warn!(
                "Magic number mismatch (got {:04x}, expected {:04x})",
                magic,
                PackageHeader::HEADER
            );
            return Err(Error::InvalidHeader);
        }

        let buf_len = buf.len();
        let content_buf = buf.get_mut(0..pckg_header.length as usize - 2).ok_or({
            error!(
                "Buffer to small: expected at most {} bytes, sensor tried to send {} bytes",
                buf_len,
                pckg_header.length - 2
            );
            Error::BufTooSmall
        })?;
        self.serial.read_exact(content_buf).await?;

        let mut checksum = [0; 2];
        self.serial.read_exact(&mut checksum).await?;
        let pckg = Package {
            pckg_header,
            data: content_buf,
            checksum: u16::from_be_bytes(checksum),
        };

        let pid = pckg.pckg_header.pid;

        info!("Received {} package", pid);

        if !verify_checksum(&pckg) {
            return Err(Error::Checksum);
        }
        Ok(pckg)
    }

    /// Verify Module's handshaking password.
    pub async fn vfy_pwd(&mut self) -> Result<(), Error<T::Error>> {
        let pwd = self.pwd.to_be_bytes();
        let data = [CommandCode::VfyPwd as u8, pwd[0], pwd[1], pwd[2], pwd[3]];
        let pckg = Package::new(Pid::Command, self.address, &data);
        self.write_packet(&pckg).await?;
        let mut buf = [0; 12];
        let pckg = self.read_packet(&mut buf).await?;
        let code = ConfirmationCode::try_read_from_bytes(&pckg.data[..1])
            .map_err(|_| Error::InvalidContent)?;
        if code.is_error() {
            return Err(Error::CommandErr(code));
        }
        self.authenticated = true;
        Ok(())
    }

    /// Write packet to the module. The checksum is generated automatically.
    async fn write_packet(&mut self, pckg: &Package<'_>) -> Result<(), Error<T::Error>> {
        let header = pckg.pckg_header.as_bytes();
        let checksum = pckg.generate_checksum().to_be_bytes();
        trace!(
            "Writing packet: header = {:02x}, data = {:02x}, checksum = {:02x}",
            header, pckg.data, checksum
        );
        self.serial.write_all(header).await?;
        self.serial.write_all(pckg.data).await?;
        Ok(self.serial.write_all(&checksum).await?)
    }
}

fn verify_checksum(pckg: &Package) -> bool {
    let mut checksum: u16 = 0;
    checksum = checksum.wrapping_add(pckg.pckg_header.pid as u16);
    checksum = checksum.wrapping_add(pckg.pckg_header.length);
    for d in pckg.data {
        checksum = checksum.wrapping_add(*d as u16);
    }
    pckg.checksum == checksum
}
