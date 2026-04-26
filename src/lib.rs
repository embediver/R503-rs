#![no_std]

use embedded_io_async::{Read, Write};
use zerocopy::{IntoBytes, TryFromBytes};

use crate::types::{Error, Package, PackageHeader};
mod types;

pub struct R503<T: Read + Write> {
    serial: T,
    pwd: u32,
    authenticated: bool,
}

impl<T: Read + Write> R503<T> {
    /// Create a new R503 struct.
    /// If `pwd` is not supplied the default password `0x00000000` is used.
    pub fn new(serial: T, pwd: Option<u32>) -> R503<T> {
        R503 {
            serial,
            pwd: pwd.unwrap_or_default(),
            authenticated: false,
        }
    }
    async fn read_packet<'a>(&mut self, buf: &'a mut [u8]) -> Result<Package<'a>, Error<T>> {
        let header_buf = buf
            .get_mut(0..size_of::<PackageHeader>())
            .ok_or(Error::BufTooSmall)?;
        self.serial.read_exact(header_buf).await?;
        let pckg_header =
            PackageHeader::try_read_from_bytes(header_buf).map_err(|_| Error::InvalidPid)?;
        if pckg_header.header != PackageHeader::HEADER {
            return Err(Error::InvalidHeader);
        }

        let content_buf = buf
            .get_mut(0..pckg_header.length as usize - 2)
            .ok_or(Error::BufTooSmall)?;
        self.serial.read_exact(content_buf).await?;

        let mut checksum = [0; 2];
        self.serial.read_exact(&mut checksum).await?;
        let pckg = Package {
            pckg_header,
            data: content_buf,
            checksum: u16::from_be_bytes(checksum),
        };

        if !verify_checksum(&pckg) {
            return Err(Error::Checksum);
        }
        return Ok(pckg);
    }
    /// Verify Module's handshaking password.
    pub async fn vfy_pwd(&mut self) {
        todo!()
    }
    /// Write packet to the module. The checksum is generated automatically.
    async fn write_packet(&mut self, pckg: &Package<'_>) -> Result<(), Error<T>> {
        let header = pckg.pckg_header.as_bytes();
        let checksum = pckg.generate_checksum().to_be_bytes();
        self.serial
            .write_all(header)
            .await
            .map_err(Error::WriteErr)?;
        self.serial
            .write_all(pckg.data)
            .await
            .map_err(Error::WriteErr)?;
        self.serial
            .write_all(&checksum)
            .await
            .map_err(Error::WriteErr)
    }
}

fn verify_checksum(pckg: &Package) -> bool {
    let mut checksum: u16 = 0;
    checksum = checksum.wrapping_add(pckg.pckg_header.pid as u16);
    checksum = checksum.wrapping_add(pckg.pckg_header.length);
    for d in pckg.data {
        checksum = checksum.wrapping_add(*d as u16);
    }
    return pckg.checksum == checksum;
}
