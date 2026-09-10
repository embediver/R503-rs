#![cfg_attr(not(test), no_std)]

//! # R503 Fingerprint Reader - Driver
//!
//! An [embedded-io-async](https://crates.io/crates/embedded-io-async) driver for the Grow R503 fingerprint reader.
//!
//! # Example
//! ```no_run
//! # smol::block_on( async {
//! # use r503_mock::*;
//! use r503::{R503, ConfirmationCode};
//! # let serial = SerialMock::new(&[]);
//!
//! let address = 0x1234_5678;
//! let password = 0xDEAD_BEEF;
//!
//! let mut r503 = R503::new(serial, Some(password), Some(address));
//! // Unlock the sensor
//! r503.vfy_pwd().await?;
//! // Check that the sensor is operational
//! if r503.check_sensor().await? == ConfirmationCode::SensorAbnormal {
//!    // Handle hardware error
//! }
//! // Take an image of a finger
//! r503.gen_image().await?;
//! // Process and match the image...
//! # Ok::<_, r503::Error<core::convert::Infallible>>(())
//! # });
//! ```
//! Take a look at the examples for a complete usage example.
//!
//! # Note
//! While the data on the sensor is protected with a password,
//! there is __no__ authentication of the sensor and
//! __no__ encryption of the communication.
//! Be aware that therefor an attacker with physical access to the serial
//! communication can impersonate a sensor, gaining access to the system
//! and/or fingerprint library stored on the sensor.
//!
//! ## License
//! Licensed under either of:
//!
//! - Apache License, Version 2.0 ([LICENSE-APACHE](/LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
//! - MIT license ([LICENSE-MIT](/LICENSE-MIT) or <http://opensource.org/licenses/MIT>)
//!
//! at your option.

use defmt::{debug, error, info, trace, warn};
use embedded_io_async::{Read, Write};
use zerocopy::{IntoBytes, TryFromBytes};

use crate::{
    led::LedConfig,
    types::{CommandCode, Package, PackageHeader, Pid, SearchResult},
};

pub use types::{CharacterBuffer, ConfirmationCode, Error, SlotTable, SystemParameters};

pub mod led;
#[cfg(test)]
mod tests;
mod types;

/// R503 sensor instance
pub struct R503<T: Read + Write> {
    serial: T,
    pwd: u32,
    authenticated: bool,
    address: u32,
    parameters: Option<SystemParameters>,
}

impl<T: Read + Write> R503<T> {
    /// Create a new R503 instance.
    ///
    /// If `addr` is not supplied the default address `0xFFFFFFFF` is used.
    /// If `pwd` is not supplied the default password `0x00000000` is used.
    pub fn new(serial: T, pwd: Option<u32>, addr: Option<u32>) -> R503<T> {
        R503 {
            serial,
            pwd: pwd.unwrap_or_default(),
            authenticated: false,
            address: addr.unwrap_or(0xFFFFFFFF),
            parameters: None,
        }
    }

    /// Deconstruct the R503 instance yielding the contained serial peripheral.
    pub fn destroy(self) -> T {
        self.serial
    }

    /// Get a mutable reference to the underlying serial line
    ///
    /// This might be used for reconfiguration purposes
    /// (e.g. after changing the baud rate).
    pub fn serial(&mut self) -> &mut T {
        &mut self.serial
    }

    /// Read a packet from the module. The checksum is verified automatically.
    async fn read_packet<'a>(&mut self, buf: &'a mut [u8]) -> Result<Package<'a>, Error<T::Error>> {
        let header_buf = buf
            .get_mut(0..size_of::<PackageHeader>())
            .ok_or(Error::BufToSmall)?;
        self.serial.read_exact(header_buf).await?;
        let pckg_header = PackageHeader::try_read_from_bytes(header_buf).map_err(|_| {
            warn!("Failed to parse header from buffer: {:02x}", header_buf);
            Error::InvalidPid
        })?;
        if pckg_header.header != PackageHeader::HEADER {
            let magic = pckg_header.header;
            warn!(
                "Magic number mismatch (got {:04x}, expected {:04x})",
                magic.get(),
                PackageHeader::HEADER
            );
            return Err(Error::InvalidHeader);
        }
        trace!(
            "Successfully read package header with PID {}",
            pckg_header.pid
        );

        let buf_len = buf.len();
        let content_buf = buf
            .get_mut(0..pckg_header.length.get() as usize - 2)
            .ok_or_else(|| {
                error!(
                    "Buffer to small: expected at most {} bytes, sensor tried to send {} bytes",
                    buf_len,
                    pckg_header.length.get() - 2
                );
                Error::BufToSmall
            })?;
        debug!("Trying to read {} bytes of payload...", content_buf.len());
        self.serial.read_exact(content_buf).await?;

        debug!("Trying to read 2 bytes of checksum...");
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
    ///
    /// This has to be called to unlock the sensor.
    /// The instance tries to keep of the current state
    /// and unlocks the sensor automatically if necessary.
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

    /// Control the _Aura LED_ ring.
    pub async fn led_control(&mut self, config: LedConfig) -> Result<(), Error<T::Error>> {
        if !self.authenticated {
            self.authenticated = false;
            self.vfy_pwd().await?;
        }
        let pckg = Package::new(Pid::Command, self.address, config.as_bytes());
        self.write_packet(&pckg).await?;
        let mut buf = [0; 12];
        let pckg = self.read_packet(&mut buf).await?;
        let code = ConfirmationCode::try_read_from_bytes(&pckg.data[..1])
            .map_err(|_| Error::InvalidContent)?;
        if code.is_error() {
            return Err(Error::CommandErr(code));
        }
        Ok(())
    }

    /// Check the sensor status
    ///
    /// # Returns
    /// - `Ok` [ConfirmationCode::Ok] on normal operation
    /// - `Ok` [ConfirmationCode::SensorAbnormal] on abnormal sensor status
    /// - `Err` [Error] when command execution isn't successfull
    pub async fn check_sensor(&mut self) -> Result<ConfirmationCode, Error<T::Error>> {
        if !self.authenticated {
            self.authenticated = false;
            self.vfy_pwd().await?;
        }
        let pckg = Package::new(
            Pid::Command,
            self.address,
            &[CommandCode::CheckSensor as u8],
        );
        self.write_packet(&pckg).await?;
        let mut buf = [0; 12];
        let pckg = self.read_packet(&mut buf).await?;
        let code = ConfirmationCode::try_read_from_bytes(&pckg.data[..1])
            .map_err(|_| Error::InvalidContent)?;
        if code.is_error() {
            return Err(Error::CommandErr(code));
        }
        Ok(code)
    }

    /// Collect a finger image and store it into the internal image buffer.
    ///
    /// # Returns
    /// - `Ok` [ConfirmationCode::Ok] on successfull image collection
    /// - `CommandErr` [ConfirmationCode::NoFinger] when no finger is detected
    /// - `CommandErr` [ConfirmationCode::EnrollErr] when collection failed
    /// - `Err` [Error] when other errors occur
    pub async fn gen_image(&mut self) -> Result<ConfirmationCode, Error<T::Error>> {
        if !self.authenticated {
            self.authenticated = false;
            self.vfy_pwd().await?;
        }
        let pckg = Package::new(Pid::Command, self.address, &[CommandCode::GenImg as u8]);
        self.write_packet(&pckg).await?;
        let mut buf = [0; 12];
        let pckg = self.read_packet(&mut buf).await?;
        let code = ConfirmationCode::try_read_from_bytes(&pckg.data[..1])
            .map_err(|_| Error::InvalidContent)?;
        if code.is_error() {
            return Err(Error::CommandErr(code));
        }
        Ok(code)
    }

    /// Collect a finger image and store it into the internal image buffer.
    ///
    /// As opposed to [gen_image](Self::gen_image), [gen_imgage_ex](Self::gen_image_ex) returns [ConfirmationCode::ErrTooLittleData]
    /// when the image quality is to poor.
    ///
    /// # Returns
    /// - `Ok` [ConfirmationCode::Ok] on successfull image collection
    /// - `CommandErr` [ConfirmationCode::NoFinger] when no finger is detected
    /// - `CommandErr` [ConfirmationCode::EnrollErr] when collection failed
    /// - `CommandErr` [ConfirmationCode::ErrTooLittleData] when image quality is poor
    /// - `Err` [Error] when other errors occur
    pub async fn gen_image_ex(&mut self) -> Result<ConfirmationCode, Error<T::Error>> {
        if !self.authenticated {
            self.authenticated = false;
            self.vfy_pwd().await?;
        }
        let pckg = Package::new(Pid::Command, self.address, &[CommandCode::GenImg as u8]);
        self.write_packet(&pckg).await?;
        let mut buf = [0; 12];
        let pckg = self.read_packet(&mut buf).await?;
        let code = ConfirmationCode::try_read_from_bytes(&pckg.data[..1])
            .map_err(|_| Error::InvalidContent)?;
        if code.is_error() {
            return Err(Error::CommandErr(code));
        }
        Ok(code)
    }

    /// Generate a character file from a finger image.
    ///
    /// The character file is stored in one of the available [CaracterBuffers](CharacterBuffer).
    ///
    /// # Returns
    /// - `Ok` [ConfirmationCode::Ok] on successfull generation
    /// - `CommandErr` [ErrTooNoisyData](ConfirmationCode::ErrTooNoisyData),
    ///   [ErrTooLittleData](ConfirmationCode::ErrTooLittleData) or
    ///   [NoValidImage](ConfirmationCode::NoValidImage) when generation failed
    /// - `Err` [Error] when other errors occur
    pub async fn img2tz(
        &mut self,
        buffer: CharacterBuffer,
    ) -> Result<ConfirmationCode, Error<T::Error>> {
        if !self.authenticated {
            self.authenticated = false;
            self.vfy_pwd().await?;
        }
        let data = &[CommandCode::Img2Tz as u8, buffer as u8];
        let pckg = Package::new(Pid::Command, self.address, data);
        self.write_packet(&pckg).await?;
        let mut buf = [0; 12];
        let pckg = self.read_packet(&mut buf).await?;
        let code = ConfirmationCode::try_read_from_bytes(&pckg.data[..1])
            .map_err(|_| Error::InvalidContent)?;
        if code.is_error() {
            return Err(Error::CommandErr(code));
        }
        Ok(code)
    }

    /// Generate a template file from two character files.
    ///
    /// Combine both [CaracterBuffers](CharacterBuffer) into a template.
    /// The template is stored in both [CaracterBuffers](CharacterBuffer).
    ///
    /// # Returns
    /// - `Ok` [ConfirmationCode::Ok] on successfull generation
    /// - `CommandErr` [FileCombinationFailed](ConfirmationCode::FileCombinationFailed)
    ///   when the characters files don't belong to the same finger
    /// - `Err` [Error] when other errors occur
    pub async fn gen_template(&mut self) -> Result<ConfirmationCode, Error<T::Error>> {
        if !self.authenticated {
            self.authenticated = false;
            self.vfy_pwd().await?;
        }
        let data = &[CommandCode::GenTemplate as u8];
        let pckg = Package::new(Pid::Command, self.address, data);
        self.write_packet(&pckg).await?;
        let mut buf = [0; 12];
        let pckg = self.read_packet(&mut buf).await?;
        let code = ConfirmationCode::try_read_from_bytes(&pckg.data[..1])
            .map_err(|_| Error::InvalidContent)?;
        if code.is_error() {
            return Err(Error::CommandErr(code));
        }
        Ok(code)
    }

    /// Store a template file in flash memory.
    ///
    /// Writes a template to a `page_id` in flash.
    ///
    /// # Returns
    /// - `Ok` [ConfirmationCode::Ok] on success
    /// - `CommandErr` [PageIdBeyondLibrary](ConfirmationCode::PageIdBeyondLibrary)
    ///   when the `page_id` is invalid
    /// - `CommandErr` [ErrorWritingFlash](ConfirmationCode::ErrorWritingFlash)
    ///   when writing to the flash failed
    /// - `Err` [Error] when other errors occur
    pub async fn store_template(
        &mut self,
        buffer: CharacterBuffer,
        page_id: u16,
    ) -> Result<ConfirmationCode, Error<T::Error>> {
        if !self.authenticated {
            self.authenticated = false;
            self.vfy_pwd().await?;
        }
        let page_id = page_id.to_be_bytes();
        let data = &[
            CommandCode::StoreTemplate as u8,
            buffer as u8,
            page_id[0],
            page_id[1],
        ];
        let pckg = Package::new(Pid::Command, self.address, data);
        self.write_packet(&pckg).await?;
        let mut buf = [0; 12];
        let pckg = self.read_packet(&mut buf).await?;
        let code = ConfirmationCode::try_read_from_bytes(&pckg.data[..1])
            .map_err(|_| Error::InvalidContent)?;
        if code.is_error() {
            return Err(Error::CommandErr(code));
        }
        Ok(code)
    }

    /// Search the fingerprint flash library for a matching template.
    ///
    /// Searches for a template that matches the [CharacterBuffer]
    /// and returns the `page_id`.
    /// The `start_id` specifies the start slot where search begins.
    ///
    /// # Returns
    /// - `Ok(template_id)` on success
    /// - `CommandErr` [PageIdBeyondLibrary](ConfirmationCode::PageIdBeyondLibrary)
    ///   when the `page_id` is invalid
    /// - `CommandErr` [ErrorWritingFlash](ConfirmationCode::ErrorWritingFlash)
    ///   when writing to the flash failed
    /// - `Err` [Error] when other errors occur
    pub async fn search_for_match(
        &mut self,
        buffer: CharacterBuffer,
        start_id: u16,
    ) -> Result<u16, Error<T::Error>> {
        if !self.authenticated {
            self.authenticated = false;
            self.vfy_pwd().await?;
        }
        let para = match self.parameters {
            Some(p) => p,
            None => self.read_system_parameters().await?,
        };
        let start_page = start_id.to_be_bytes();
        let end_page = para.get_library_size().to_be_bytes();
        let data = &[
            CommandCode::SearchLibrary as u8,
            buffer as u8,
            start_page[0],
            start_page[1],
            end_page[0],
            end_page[1],
        ];

        let pckg = Package::new(Pid::Command, self.address, data);
        self.write_packet(&pckg).await?;
        let mut buf = [0; 12];
        let pckg = self.read_packet(&mut buf).await?;
        trace!("Received packet with data: {:02x}", pckg.data);
        let result =
            SearchResult::try_read_from_bytes(pckg.data).map_err(|_| Error::InvalidContent)?;
        if result.code.is_error() {
            return Err(Error::CommandErr(result.code));
        }
        debug!(
            "Successfully matched finger with library id {}, score {}",
            result.page_id.get(),
            result.score.get()
        );
        Ok(result.page_id.get())
    }

    /// Read the number of stored templates.
    ///
    /// # Returns
    /// - Number of stored templates on success
    /// - [Error] when other errors occur
    pub async fn get_library_count(&mut self) -> Result<u16, Error<T::Error>> {
        if !self.authenticated {
            self.authenticated = false;
            self.vfy_pwd().await?;
        }
        let data = &[CommandCode::GetTemplateCount as u8];
        let pckg = Package::new(Pid::Command, self.address, data);
        self.write_packet(&pckg).await?;
        let mut buf = [0; 12];
        let pckg = self.read_packet(&mut buf).await?;
        let code = ConfirmationCode::try_read_from_bytes(&pckg.data[..1])
            .map_err(|_| Error::InvalidContent)?;
        if code.is_error() {
            return Err(Error::CommandErr(code));
        }
        let count = pckg.data.get(1..3).ok_or(Error::InvalidContent)?;
        Ok(u16::from_be_bytes([count[0], count[1]]))
    }

    /// Delete every template stored in the flash library.
    pub async fn empty_library(&mut self) -> Result<(), Error<T::Error>> {
        if !self.authenticated {
            self.authenticated = false;
            self.vfy_pwd().await?;
        }
        let data = &[CommandCode::ClearLibrary as u8];
        let pckg = Package::new(Pid::Command, self.address, data);
        self.write_packet(&pckg).await?;
        let mut buf = [0; 12];
        let pckg = self.read_packet(&mut buf).await?;
        let code = ConfirmationCode::try_read_from_bytes(&pckg.data[..1])
            .map_err(|_| Error::InvalidContent)?;
        if code.is_error() {
            return Err(Error::CommandErr(code));
        }
        Ok(())
    }

    /// Read system parameters.
    ///
    /// Reads the system parameters from the sensor.
    ///
    /// # Returns
    /// - `Ok` [SystemParameters] on success
    /// - `Err` [Error] when other errors occur
    pub async fn read_system_parameters(&mut self) -> Result<SystemParameters, Error<T::Error>> {
        if !self.authenticated {
            self.authenticated = false;
            self.vfy_pwd().await?;
        }
        let data = &[CommandCode::ReadSysPara as u8];
        let pckg = Package::new(Pid::Command, self.address, data);
        self.write_packet(&pckg).await?;
        let mut buf = [0; 17];
        let pckg = self.read_packet(&mut buf).await?;
        let code = ConfirmationCode::try_read_from_bytes(&pckg.data[..1])
            .map_err(|_| Error::InvalidContent)?;
        if code.is_error() {
            return Err(Error::CommandErr(code));
        }
        let (_, para) =
            SystemParameters::try_read_from_suffix(pckg.data).map_err(|_| Error::InvalidContent)?;

        self.parameters = Some(para);
        Ok(para)
    }

    /// Delete templates by specifying the start slot and number of templates to be deleted.
    ///
    /// # Returns
    /// - `Ok(())` on success
    /// - `CommandErr` [ErrDeletingTemplates](ConfirmationCode::ErrDeletingTemplates) when deletion failed
    /// - `Err` [Error] when other errors occur
    pub async fn delete_templates(&mut self, slot: u16, count: u16) -> Result<(), Error<T::Error>> {
        if !self.authenticated {
            self.authenticated = false;
            self.vfy_pwd().await?;
        }
        let start_slot = slot.to_be_bytes();
        let slot_count = count.to_be_bytes();
        let data = &[
            CommandCode::DeleteTemplate as u8,
            start_slot[0],
            start_slot[1],
            slot_count[0],
            slot_count[1],
        ];
        let pckg = Package::new(Pid::Command, self.address, data);
        self.write_packet(&pckg).await?;
        let mut buf = [0; 12];
        let pckg = self.read_packet(&mut buf).await?;
        let code = ConfirmationCode::try_read_from_bytes(&pckg.data[..1])
            .map_err(|_| Error::InvalidContent)?;
        if code.is_error() {
            return Err(Error::CommandErr(code));
        }
        Ok(())
    }

    /// Delete templates by specifying the start slot and number of templates to be deleted.
    ///
    /// # Returns
    /// - `Ok(())` on success
    /// - `CommandErr` [ErrDeletingTemplates](ConfirmationCode::ErrDeletingTemplates) when deletion failed
    /// - `Err` [Error] when other errors occur
    pub async fn delete_template(&mut self, slot: u16) -> Result<(), Error<T::Error>> {
        self.delete_templates(slot, 1).await
    }

    /// Read a page of the fingerprint library.
    ///
    /// Returns a [SlotTable] representing 256 slots.
    /// Valid `pages` are 0 - 3, for a total of 1024 slots.
    pub async fn read_slot_table(&mut self, page: u8) -> Result<SlotTable, Error<T::Error>> {
        if !self.authenticated {
            self.authenticated = false;
            self.vfy_pwd().await?;
        }
        if page > 3 {
            return Err(Error::InvalidParameter);
        }
        let data = &[CommandCode::GetSlotTable as u8, page];
        let pckg = Package::new(Pid::Command, self.address, data);
        self.write_packet(&pckg).await?;
        let mut buf = [0; 33];
        let pckg = self.read_packet(&mut buf).await?;
        let code = ConfirmationCode::try_read_from_bytes(&pckg.data[..1])
            .map_err(|_| Error::InvalidContent)?;
        if code.is_error() {
            return Err(Error::CommandErr(code));
        }

        let table = SlotTable::new(
            *pckg.data[1..].as_array().ok_or(Error::InvalidContent)?,
            page,
        );

        Ok(table)
    }
}

fn verify_checksum(pckg: &Package) -> bool {
    let mut checksum: u16 = 0;
    checksum = checksum.wrapping_add(pckg.pckg_header.pid as u16);
    checksum = checksum.wrapping_add(pckg.pckg_header.length.get());
    for d in pckg.data {
        checksum = checksum.wrapping_add(*d as u16);
    }
    if pckg.checksum != checksum {
        warn!(
            "Package checksum mismatch: expected {:04x}, got {:04x}",
            checksum, pckg.checksum
        );
    }
    pckg.checksum == checksum
}
