use core::fmt::Display;

use embedded_io_async::ReadExactError;
use zerocopy::byteorder::big_endian::{U16, U32};
use zerocopy::{Immutable, IntoBytes, TryFromBytes};

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, TryFromBytes, IntoBytes, Immutable)]
pub struct PackageHeader {
    pub header: U16,
    pub address: U32,
    pub pid: Pid,
    pub length: U16,
}

#[derive(Debug)]
pub struct Package<'a> {
    pub pckg_header: PackageHeader,
    pub data: &'a [u8],
    /// The arithmetic sum of package identifier, package length and all package contents.
    /// Overflowing bits are omitted. High byte is transferred first.
    pub checksum: u16,
}

impl<'a> Package<'a> {
    pub fn new(pid: Pid, address: u32, data: &'a [u8]) -> Self {
        let pckg_header = PackageHeader {
            header: PackageHeader::HEADER.into(),
            address: address.into(),
            pid,
            length: U16::new((data.len() + 2) as u16),
        };
        let mut pckg = Self {
            pckg_header,
            data,
            checksum: 0,
        };
        pckg.checksum = pckg.generate_checksum();
        pckg
    }
    pub fn generate_checksum(&self) -> u16 {
        let mut checksum: u16 = 0;
        checksum = checksum.wrapping_add(self.pckg_header.pid as u16);
        checksum = checksum.wrapping_add(self.pckg_header.length.get());
        for d in self.data {
            checksum = checksum.wrapping_add(*d as u16);
        }
        checksum
    }
}

/// Package Identifier
#[repr(u8)]
#[derive(Debug, defmt::Format, TryFromBytes, Clone, Copy, IntoBytes, Immutable)]
#[allow(dead_code)]
pub enum Pid {
    Command = 0x01,
    Data = 0x02,
    Ack = 0x07,
    End = 0x08,
}

#[derive(Debug)]
pub enum Error<T>
where
    T: embedded_io_async::Error,
{
    /// UART read error
    ReadErr(ReadExactError<T>),
    /// UART write error
    WriteErr(T),
    /// Buffer to small
    BufToSmall,
    /// Unexpected package identifier
    InvalidPid,
    /// The returned header is invalid
    InvalidHeader,
    /// Checksum mismatch
    Checksum,
    /// The returned data is invalid
    InvalidContent,
    /// The sensor returned an error confirmation code
    CommandErr(ConfirmationCode),
    /// One of the parameters was invalid
    InvalidParameter,
}

impl<T> Display for Error<T>
where
    T: embedded_io_async::Error,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::ReadErr(ReadExactError::Other(e)) => write!(f, "UART read error: {}", e.kind()),
            Error::ReadErr(ReadExactError::UnexpectedEof) => {
                f.write_str("UART read error: unexpected EOF")
            }
            Error::WriteErr(e) => write!(f, "UART write error: {}", e.kind()),
            Error::BufToSmall => f.write_str("Buffer to small"),
            Error::InvalidPid => f.write_str("Unexpected package identifier"),
            Error::InvalidHeader => f.write_str("Invalid header received"),
            Error::Checksum => f.write_str("Checksum mismatch"),
            Error::InvalidContent => f.write_str("Unexpected data received"),
            Error::CommandErr(confirmation_code) => {
                write!(f, "Sensor returned error: {confirmation_code}")
            }
            Error::InvalidParameter => f.write_str("Invalid parameter"),
        }
    }
}

impl<T> core::error::Error for Error<T> where T: embedded_io_async::Error {}

impl<T: embedded_io_async::Error> From<ReadExactError<T>> for Error<T> {
    fn from(value: ReadExactError<T>) -> Self {
        Error::ReadErr(value)
    }
}

impl<T: embedded_io_async::Error> From<T> for Error<T> {
    fn from(value: T) -> Self {
        Error::WriteErr(value)
    }
}

impl PackageHeader {
    pub const HEADER: u16 = 0xEF01;
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, TryFromBytes, Immutable, IntoBytes)]
#[non_exhaustive]
pub enum CommandCode {
    SearchLibrary = 0x04,
    VfyPwd = 0x13,
    SetPwd = 0x12,
    LedCtrl = 0x35,
    CheckSensor = 0x36,
    GenImg = 0x01,
    Img2Tz = 0x02,
    GenTemplate = 0x05,
    StoreTemplate = 0x06,
    DeleteTemplate = 0x0C,
    ClearLibrary = 0x0D,
    ReadSysPara = 0x0F,
    GetTemplateCount = 0x1D,
    GetSlotTable = 0x1F,
    GenImgEx = 0x28,
}

/// Codes returned by the sensor
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromBytes)]
#[non_exhaustive]
pub enum ConfirmationCode {
    /// Generic success / status ok code
    Ok = 0x00,
    DataErr = 0x01,
    NoFinger = 0x02,
    EnrollErr = 0x03,
    ErrTooNoisyData = 0x06,
    ErrTooLittleData = 0x07,
    ComparisonFailed = 0x08,
    SearchFailed = 0x09,
    FileCombinationFailed = 0x0A,
    PageIdBeyondLibrary = 0x0B,
    TemplateInvalid = 0x0C,
    ErrDeletingTemplates = 0x10,
    ErrClearingLibrary = 0x11,
    WrongPwd = 0x13,
    NoValidImage = 0x15,
    ErrorWritingFlash = 0x18,
    SensorAbnormal = 0x29,
}

impl ConfirmationCode {
    /// Matches any field besides
    /// - Ok
    /// - NoFinger
    pub fn is_error(&self) -> bool {
        !matches!(self, Self::Ok)
    }
}

impl Display for ConfirmationCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            ConfirmationCode::Ok => "Ok",
            ConfirmationCode::DataErr => "Error when receiving data package",
            ConfirmationCode::NoFinger => "No finger on the sensor",
            ConfirmationCode::EnrollErr => "Failed to enroll finger",
            ConfirmationCode::ErrTooNoisyData => {
                "Failed to generate character file: Too much noise"
            }
            ConfirmationCode::ErrTooLittleData => {
                "Failed to generate character file: Lack of features"
            }
            ConfirmationCode::ComparisonFailed => "No Match: Comparison of two finger templates",
            ConfirmationCode::SearchFailed => {
                "No Match: Searching the template library for the fingerprint"
            }
            ConfirmationCode::FileCombinationFailed => "Failed to combine the character files",
            ConfirmationCode::PageIdBeyondLibrary => {
                "Adressing a page id beyond the fingerprint library"
            }
            ConfirmationCode::TemplateInvalid => {
                "Error reading template form libary: template is invalid"
            }
            ConfirmationCode::WrongPwd => "Wrong password",
            ConfirmationCode::SensorAbnormal => "Sensor status is abnormal",
            ConfirmationCode::NoValidImage => "Finger image not valid",
            ConfirmationCode::ErrorWritingFlash => "Write to flash failed",
            ConfirmationCode::ErrClearingLibrary => "Failed to clear the template library",
            ConfirmationCode::ErrDeletingTemplates => "Failed to delete the specified template(s)",
        };
        write!(f, "{}", msg)
    }
}

/// Availabe character buffers
///
/// _Note:_ The datasheet mentions up to six character buffers,
///         but all commands only specify `CharBuffer1` and `CharBuffer2` as valid.
#[repr(u8)]
#[derive(Debug, Clone, Copy, TryFromBytes, Immutable, IntoBytes)]
#[non_exhaustive]
pub enum CharacterBuffer {
    Buffer1 = 0x01,
    Buffer2 = 0x02,
}

#[derive(Debug, Clone, Copy, TryFromBytes)]
#[repr(C, packed)]
pub(crate) struct SearchResult {
    pub(crate) code: ConfirmationCode,
    pub(crate) page_id: U16,
    pub(crate) score: U16,
}

/// Sensor system parameters
///
/// Can be obtained by reading the current system parameters from the sensor.
#[derive(Debug, Clone, Copy, TryFromBytes)]
#[repr(C, packed)]
pub struct SystemParameters {
    status: U16,
    /// System identification code, fixed 0x0009
    id: U16,
    finger_library_size: U16,
    security_level: U16,
    device_addr: U32,
    max_packet_size: U16,
    baud_rate: U16,
}

impl Display for SystemParameters {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            writeln!(f, "System Parameters:")?;
            writeln!(f, "  max. library size: {}", self.get_library_size())?;
            writeln!(f, "  security level: {}", self.get_security_level())?;
            writeln!(f, "  max. packet size: {}", self.get_max_packet_size())?;
            writeln!(f, "  device address: {:#08X}", self.get_device_address())?;
            writeln!(f, "  configured baud: {}", self.get_baud_rate())
        } else {
            write!(
                f,
                "max. library size: {}, security level: {}, max. packet size: {}, device address: {:08X}, configured baud: {}",
                self.get_library_size(),
                self.get_security_level(),
                self.get_max_packet_size(),
                self.get_device_address(),
                self.get_baud_rate(),
            )
        }
    }
}

impl SystemParameters {
    /// Get the finger template library size.
    pub fn get_library_size(&self) -> u16 {
        self.finger_library_size.get()
    }
    /// Get the configured security level.
    pub fn get_security_level(&self) -> u16 {
        self.security_level.get()
    }
    /// Get the configured device address.
    pub fn get_device_address(&self) -> u32 {
        self.device_addr.get()
    }
    /// Get the configured maximum packet data size.
    ///
    /// 32, 64, 128 and 256 byte sized are specified by the
    /// datasheet.
    /// For ever other value `0xFFFF` is returned.
    pub fn get_max_packet_size(&self) -> u16 {
        match self.max_packet_size.get() {
            0 => 32,
            1 => 64,
            2 => 128,
            3 => 256,
            _ => 0xFFFF,
        }
    }
    /// Get the configured baud rate.
    pub fn get_baud_rate(&self) -> u32 {
        self.baud_rate.get() as u32 * 9600
    }
}

/// A slot table indicating used fingerprint library slots
///
/// The `SlotTable` represents a page of 256 slots.
///
/// The table implements [Iterator] which yields the
/// absolute slot numbers of the provisioned slots.
#[derive(Debug, Clone, Copy, TryFromBytes)]
#[repr(C, packed)]
pub struct SlotTable {
    table: [u8; 32],
    iter_pos: u16,
    page: u8,
}

impl SlotTable {
    pub(crate) fn new(table: [u8; 32], page: u8) -> Self {
        Self {
            table,
            iter_pos: 0,
            page,
        }
    }
    fn is_slot_used(&self) -> Option<bool> {
        let byte_idx = self.iter_pos / 8;
        let bit_idx = self.iter_pos % 8;
        let byte = self.table.get(byte_idx as usize)?;

        Some(byte & 1 << bit_idx != 0)
    }
}

impl Iterator for SlotTable {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.is_slot_used()? {
            self.iter_pos += 1;
        }
        self.iter_pos += 1;
        Some((self.iter_pos - 1) + self.page as u16 * 256)
    }
}

#[cfg(test)]
mod tests {
    use crate::types::SlotTable;

    #[test]
    fn test_slot_table_iter() {
        let mut table = SlotTable {
            table: [0; 32],
            iter_pos: 0,
            page: 0,
        };
        table.table[0] = 0b0000_1001; // Slot 0, 3
        table.table[1] = 0b1000_0001; // Slot 8, 15
        table.table[31] = 0b1000_0000; // Slot 255

        let numbers: Vec<_> = table.collect();
        assert_eq!(numbers, [0, 3, 8, 15, 255]);

        let mut table = SlotTable {
            table: [0; 32],
            iter_pos: 0,
            page: 1,
        };
        table.table[0] = 0b0000_1001; // Slot 256, 259 
        table.table[31] = 0b1000_0000; // Slot 511

        let numbers: Vec<_> = table.collect();
        assert_eq!(numbers, [256, 259, 511]);
    }
}
