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
    ReadErr(ReadExactError<T>),
    WriteErr(T),
    BufTooSmall,
    InvalidPid,
    InvalidHeader,
    Checksum,
    InvalidContent,
    CommandErr(ConfirmationCode),
}

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
    GenImgEx = 0x28,
}

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
