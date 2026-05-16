use core::fmt::Display;

use embedded_io_async::ReadExactError;
use zerocopy::{Immutable, IntoBytes, TryFromBytes};

#[repr(packed)]
#[derive(Debug, Clone, Copy, TryFromBytes, IntoBytes, Immutable)]
pub struct PackageHeader {
    pub header: u16,
    pub address: u32,
    pub pid: Pid,
    pub length: u16,
}

#[repr(packed)]
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
            header: PackageHeader::HEADER,
            address,
            pid,
            length: (data.len() + 2) as u16,
        };
        let mut pckg = Self {
            pckg_header,
            data,
            checksum: 0,
        };
        pckg.checksum = pckg.generate_checksum();
        return pckg;
    }
    pub fn generate_checksum(&self) -> u16 {
        let mut checksum: u16 = 0;
        checksum = checksum.wrapping_add(self.pckg_header.pid as u16);
        checksum = checksum.wrapping_add(self.pckg_header.length);
        for d in self.data {
            checksum = checksum.wrapping_add(*d as u16);
        }
        return checksum;
    }
}

/// Package Identifier
#[repr(u8)]
#[derive(Debug, TryFromBytes, Clone, Copy, IntoBytes, Immutable)]
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
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum CommandCode {
    VfyPwd = 0x13,
    SetPwd = 0x12,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromBytes)]
#[non_exhaustive]
pub enum ConfirmationCode {
    Ok = 0x00,
    DataErr = 0x01,
    NoFinger = 0x02,
    EnrollErr = 0x03,
    EnrollErrTooNoisyData = 0x06,
    EnrollErrTooLittleData = 0x07,
    ComparisonFailed = 0x08,
    SearchFailed = 0x09,
    FileCombinationFailed = 0x0A,
    PageIdBeyondLibrary = 0x0B,
    TemplateInvalid = 0x0C,
    WrongPwd = 0x13,
}

impl ConfirmationCode {
    /// Matches any field besides
    /// - Ok
    /// - NoFinger
    /// - SearchFailed
    pub fn is_error(&self) -> bool {
        !matches!(self, Self::Ok | Self::NoFinger | Self::SearchFailed)
    }
    fn is_unauthorized(&self) -> bool {
        todo!()
    }
}

impl Display for ConfirmationCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            ConfirmationCode::Ok => "Command execution successful",
            ConfirmationCode::DataErr => "Error when receiving data package",
            ConfirmationCode::NoFinger => "No finger on the sensor",
            ConfirmationCode::EnrollErr => "Failed to enroll finger",
            ConfirmationCode::EnrollErrTooNoisyData => {
                "Failed to generate character file: Too much noise"
            }
            ConfirmationCode::EnrollErrTooLittleData => {
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
        };
        write!(f, "{}", msg)
    }
}
