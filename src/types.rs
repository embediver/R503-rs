use embedded_io_async::{ErrorType, ReadExactError};
use zerocopy::TryFromBytes;

#[derive(Debug, TryFromBytes)]
pub struct PackageHeader {
    pub header: u16,
    pub address: u32,
    pub pid: Pid,
    pub length: u16,
}

pub struct Package<'a> {
    pub pckg_header: PackageHeader,
    pub data: &'a [u8],
    pub checksum: u16,
}

#[repr(u8)]
#[derive(Debug, TryFromBytes, Clone, Copy)]
pub enum Pid {
    Command = 0x01,
    Data = 0x02,
    Ack = 0x07,
    End = 0x08,
}

#[derive(Debug)]
pub enum Error<T>
where
    T: ErrorType,
{
    Serial(ReadExactError<<T as ErrorType>::Error>),
    BufTooSmall,
    InvalidPid,
    InvalidHeader,
    Checksum,
}

impl<T: ErrorType> From<ReadExactError<<T as ErrorType>::Error>> for Error<T> {
    fn from(value: ReadExactError<<T as ErrorType>::Error>) -> Self {
        Error::Serial(value)
    }
}

impl PackageHeader {
    pub const HEADER: u16 = 0xEF01;
}
