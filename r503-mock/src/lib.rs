//! Mock structures used for unit tests.
//!
//! Required as a separate crate to be able to
//! use it inside of _doc_ examples.

use defmt::trace;
use embedded_io_async::{ErrorType, Read, Write};

/// Serial/UART device mock
///
/// Implements _embedded_io_async_ _Read_ + _Write_.
pub struct SerialMock<'a> {
    // The receive side of the sensor
    pub rx: Vec<u8>,
    // The transmit side of the sensor
    pub tx: &'a [u8],
}

impl<'a> SerialMock<'a> {
    pub fn new(tx_bytes: &'a [u8]) -> Self {
        SerialMock {
            rx: Vec::new(),
            tx: tx_bytes,
        }
    }
}

impl ErrorType for SerialMock<'_> {
    type Error = core::convert::Infallible;
}

impl Read for SerialMock<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let res = self.tx.read(buf).await;
        trace!("read from sensor invoked, tx buf is now {:02x}", self.tx);
        res
    }
}

impl Write for SerialMock<'_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.rx.write(buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
