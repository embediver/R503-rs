use std::sync::Once;

use defmt::trace;
use embedded_io_async::{ErrorType, Read, Write};
use flexi_logger::Logger;

use crate::R503;

struct SerialMock<'a> {
    // The receive side of the sensor
    rx: Vec<u8>,
    // The transmit side of the sensor
    tx: &'a [u8],
}

impl<'a> SerialMock<'a> {
    fn new(tx_bytes: &'a [u8]) -> Self {
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

fn setup_defmt() {
    static LOGGER_INIT: Once = Once::new();
    LOGGER_INIT.call_once(|| {
        defmt2log::init_from_current_exe();
        Logger::try_with_env_or_str("trace")
            .unwrap()
            .log_to_stdout()
            .write_mode(flexi_logger::WriteMode::SupportCapture)
            .start()
            .unwrap();
    });
}

#[test]
fn test_vfy_pwd() {
    setup_defmt();

    let tx = &[
        0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x00, 0x03, 0x00, 0x00, 0x0A,
    ];

    let serial = SerialMock::new(tx);

    let mut r503 = R503::new(serial, None, None);

    smol::block_on(async {
        r503.vfy_pwd().await.expect("Failed to verify password");
    });

    let serial = r503.destroy();

    assert_eq!(
        &serial.rx,
        &[
            0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x07, 0x13, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x1B
        ]
    );
}
