use std::sync::Once;

use flexi_logger::Logger;
use r503_mock::SerialMock;

use crate::{
    R503,
    led::{Color, LedConfig},
};

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

#[test]
fn test_aura_led() {
    setup_defmt();

    let tx = &[
        0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x00, 0x03, 0x00, 0x00, 0x0A,
    ];

    let serial = SerialMock::new(tx);

    let mut r503 = R503::new(serial, None, None);
    r503.authenticated = true;

    smol::block_on(async {
        r503.led_control(LedConfig::breathing(Color::Red, 0xAA, 0x05))
            .await
            .expect("Failed to send led control command");
    });

    let serial = r503.destroy();

    // Instruction: 0x35
    //
    // Payload:
    // Ctrl-code: 0x01 (breathing light)
    // Speed:     0xAA
    // Color Idx: 0x01 (red)
    // Count:     0x05
    assert_eq!(
        &serial.rx,
        &[
            0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x07, 0x35, 0x01, 0xAA, 0x01, 0x05,
            0x00, 0xee
        ]
    );
}
