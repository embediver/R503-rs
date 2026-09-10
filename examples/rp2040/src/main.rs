#![no_std]
#![no_main]

use defmt::{Debug2Format, info, warn};
use embassy_executor::Spawner;
use embassy_rp::{bind_interrupts, peripherals, uart};
use embassy_time::{Duration, Instant, Timer};
use embedded_io_async::{Read, Write};
use r503::{CharacterBuffer, ConfirmationCode, Error, R503, led::LedConfig};
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(
    struct UartIrqs {
        UART0_IRQ => uart::BufferedInterruptHandler<peripherals::UART0>;
    }
);

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_rp::init(Default::default());
    let mut config = uart::Config::default();
    config.baudrate = 57600;
    let mut tx_buf = [0u8; 256];
    let mut rx_buf = [0u8; 256];
    let uart = uart::BufferedUart::new(
        p.UART0,
        p.PIN_0,
        p.PIN_1,
        UartIrqs,
        &mut tx_buf,
        &mut rx_buf,
        config,
    );

    let mut r503 = R503::new(uart, None, None);

    info!("Initializing sensor...");
    r503.vfy_pwd().await.expect("Failed to verify password");
    if r503.check_sensor().await.unwrap() == ConfirmationCode::SensorAbnormal {
        panic!("Sensor reported abnormal status!");
    }
    r503.read_system_parameters().await.unwrap();

    info!("Sensor initialized");
    info!(
        "{} stored finger templates",
        r503.get_library_count().await.unwrap()
    );
    loop {
        info!("Present finger for matching");
        if get_finger(&mut r503, Duration::MAX)
            .await
            .inspect_err(|e| warn!("Error occured while detecting finger: {}", Debug2Format(e)))
            .is_err()
        {
            continue;
        }
        if r503
            .img2tz(CharacterBuffer::Buffer1)
            .await
            .inspect_err(|e| warn!("Error occured while detecting finger: {}", Debug2Format(e)))
            .is_err()
        {
            continue;
        }
        match r503.search_for_match(CharacterBuffer::Buffer1, 0).await {
            Ok(p) => info!("Found match: slot {}", p),
            Err(Error::CommandErr(ConfirmationCode::SearchFailed)) => {
                r503.led_control(LedConfig::flashing(r503::led::Color::Red, 20, 5))
                    .await
                    .unwrap();
                info!("Finger not in library!");
            }
            Err(e) => warn!("Error occured searching for match: {}", Debug2Format(&e)),
        };
    }
}

async fn get_finger<T: Read + Write>(
    r503: &mut R503<T>,
    timeout: Duration,
) -> Result<(), Error<T::Error>> {
    r503.led_control(LedConfig::breathing(r503::led::Color::Purple, 100, 255))
        .await?;
    info!("Detecting finger ({}sec timeout)...", timeout.as_secs());

    let start = Instant::now();
    while start.elapsed() < timeout {
        match r503.gen_image_ex().await {
            Ok(ConfirmationCode::Ok) => {
                info!("Finger detected.");
                r503.led_control(LedConfig::flashing(r503::led::Color::Blue, 180, 1))
                    .await?;
                break;
            }
            Ok(c) => {
                r503.led_control(LedConfig::flashing(r503::led::Color::Red, 20, 5))
                    .await?;
                info!("Unexpected status while executing command: {}", c);
                return Err(Error::CommandErr(c));
            }
            Err(Error::CommandErr(ConfirmationCode::NoFinger)) => {} // Continue searching
            Err(Error::CommandErr(ConfirmationCode::ErrTooLittleData)) => {} // Continue searching
            Err(e @ Error::CommandErr(ConfirmationCode::EnrollErr)) => {
                r503.led_control(LedConfig::flashing(r503::led::Color::Red, 20, 5))
                    .await?;
                info!("Finger collection unsuccessfull.");
                return Err(e);
            }
            Err(e) => {
                r503.led_control(LedConfig::flashing(r503::led::Color::Red, 20, 5))
                    .await?;
                return Err(e);
            }
        }
        Timer::after(Duration::from_millis(200)).await;
    }
    Ok(())
}
