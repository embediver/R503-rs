use std::time::{Duration, Instant};

use clap::Parser;
use embedded_io_adapters::futures_03::FromFutures;
use embedded_io_async::{Read, Write};
use flexi_logger::Logger;
use futures::io::AllowStdIo;
use r503::{ConfirmationCode, R503, led::LedConfig};
use smol::Timer;

#[derive(Debug, Parser)]
#[command(version, long_about = None)]
/// Command line interface for R503 module. This is a simple example of how to use the R503 fingerprint libary.
struct Args {
    /// Serial port to which the module is connected. For example: `COM3` on Windows or `/dev/ttyUSB0` on Linux.
    #[arg()]
    port: String,
    /// Password for the R503 module. This is optional. Defaults to `0x00000000`.
    #[arg(short, long)]
    pwd: Option<u32>,
    /// Address of the R503 module. This is optional. Defaults to `0xFFFFFFFF`.
    #[arg(short, long)]
    addr: Option<u32>,
}

fn main() {
    let args = Args::parse();

    defmt2log::init_from_current_exe();
    Logger::try_with_env_or_str("warn")
        .unwrap()
        .start()
        .unwrap();

    let serial = serialport::new(args.port, 57600)
        .timeout(Duration::from_millis(1000))
        .open()
        .map_err(|e| println!("Failed to open serial port: {}", e))
        .unwrap();
    let serial = AllowStdIo::new(serial);
    let serial = FromFutures::new(serial);
    let r503 = R503::new(serial, args.pwd, args.addr);

    let main = smol::spawn(main_task(r503));

    smol::block_on(main);
}

async fn main_task<S: Read + Write>(mut r503: R503<S>) {
    r503.vfy_pwd()
        .await
        .expect("Failed to authenticate with sensor");
    println!("Password authentication successfull.");
    let sensor_status = r503.check_sensor().await.unwrap();
    println!("Sensor status: {}", sensor_status);

    get_finger(&mut r503, Duration::from_secs(30))
        .await
        .unwrap();

    let now = Instant::now();
    r503.img2tz(r503::CharacterBuffer::Buffer1)
        .await
        .expect("Failed to generate feature file 1 from image");
    println!(
        "Generated feature file 1 from finger image (took {}ms).",
        now.elapsed().as_millis()
    );

    wait_for_no_finger(&mut r503).await;
    get_finger(&mut r503, Duration::from_secs(30))
        .await
        .unwrap();

    let now = Instant::now();
    r503.img2tz(r503::CharacterBuffer::Buffer2)
        .await
        .expect("Failed to generate feature file 2 from image");
    println!(
        "Generated feature file 2 from finger image (took {}ms).",
        now.elapsed().as_millis()
    );
}

async fn get_finger<T: Read + Write>(r503: &mut R503<T>, timeout: Duration) -> Result<(), ()> {
    r503.led_control(LedConfig::breathing(r503::led::Color::Purple, 100, 255))
        .await
        .unwrap();
    println!("LED should now breath purple.");
    println!("Detecting finger ({}sec timeout)...", timeout.as_secs());

    let start = Instant::now();
    while start.elapsed() < timeout {
        match r503.gen_image().await {
            Ok(ConfirmationCode::Ok) => {
                println!("Finger detected.");
                r503.led_control(LedConfig::flashing(r503::led::Color::Blue, 180, 1))
                    .await
                    .unwrap();
                break;
            }
            Ok(ConfirmationCode::NoFinger) => {} // Continue searching
            Ok(c) => {
                r503.led_control(LedConfig::flashing(r503::led::Color::Red, 20, 5))
                    .await
                    .unwrap();
                println!("Unexpected status while executing command: {c}");
                return Err(());
            }
            Err(r503::Error::CommandErr(ConfirmationCode::EnrollErr)) => {
                r503.led_control(LedConfig::flashing(r503::led::Color::Red, 20, 5))
                    .await
                    .unwrap();
                println!("Finger collection unsuccessfull.");
                return Err(());
            }
            Err(e) => {
                r503.led_control(LedConfig::flashing(r503::led::Color::Red, 20, 5))
                    .await
                    .unwrap();
                println!("Error executing command: {e:?}");
                return Err(());
            }
        }
        Timer::after(Duration::from_millis(200)).await;
    }
    Ok(())
}

async fn wait_for_no_finger<T: Read + Write>(r503: &mut R503<T>) {
    if let Ok(ConfirmationCode::Ok) = r503.gen_image().await {
        println!("Please release finger");
    }
    Timer::after(Duration::from_millis(200)).await;
    while !matches!(
        r503.gen_image().await,
        Ok(ConfirmationCode::NoFinger) | Err(_)
    ) {
        Timer::after(Duration::from_millis(200)).await;
    }
}
