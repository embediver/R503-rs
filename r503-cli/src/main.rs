use std::time::{Duration, Instant};

use clap::Parser;
use embedded_io_adapters::futures_03::FromFutures;
use embedded_io_async::{Read, Write};
use flexi_logger::Logger;
use futures::io::AllowStdIo;
use r503::{R503, led::LedConfig};
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
        .timeout(Duration::from_millis(500))
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
    r503.led_control(LedConfig::breathing(r503::led::Color::Purple, 100, 255))
        .await
        .unwrap();
    println!("LED should now breath purple.");
    println!("Detecting finger (30sec timeout)...");

    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        match r503.gen_image().await {
            Ok(r503::ConfirmationCode::Ok) => {
                println!("Finger detected.");
                r503.led_control(LedConfig::flashing(r503::led::Color::Blue, 180, 1))
                    .await
                    .unwrap();
                break;
            }
            Ok(r503::ConfirmationCode::NoFinger) => {} // Continue searching
            Ok(c) => {
                r503.led_control(LedConfig::flashing(r503::led::Color::Red, 20, 5))
                    .await
                    .unwrap();
                println!("Unexpected status while executing command: {c}");
                break;
            }
            Err(r503::Error::CommandErr(r503::ConfirmationCode::EnrollErr)) => {
                r503.led_control(LedConfig::flashing(r503::led::Color::Red, 20, 5))
                    .await
                    .unwrap();
                println!("Finger collection unsuccessfull.");
                break;
            }
            Err(e) => {
                r503.led_control(LedConfig::flashing(r503::led::Color::Red, 20, 5))
                    .await
                    .unwrap();
                println!("Error executing command: {e:?}");
                break;
            }
        }
        Timer::after(Duration::from_millis(200)).await;
    }
}
