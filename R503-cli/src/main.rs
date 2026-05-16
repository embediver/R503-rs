use R503::R503;
use clap::Parser;
use embedded_io_adapters::futures_03::FromFutures;
use embedded_io_async::{Read, Write};
use futures::io::AllowStdIo;

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
    let serial = serialport::new(args.port, 57600)
        .open()
        .map_err(|e| eprintln!("Failed to open serial port: {}", e))
        .unwrap();
    let serial = AllowStdIo::new(serial);
    let serial = FromFutures::new(serial);
    let r503 = R503::new(serial, args.pwd, args.addr);

    let main = smol::spawn(main_task(r503));

    smol::block_on(main);
}

async fn main_task<S: Read + Write>(mut r503: R503<S>) {
    r503.vfy_pwd().await.unwrap();
    println!("========================================");
    println!("| Password authentication successfull. |");
    println!("========================================");
}
