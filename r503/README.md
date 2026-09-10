# R503 Fingerprint Reader - Driver

An [embedded-io-async](https://crates.io/crates/embedded-io-async) driver for the Grow R503 fingerprint reader.

# Example
```rust
use r503::{R503, ConfirmationCode};

let address = 0x1234_5678;
let password = 0xDEAD_BEEF;

let mut r503 = R503::new(serial, Some(password), Some(address));
// Unlock the sensor
r503.vfy_pwd().await?;
// Check that the sensor is operational
if r503.check_sensor().await? == ConfirmationCode::SensorAbnormal {
   // Handle hardware error
}
// Take an image of a finger
r503.gen_image().await?;
// Process and match the image...
```
Take a look at the examples for a complete usage example.

# Note
While the data on the sensor is protected with a password,
there is __no__ authentication of the sensor and
__no__ encryption of the communication.
Be aware that therefor an attacker with physical access to the serial
communication can impersonate a sensor, gaining access to the system
and/or fingerprint library stored on the sensor.

## License
Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](/LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](/LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
