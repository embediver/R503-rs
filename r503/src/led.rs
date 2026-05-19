use zerocopy::{Immutable, IntoBytes, TryFromBytes};

use crate::types::CommandCode;

/// Supported LED modes
///
/// Referred to as _Control Code_ in the datasheet.
#[derive(Debug, Clone, Copy, TryFromBytes, Immutable, IntoBytes)]
#[repr(u8)]
pub(crate) enum Mode {
    /// Breathing light
    Breathing = 0x01,
    /// Flashing light
    Flashing = 0x02,
    /// Light On
    On = 0x03,
    /// Light Off
    Off = 0x04,
    /// Transition to On state
    TransitionOn = 0x05,
    /// Transition to Off state
    TransitionOff = 0x06,
}

/// Possible LED colors
#[derive(Debug, Clone, Copy, TryFromBytes, Immutable, IntoBytes)]
#[repr(u8)]
pub enum Color {
    Red = 0x01,
    Blue = 0x02,
    Purple = 0x03,
}

/// A LED configuration for the Aura LED
///
/// The default config is off.
#[derive(Debug, Clone, Copy, TryFromBytes, Immutable, IntoBytes)]
#[repr(C, packed)]
pub struct LedConfig {
    /// Included to be able to create a &[u8] packet payload directly from this struct
    cmd_code: CommandCode,
    /// Ctrl
    pub(crate) mode: Mode,
    pub(crate) speed: u8,
    pub(crate) color: Color,
    pub(crate) count: u8,
}

impl Default for LedConfig {
    fn default() -> Self {
        Self {
            cmd_code: CommandCode::LedCtrl,
            mode: Mode::Off,
            color: Color::Red,
            speed: Default::default(),
            count: Default::default(),
        }
    }
}

impl LedConfig {
    /// New config for breathing LED effect.
    ///
    /// Speed can be controlled from `0x00` (fastest) to `0xFF` (slowest).
    ///
    /// A cycle count of 255 the effect is effective until changed again.
    pub fn breathing(color: Color, speed: u8, count: u8) -> LedConfig {
        LedConfig {
            cmd_code: CommandCode::LedCtrl,
            mode: Mode::Breathing,
            color,
            speed,
            count,
        }
    }
    /// New config for flashing LED effect.
    ///
    /// Speed can be controlled from `0x00` (fastest) to `0xFF` (slowest).
    ///
    /// A cycle count of 255 the effect is effective until changed again.
    pub fn flashing(color: Color, speed: u8, count: u8) -> LedConfig {
        LedConfig {
            cmd_code: CommandCode::LedCtrl,
            mode: Mode::Flashing,
            color,
            speed,
            count,
        }
    }
    /// New config for turning the LED on.
    pub fn on(color: Color) -> LedConfig {
        LedConfig {
            cmd_code: CommandCode::LedCtrl,
            mode: Mode::On,
            color,
            speed: 0,
            count: 0,
        }
    }
    /// New config for turning the LED off.
    pub fn off(color: Color) -> LedConfig {
        LedConfig {
            cmd_code: CommandCode::LedCtrl,
            mode: Mode::Off,
            color,
            speed: 0,
            count: 0,
        }
    }
    /// New config for transitioning to on.
    ///
    /// Speed can be controlled from `0x00` (fastest) to `0xFF` (slowest).
    pub fn transition_on(color: Color, speed: u8) -> LedConfig {
        LedConfig {
            cmd_code: CommandCode::LedCtrl,
            mode: Mode::TransitionOn,
            color,
            speed,
            count: 0,
        }
    }
    /// New config for transitioning to on.
    ///
    /// Speed can be controlled from `0x00` (fastest) to `0xFF` (slowest).
    pub fn transition_off(color: Color, speed: u8) -> LedConfig {
        LedConfig {
            cmd_code: CommandCode::LedCtrl,
            mode: Mode::TransitionOff,
            color,
            speed,
            count: 0,
        }
    }
}
