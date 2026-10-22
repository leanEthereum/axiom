//! The failure of a command sent to a stopped driver.

use std::{error::Error, fmt};

/// The driver has stopped, so the command was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriverStopped;

impl fmt::Display for DriverStopped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("discovery driver has stopped")
    }
}

impl Error for DriverStopped {}
