//! The failure of a command sent to a stopped driver.

use thiserror::Error;

/// The driver has stopped, so the command was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("discovery driver has stopped")]
pub struct DriverStopped;
