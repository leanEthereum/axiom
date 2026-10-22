//! The failures of commands sent to the driver.

use thiserror::Error;

use crate::service::ServiceError;

/// The driver has stopped, so the command was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("discovery driver has stopped")]
pub struct DriverStopped;

/// Why the running node kept its old local record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RecordUpdateError {
    /// The driver has stopped.
    #[error("local record not replaced: {0}")]
    Stopped(#[from] DriverStopped),
    /// The service refused the record.
    #[error("local record refused: {0}")]
    Refused(#[from] ServiceError),
}
