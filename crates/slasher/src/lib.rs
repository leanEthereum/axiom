//! The slasher: detects double votes, surround votes, and double proposals.

mod error;

pub use error::{ConfigError, EvidenceError, SlasherError};
