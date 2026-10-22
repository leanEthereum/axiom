//! The values a failed gossip rule compared, printed after the rule's wording.

use std::fmt;

use axiom_das::ColumnError;
use axiom_types::{Epoch, Root, Slot, ValidatorIndex};

/// What a failed rule looked at, so a log line shows why the rule failed.
///
/// The rule's wording says what each value is, so the shapes here stay generic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Detail {
    /// The rule compares nothing a log reader could act on, such as a signature check.
    #[default]
    None,
    /// A message's slot and the slot the rule measures it against.
    Slot {
        /// The message's slot.
        slot: Slot,
        /// The current, finalized, or parent slot, as the rule says.
        reference: Slot,
    },
    /// A message's epoch and the epoch the rule measures it against.
    Epoch {
        /// The message's epoch.
        epoch: Epoch,
        /// The current epoch, as the rule says.
        reference: Epoch,
    },
    /// A count or index and the bound it reached.
    Bound {
        /// The count or index the message carries.
        value: u64,
        /// The exclusive bound for an index, or the inclusive limit for a count.
        bound: u64,
    },
    /// A value and the one the rule expects in its place.
    Mismatch {
        /// The value the message carries.
        actual: u64,
        /// The value the rule expects.
        expected: u64,
    },
    /// The validator the rule concerns.
    Validator(ValidatorIndex),
    /// The block the rule concerns.
    Block(Root),
    /// A data column sidecar check, with the values it compared.
    Column(ColumnError),
}

impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => Ok(()),
            Self::Slot { slot, reference } => {
                write!(f, ": slot {slot}, reference slot {reference}")
            }
            Self::Epoch { epoch, reference } => {
                write!(f, ": epoch {epoch}, reference epoch {reference}")
            }
            Self::Bound { value, bound } => write!(f, ": {value} against the bound {bound}"),
            Self::Mismatch { actual, expected } => write!(f, ": {actual}, expected {expected}"),
            Self::Validator(index) => write!(f, ": validator {index}"),
            Self::Block(root) => write!(f, ": block {root}"),
            Self::Column(error) => write!(f, ": {error}"),
        }
    }
}
