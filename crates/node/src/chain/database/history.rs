//! Where the stored chain begins, the point backfill extends from.

use axiom_ssz::{DecodeError, Ssz};
use axiom_types::{Root, Slot};

/// The oldest block of the stored, unbroken chain: its slot and its parent's root.
///
/// Every stored block from here to the head links to its parent.
/// Backfill fetches the parent next, and stops once the parent root is zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryStart {
    /// Slot of the oldest stored block.
    pub slot: Slot,
    /// Root its parent must have; zero for the genesis block.
    pub parent_root: Root,
}

impl HistoryStart {
    /// Bytes of the encoded record: a big-endian slot, then the root.
    const LEN: usize = 8 + 32;

    /// Whether the stored chain reaches genesis, whose block has no parent.
    ///
    /// See `get_forkchoice_store` in the phase0 fork choice spec, where the genesis parent is zero.
    #[must_use]
    pub fn reaches_genesis(&self) -> bool {
        self.parent_root == Root::ZERO
    }

    /// The record as stored.
    pub(super) fn encode(&self) -> [u8; Self::LEN] {
        let mut bytes = [0; Self::LEN];
        bytes[..8].copy_from_slice(&self.slot.0.to_be_bytes());
        bytes[8..].copy_from_slice(&self.parent_root.0);
        bytes
    }

    /// Reads a stored record.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != Self::LEN {
            return Err(DecodeError::InvalidLength {
                expected: Self::LEN,
                actual: bytes.len(),
            });
        }
        let (slot, root) = bytes.split_at(8);
        Ok(Self {
            slot: Slot(u64::from_be_bytes(slot.try_into().unwrap_or_default())),
            parent_root: Root::decode(root)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_round_trips_and_refuses_a_wrong_length() {
        let start = HistoryStart {
            slot: Slot(0x0102),
            parent_root: Root([7; 32]),
        };

        // The slot comes first, big-endian, then the 32 root bytes.
        let bytes = start.encode();
        assert_eq!(bytes[..8], [0, 0, 0, 0, 0, 0, 1, 2]);
        assert_eq!(HistoryStart::decode(&bytes).unwrap(), start);
        assert_eq!(
            HistoryStart::decode(&bytes[..39]),
            Err(DecodeError::InvalidLength {
                expected: 40,
                actual: 39
            })
        );
    }

    #[test]
    fn only_a_zero_parent_reaches_genesis() {
        let mut start = HistoryStart {
            slot: Slot(0),
            parent_root: Root::ZERO,
        };
        assert!(start.reaches_genesis());

        start.parent_root = Root([1; 32]);
        assert!(!start.reaches_genesis());
    }
}
