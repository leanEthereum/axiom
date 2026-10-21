//! The slot, the protocol's unit of time.

use std::{
    fmt,
    ops::{Add, AddAssign, Rem, Sub},
};

use axiom_ssz::{DecodeError, Root, Ssz};

use crate::{Epoch, Preset};

/// A slot number, counted from genesis.
///
/// Each slot gives one validator the right to propose a block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Slot(pub u64);

impl Slot {
    /// The first slot of the chain.
    pub const GENESIS: Self = Self(0);

    /// Epoch containing this slot.
    ///
    /// See `compute_epoch_at_slot` in the phase0 beacon chain spec.
    #[must_use]
    pub const fn epoch<P: Preset>(self) -> Epoch {
        Epoch(self.0 / P::SLOTS_PER_EPOCH)
    }

    /// Whether this slot opens an epoch.
    #[must_use]
    pub const fn is_epoch_start<P: Preset>(self) -> bool {
        self.0.is_multiple_of(P::SLOTS_PER_EPOCH)
    }

    /// Position of this slot within its epoch.
    #[must_use]
    pub const fn index_in_epoch<P: Preset>(self) -> u64 {
        self.0 % P::SLOTS_PER_EPOCH
    }

    /// The slot that many slots later, or nothing on overflow.
    #[must_use]
    pub const fn checked_add(self, slots: u64) -> Option<Self> {
        match self.0.checked_add(slots) {
            Some(slot) => Some(Self(slot)),
            None => None,
        }
    }

    /// The slot that many slots earlier, or genesis when that would go before it.
    #[must_use]
    pub const fn saturating_sub(self, slots: u64) -> Self {
        Self(self.0.saturating_sub(slots))
    }

    /// The slot as a vector index.
    ///
    /// Axiom targets 64-bit platforms only, so the conversion is lossless.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "axiom targets 64-bit platforms only"
    )]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl From<u64> for Slot {
    fn from(slot: u64) -> Self {
        Self(slot)
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Add<u64> for Slot {
    type Output = Self;

    fn add(self, slots: u64) -> Self {
        Self(self.0 + slots)
    }
}

impl AddAssign<u64> for Slot {
    fn add_assign(&mut self, slots: u64) {
        self.0 += slots;
    }
}

impl Sub<u64> for Slot {
    type Output = Self;

    fn sub(self, slots: u64) -> Self {
        Self(self.0 - slots)
    }
}

impl Sub for Slot {
    type Output = u64;

    /// Number of slots between two slots.
    fn sub(self, earlier: Self) -> u64 {
        self.0 - earlier.0
    }
}

impl Rem<u64> for Slot {
    type Output = u64;

    fn rem(self, modulus: u64) -> u64 {
        self.0 % modulus
    }
}

impl Ssz for Slot {
    const FIXED_SIZE: Option<usize> = u64::FIXED_SIZE;
    const PACKED_SIZE: Option<usize> = u64::PACKED_SIZE;

    fn encoded_len(&self) -> usize {
        self.0.encoded_len()
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        self.0.encode_to(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        u64::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        self.0.hash_tree_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Mainnet, Minimal};

    #[test]
    fn epoch_divides_by_the_preset_epoch_length() {
        // Mainnet epochs hold 32 slots and minimal epochs hold 8.
        assert_eq!(Slot(65).epoch::<Mainnet>(), Epoch(2));
        assert_eq!(Slot(65).epoch::<Minimal>(), Epoch(8));
    }

    #[test]
    fn epoch_start_is_a_multiple_of_the_epoch_length() {
        assert!(Slot(64).is_epoch_start::<Mainnet>());
        assert!(!Slot(65).is_epoch_start::<Mainnet>());
        assert_eq!(Slot(65).index_in_epoch::<Mainnet>(), 1);
    }
}
