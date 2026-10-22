//! The epoch, a fixed run of slots.

use std::{
    fmt,
    ops::{Add, AddAssign, Rem, Sub},
};

use axiom_ssz::{DecodeError, Root, Ssz};

use crate::{Preset, Slot};

/// An epoch number, counted from genesis.
///
/// Committees, justification, and rewards all advance one epoch at a time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Epoch(pub u64);

impl Epoch {
    /// The first epoch of the chain.
    pub const GENESIS: Self = Self(0);

    /// Marks an event that has not been scheduled, such as the exit of an active validator.
    pub const FAR_FUTURE: Self = Self(u64::MAX);

    /// First slot of this epoch.
    ///
    /// See `compute_start_slot_at_epoch` in the phase0 beacon chain spec.
    #[must_use]
    pub const fn start_slot<P: Preset>(self) -> Slot {
        Slot(self.0 * P::SLOTS_PER_EPOCH)
    }

    /// Epoch an activation or exit decided in this epoch takes effect.
    ///
    /// The delay keeps the change outside every committee already derivable from randao.
    /// See `compute_activation_exit_epoch` in the phase0 beacon chain spec.
    #[must_use]
    pub const fn activation_exit_epoch<P: Preset>(self) -> Self {
        Self(self.0 + 1 + P::MAX_SEED_LOOKAHEAD)
    }

    /// The epoch that many epochs later, or nothing on overflow.
    #[must_use]
    pub const fn checked_add(self, epochs: u64) -> Option<Self> {
        match self.0.checked_add(epochs) {
            Some(epoch) => Some(Self(epoch)),
            None => None,
        }
    }

    /// The epoch that many epochs later, or the far future on overflow.
    #[must_use]
    pub const fn saturating_add(self, epochs: u64) -> Self {
        Self(self.0.saturating_add(epochs))
    }

    /// The epoch that many epochs earlier, or genesis when that would go before it.
    #[must_use]
    pub const fn saturating_sub(self, epochs: u64) -> Self {
        Self(self.0.saturating_sub(epochs))
    }

    /// The epoch as a vector index.
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

impl From<u64> for Epoch {
    fn from(epoch: u64) -> Self {
        Self(epoch)
    }
}

impl fmt::Display for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Add<u64> for Epoch {
    type Output = Self;

    fn add(self, epochs: u64) -> Self {
        Self(self.0 + epochs)
    }
}

impl AddAssign<u64> for Epoch {
    fn add_assign(&mut self, epochs: u64) {
        self.0 += epochs;
    }
}

impl Sub<u64> for Epoch {
    type Output = Self;

    fn sub(self, epochs: u64) -> Self {
        Self(self.0 - epochs)
    }
}

impl Sub for Epoch {
    type Output = u64;

    /// Number of epochs between two epochs.
    fn sub(self, earlier: Self) -> u64 {
        self.0 - earlier.0
    }
}

impl Rem<u64> for Epoch {
    type Output = u64;

    fn rem(self, modulus: u64) -> u64 {
        self.0 % modulus
    }
}

impl Ssz for Epoch {
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
    use crate::Mainnet;

    #[test]
    fn start_slot_inverts_slot_epoch() {
        // Epoch 3 starts at slot 96 on mainnet, and slot 96 lies in epoch 3.
        let start = Epoch(3).start_slot::<Mainnet>();

        assert_eq!(start, Slot(96));
        assert_eq!(start.epoch::<Mainnet>(), Epoch(3));
    }

    #[test]
    fn far_future_saturates_instead_of_wrapping() {
        assert_eq!(Epoch::FAR_FUTURE.saturating_add(1), Epoch::FAR_FUTURE);
        assert_eq!(Epoch::FAR_FUTURE.checked_add(1), None);
    }
}
