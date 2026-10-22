//! Participation flags, one bit per duty an attester fulfilled.

use axiom_ssz::{DecodeError, Root, Ssz};

/// The duties a validator fulfilled in one epoch, one bit per duty.
///
/// The bits are the timely source, timely target, and timely head flags.
/// See the Altair beacon chain spec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ParticipationFlags(pub u8);

impl ParticipationFlags {
    /// Whether the flag at an index is set.
    #[must_use]
    pub const fn has(self, flag_index: usize) -> bool {
        self.0 >> flag_index & 1 == 1
    }

    /// These flags with one more flag set.
    #[must_use]
    pub const fn with(self, flag_index: usize) -> Self {
        Self(self.0 | 1 << flag_index)
    }
}

impl Ssz for ParticipationFlags {
    const FIXED_SIZE: Option<usize> = u8::FIXED_SIZE;
    const PACKED_SIZE: Option<usize> = u8::PACKED_SIZE;

    fn encoded_len(&self) -> usize {
        1
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        u8::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        self.0.hash_tree_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_set_and_read_independently() {
        // Setting flags 0 and 2 gives 0b101 and leaves flag 1 clear.
        let flags = ParticipationFlags::default().with(0).with(2);

        assert_eq!(flags, ParticipationFlags(0b101));
        assert!(flags.has(0));
        assert!(!flags.has(1));
        assert!(flags.has(2));
    }
}
