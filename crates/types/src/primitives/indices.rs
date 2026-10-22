//! Indices into the registry, committees, and data structures.

use std::fmt;

use axiom_ssz::{DecodeError, Root, Ssz};

use crate::constants::BUILDER_INDEX_FLAG;

/// Position of a validator in the registry.
///
/// Indices are stable: a validator keeps its index for life.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValidatorIndex(pub u64);

impl ValidatorIndex {
    /// The index as a vector position.
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

    /// The builder this index names, when it carries the builder flag.
    ///
    /// Withdrawals name builders and validators in one field, told apart by the flag.
    /// See `is_builder_index` and `convert_validator_index_to_builder_index` in the Gloas spec.
    #[must_use]
    pub const fn builder(self) -> Option<BuilderIndex> {
        if self.0 & BUILDER_INDEX_FLAG == 0 {
            None
        } else {
            Some(BuilderIndex(self.0 & !BUILDER_INDEX_FLAG))
        }
    }
}

impl From<u64> for ValidatorIndex {
    fn from(index: u64) -> Self {
        Self(index)
    }
}

impl From<usize> for ValidatorIndex {
    /// Axiom targets 64-bit platforms only, so the conversion is lossless.
    fn from(index: usize) -> Self {
        Self(index as u64)
    }
}

impl fmt::Display for ValidatorIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Ssz for ValidatorIndex {
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

/// Position of a builder in the builder registry.
///
/// Builders live in their own registry since Gloas, apart from validators.
/// See EIP-7732.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BuilderIndex(pub u64);

impl BuilderIndex {
    /// The index as a vector position.
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

    /// The index a withdrawal names this builder by: the builder index with the flag set.
    ///
    /// See `convert_builder_index_to_validator_index` in the Gloas beacon chain spec.
    #[must_use]
    pub const fn withdrawal_index(self) -> ValidatorIndex {
        ValidatorIndex(self.0 | BUILDER_INDEX_FLAG)
    }
}

impl From<u64> for BuilderIndex {
    fn from(index: u64) -> Self {
        Self(index)
    }
}

impl From<usize> for BuilderIndex {
    /// Axiom targets 64-bit platforms only, so the conversion is lossless.
    fn from(index: usize) -> Self {
        Self(index as u64)
    }
}

impl fmt::Display for BuilderIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Ssz for BuilderIndex {
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

/// Position of a committee among the committees of one slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommitteeIndex(pub u64);

impl CommitteeIndex {
    /// The index as a vector position.
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

impl From<u64> for CommitteeIndex {
    fn from(index: u64) -> Self {
        Self(index)
    }
}

impl From<usize> for CommitteeIndex {
    /// Axiom targets 64-bit platforms only, so the conversion is lossless.
    fn from(index: usize) -> Self {
        Self(index as u64)
    }
}

impl fmt::Display for CommitteeIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Ssz for CommitteeIndex {
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

/// Sequence number of a withdrawal, counted across the whole chain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WithdrawalIndex(pub u64);

impl WithdrawalIndex {
    /// The index as a vector position.
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

impl From<u64> for WithdrawalIndex {
    fn from(index: u64) -> Self {
        Self(index)
    }
}

impl From<usize> for WithdrawalIndex {
    /// Axiom targets 64-bit platforms only, so the conversion is lossless.
    fn from(index: usize) -> Self {
        Self(index as u64)
    }
}

impl fmt::Display for WithdrawalIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Ssz for WithdrawalIndex {
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

/// Position of a blob among the blobs of one block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobIndex(pub u64);

impl BlobIndex {
    /// The index as a vector position.
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

impl From<u64> for BlobIndex {
    fn from(index: u64) -> Self {
        Self(index)
    }
}

impl From<usize> for BlobIndex {
    /// Axiom targets 64-bit platforms only, so the conversion is lossless.
    fn from(index: usize) -> Self {
        Self(index as u64)
    }
}

impl fmt::Display for BlobIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Ssz for BlobIndex {
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

/// Position of a column in the extended blob matrix of PeerDAS.
///
/// See EIP-7594.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ColumnIndex(pub u64);

impl ColumnIndex {
    /// The index as a vector position.
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

impl From<u64> for ColumnIndex {
    fn from(index: u64) -> Self {
        Self(index)
    }
}

impl From<usize> for ColumnIndex {
    /// Axiom targets 64-bit platforms only, so the conversion is lossless.
    fn from(index: usize) -> Self {
        Self(index as u64)
    }
}

impl fmt::Display for ColumnIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Ssz for ColumnIndex {
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

/// Identifier of a gossip subnet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubnetId(pub u64);

impl SubnetId {
    /// The index as a vector position.
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

impl From<u64> for SubnetId {
    fn from(index: u64) -> Self {
        Self(index)
    }
}

impl From<usize> for SubnetId {
    /// Axiom targets 64-bit platforms only, so the conversion is lossless.
    fn from(index: usize) -> Self {
        Self(index as u64)
    }
}

impl fmt::Display for SubnetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Ssz for SubnetId {
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
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn a_registry_index_names_no_builder() {
        // Validator 7 carries no flag, so it stays a validator.
        assert_eq!(ValidatorIndex(7).builder(), None);
    }

    #[test]
    fn builder_three_withdraws_under_the_flagged_index() {
        // Builder 3 is named 2^40 + 3 in a withdrawal, and the flag maps back to it.
        let flagged = BuilderIndex(3).withdrawal_index();
        assert_eq!(flagged, ValidatorIndex((1 << 40) + 3));
        assert_eq!(flagged.builder(), Some(BuilderIndex(3)));
    }

    proptest! {
        #[test]
        fn a_flagged_index_round_trips(index in 0_u64..(1 << 40)) {
            let builder = BuilderIndex(index);
            prop_assert_eq!(builder.withdrawal_index().builder(), Some(builder));
        }
    }
}
