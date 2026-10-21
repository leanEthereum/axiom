//! Indices into the registry, committees, and data structures.

use std::fmt;

use axiom_ssz::{DecodeError, Root, Ssz};

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
