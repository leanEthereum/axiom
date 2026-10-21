//! Serialized KZG commitments and proofs.

use std::fmt;

use axiom_ssz::{DecodeError, Root, Ssz};

use crate::Hex;

/// A KZG commitment to a blob polynomial, a compressed G1 point.
///
/// See EIP-4844.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KzgCommitment(pub [u8; 48]);

impl KzgCommitment {
    /// The all-zero value.
    pub const ZERO: Self = Self([0; 48]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

impl Default for KzgCommitment {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 48]> for KzgCommitment {
    fn from(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for KzgCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for KzgCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for KzgCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for KzgCommitment {
    const FIXED_SIZE: Option<usize> = Some(48);

    fn encoded_len(&self) -> usize {
        48
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 48]>::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        self.0.hash_tree_root()
    }
}

/// A KZG opening proof, a compressed G1 point.
///
/// See EIP-4844 and EIP-7594.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KzgProof(pub [u8; 48]);

impl KzgProof {
    /// The all-zero value.
    pub const ZERO: Self = Self([0; 48]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

impl Default for KzgProof {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 48]> for KzgProof {
    fn from(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for KzgProof {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for KzgProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for KzgProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for KzgProof {
    const FIXED_SIZE: Option<usize> = Some(48);

    fn encoded_len(&self) -> usize {
        48
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 48]>::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        self.0.hash_tree_root()
    }
}
