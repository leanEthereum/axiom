//! Serialized KZG commitments and proofs.

use std::fmt;

use axiom_ssz::{DecodeError, Root, Ssz};

use crate::{Hex, VersionedHash, constants::VERSIONED_HASH_VERSION_KZG};

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

    /// The hash the execution layer knows this commitment by.
    ///
    /// It is sha256 of the commitment, with the first byte replaced by the version.
    /// See `kzg_commitment_to_versioned_hash` in the Deneb beacon chain spec.
    #[must_use]
    pub fn versioned_hash(&self) -> VersionedHash {
        // The version byte lets a later commitment scheme reuse the same hash slot.
        let mut hash = Root::sha256(&self.0).0;
        hash[0] = VERSIONED_HASH_VERSION_KZG;
        VersionedHash(hash)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_hash_replaces_the_first_byte_with_the_version() {
        // Fixture state: the point at infinity, 0xc0 followed by 47 zero bytes.
        let mut bytes = [0; 48];
        bytes[0] = 0xc0;

        // Expected: sha256 of those bytes, first byte overwritten by version 0x01.
        //
        //     sha256 = 0x0657f375...c444014 (computed independently with Python hashlib)
        let expected = "010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014";
        assert_eq!(
            KzgCommitment(bytes).versioned_hash().to_string(),
            format!("0x{expected}")
        );
    }
}
