//! Serialized BLS public keys and signatures.

use std::fmt;

use axiom_ssz::{DecodeError, Root, Ssz};

use crate::Hex;

/// A compressed BLS12-381 public key, as it appears in containers.
///
/// The bytes are not validated: they become a usable key only after decompression.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlsPubkey(pub [u8; 48]);

impl BlsPubkey {
    /// The all-zero value.
    pub const ZERO: Self = Self([0; 48]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

impl Default for BlsPubkey {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 48]> for BlsPubkey {
    fn from(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for BlsPubkey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for BlsPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for BlsPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for BlsPubkey {
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

/// A compressed BLS12-381 signature, as it appears in containers.
///
/// The bytes are not validated: they become a usable signature only after decompression.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlsSignature(pub [u8; 96]);

impl BlsSignature {
    /// The all-zero value.
    pub const ZERO: Self = Self([0; 96]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 96] {
        &self.0
    }

    /// Whether this selection proof's hash selects its signer, one in every modulo.
    ///
    /// Aggregators are picked this way, unpredictably to anyone without the signer's key.
    /// See `is_aggregator` in the phase0 validator spec.
    #[must_use]
    pub fn selects(&self, modulo: u64) -> bool {
        let digest = Root::sha256(&self.0);
        let mut word = [0; 8];
        word.copy_from_slice(&digest.0[..8]);
        u64::from_le_bytes(word).is_multiple_of(modulo)
    }
}

impl Default for BlsSignature {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 96]> for BlsSignature {
    fn from(bytes: [u8; 96]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for BlsSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for BlsSignature {
    const FIXED_SIZE: Option<usize> = Some(96);

    fn encoded_len(&self) -> usize {
        96
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 96]>::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        self.0.hash_tree_root()
    }
}
