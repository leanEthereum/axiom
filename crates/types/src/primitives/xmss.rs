//! Byte strings of leanXMSS, the hash-based signature of the post-quantum key registry.
//!
//! See EIP-8450.

use std::fmt;

use axiom_ssz::{DecodeError, Root, Ssz};

use crate::Hex;

/// A Keccak-256 output truncated to 16 bytes.
///
/// It is a chain value, a Merkle node, a randomizer, or a key's public parameter.
/// See `Hash16` in EIP-8450.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash16(pub [u8; 16]);

impl Hash16 {
    /// The all-zero value.
    pub const ZERO: Self = Self([0; 16]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Default for Hash16 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 16]> for Hash16 {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Hash16 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Hash16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for Hash16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for Hash16 {
    const FIXED_SIZE: Option<usize> = Some(16);

    fn encoded_len(&self) -> usize {
        16
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 16]>::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        self.0.hash_tree_root()
    }
}

/// Position of the one-time key a leanXMSS signature uses.
///
/// ```text
///     bits 31..16   which bottom tree
///     bits 15..0    which leaf in it
/// ```
///
/// A key signs at most one message per leaf index.
/// See `XMSSSignature` in EIP-8450.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct XmssLeafIndex(pub u32);

impl From<u32> for XmssLeafIndex {
    fn from(index: u32) -> Self {
        Self(index)
    }
}

impl fmt::Display for XmssLeafIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Ssz for XmssLeafIndex {
    const FIXED_SIZE: Option<usize> = u32::FIXED_SIZE;
    const PACKED_SIZE: Option<usize> = u32::PACKED_SIZE;

    fn encoded_len(&self) -> usize {
        self.0.encoded_len()
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        self.0.encode_to(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        u32::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        self.0.hash_tree_root()
    }
}

/// A leanXMSS public key: the root of its top tree, then its public parameter.
///
/// Every 32-byte string is a well-formed key, so the bytes need no validation.
/// See `XMSSPublicKey` in EIP-8450.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct XmssPublicKey(pub [u8; 32]);

impl XmssPublicKey {
    /// The all-zero value, held by validators without a registered key.
    pub const ZERO: Self = Self([0; 32]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for XmssPublicKey {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 32]> for XmssPublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for XmssPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for XmssPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for XmssPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for XmssPublicKey {
    const FIXED_SIZE: Option<usize> = Some(32);

    fn encoded_len(&self) -> usize {
        32
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 32]>::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        self.0.hash_tree_root()
    }
}
