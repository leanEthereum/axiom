//! Fixed-size byte strings with a protocol meaning.

use std::fmt;

use axiom_ssz::{DecodeError, Root, Ssz};

use crate::Hex;

/// Thirty-two opaque bytes, such as a randao mix or withdrawal credentials.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Bytes32(pub [u8; 32]);

impl Bytes32 {
    /// The all-zero value.
    pub const ZERO: Self = Self([0; 32]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for Bytes32 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 32]> for Bytes32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Bytes32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for Bytes32 {
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

/// A 32-byte hash produced by the execution layer, such as a block hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// The all-zero value.
    pub const ZERO: Self = Self([0; 32]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for Hash32 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 32]> for Hash32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Hash32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for Hash32 {
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

/// Hash of a KZG commitment, prefixed with its version byte.
///
/// See EIP-4844.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VersionedHash(pub [u8; 32]);

impl VersionedHash {
    /// The all-zero value.
    pub const ZERO: Self = Self([0; 32]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for VersionedHash {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 32]> for VersionedHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for VersionedHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for VersionedHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for VersionedHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for VersionedHash {
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

/// A fork version, which tags every signature with the fork it belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Version(pub [u8; 4]);

impl Version {
    /// The all-zero value.
    pub const ZERO: Self = Self([0; 4]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 4]> for Version {
    fn from(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Version {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for Version {
    const FIXED_SIZE: Option<usize> = Some(4);

    fn encoded_len(&self) -> usize {
        4
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 4]>::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        self.0.hash_tree_root()
    }
}

/// The kind of message a signature domain covers, such as an attestation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainType(pub [u8; 4]);

impl DomainType {
    /// The all-zero value.
    pub const ZERO: Self = Self([0; 4]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }
}

impl Default for DomainType {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 4]> for DomainType {
    fn from(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for DomainType {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for DomainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for DomainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for DomainType {
    const FIXED_SIZE: Option<usize> = Some(4);

    fn encoded_len(&self) -> usize {
        4
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 4]>::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        self.0.hash_tree_root()
    }
}

/// A signature domain: the domain type joined with a fork data root.
///
/// Signing over it stops a signature from being replayed on another fork or chain.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Domain(pub [u8; 32]);

impl Domain {
    /// The all-zero value.
    pub const ZERO: Self = Self([0; 32]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for Domain {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 32]> for Domain {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Domain {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for Domain {
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

/// Short fork identifier used to separate gossip topics between forks.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ForkDigest(pub [u8; 4]);

impl ForkDigest {
    /// The all-zero value.
    pub const ZERO: Self = Self([0; 4]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }
}

impl Default for ForkDigest {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 4]> for ForkDigest {
    fn from(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for ForkDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ForkDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for ForkDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for ForkDigest {
    const FIXED_SIZE: Option<usize> = Some(4);

    fn encoded_len(&self) -> usize {
        4
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 4]>::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        self.0.hash_tree_root()
    }
}

/// An execution layer account address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecutionAddress(pub [u8; 20]);

impl ExecutionAddress {
    /// The all-zero value.
    pub const ZERO: Self = Self([0; 20]);

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl Default for ExecutionAddress {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; 20]> for ExecutionAddress {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for ExecutionAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ExecutionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl fmt::Display for ExecutionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(&self.0), f)
    }
}

impl Ssz for ExecutionAddress {
    const FIXED_SIZE: Option<usize> = Some(20);

    fn encoded_len(&self) -> usize {
        20
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 20]>::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        self.0.hash_tree_root()
    }
}
