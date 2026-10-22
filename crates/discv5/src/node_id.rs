//! The 256-bit identifier that places a node in the discovery keyspace.

use std::{array, fmt};

use axiom_crypto::{keccak::Keccak256, secp256k1::PublicKey};

use crate::distance::{Distance, LogDistance};

/// A node's identifier: the keccak256 hash of its uncompressed public key, under scheme "v4".
///
/// See EIP-778, "v4" identity scheme.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// The identifier of a "v4" public key.
    #[must_use]
    pub fn from_public_key(key: &PublicKey) -> Self {
        // The hash covers x || y, without the 0x04 SEC 1 prefix.
        let uncompressed = key.to_uncompressed();
        Self(Keccak256::digest(&uncompressed[1..]))
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The XOR distance to another identifier, as a big-endian number.
    #[must_use]
    pub fn distance(&self, other: &Self) -> Distance {
        // Bytewise XOR keeps the big-endian order, so the result compares as a number.
        Distance(array::from_fn(|i| self.0[i] ^ other.0[i]))
    }

    /// The logarithmic distance to another identifier: the bit length of their XOR.
    ///
    /// Equal identifiers are at distance zero.
    #[must_use]
    pub fn log_distance(&self, other: &Self) -> LogDistance {
        self.distance(other).log2()
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Eight hex digits tell nodes apart in logs.
        write!(f, "NodeId(")?;
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "..)")
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The full identifier, lowercase hex without prefix.
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::secp256k1::SecretKey;

    use super::*;

    #[test]
    fn eip778_vector_identity() {
        // EIP-778 test vector: this key owns node a448f24c...617f7.
        let secret = [
            0xb7, 0x1c, 0x71, 0xa6, 0x7e, 0x11, 0x77, 0xad, 0x4e, 0x90, 0x16, 0x95, 0xe1, 0xb4,
            0xb9, 0xee, 0x17, 0xae, 0x16, 0xc6, 0x66, 0x8d, 0x31, 0x3e, 0xac, 0x2f, 0x96, 0xdb,
            0xcd, 0xa3, 0xf2, 0x91,
        ];
        let key = SecretKey::from_bytes(&secret).unwrap().public_key();
        assert_eq!(
            NodeId::from_public_key(&key).to_string(),
            "a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
        );
    }

    #[test]
    fn log_distance_is_the_xor_bit_length() {
        // Equal identifiers are at distance 0.
        let zero = NodeId([0; 32]);
        assert_eq!(zero.log_distance(&zero), LogDistance::ZERO);
        // A difference in the lowest bit is distance 1.
        let mut low = [0; 32];
        low[31] = 1;
        assert_eq!(zero.log_distance(&NodeId(low)).get(), 1);
        // A difference in the top bit is distance 256.
        let mut high = [0; 32];
        high[0] = 0x80;
        assert_eq!(zero.log_distance(&NodeId(high)).get(), 256);
        // 0x0100 differs in bit 8, so the distance is 9.
        let mut mid = [0; 32];
        mid[30] = 1;
        assert_eq!(zero.log_distance(&NodeId(mid)).get(), 9);
    }
}
