//! The 256-bit unsigned integer.

use std::fmt;

use crate::{DecodeError, Root, Ssz};

/// A 256-bit unsigned integer, stored as its little-endian encoding.
///
/// Consensus code only carries these values, such as an execution base fee.
/// It never does arithmetic on them, so the type exposes bytes and small conversions only.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct U256(pub [u8; 32]);

impl U256 {
    /// Zero.
    pub const ZERO: Self = Self([0; 32]);

    /// The value of a 64-bit integer.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        Self(bytes)
    }

    /// The little-endian bytes.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl fmt::Debug for U256 {
    /// Renders big-endian hex, the order a human reads a number in.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0.iter().rev() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Ssz for U256 {
    const FIXED_SIZE: Option<usize> = Some(32);
    const PACKED_SIZE: Option<usize> = Some(32);

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
        Root(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_value_sits_in_the_low_bytes() {
        // 258 = 0x0102, so the encoding starts 0x02 0x01 and the rest is zero.
        let mut expected = [0; 32];
        expected[0] = 0x02;
        expected[1] = 0x01;

        assert_eq!(U256::from(258).encode(), expected);
    }
}
