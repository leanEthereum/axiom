//! Fixed-length bitfields.

use std::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use crate::{DecodeError, Length, Merkleizer, Root, Ssz};

/// Exactly `N` bits, the spec's `Bitvector[N]`.
///
/// Bit `i` lives in byte `i / 8` at position `i % 8`, least significant first.
///
/// ```text
/// bits 0..10 = 1 0 1 1 0 0 0 0 | 1 0
/// bytes      = 0b0000_1101       0b0000_0001
/// ```
pub struct BitVector<N> {
    /// Packed bits, with every padding bit past `N` held at zero.
    bytes: Vec<u8>,
    /// The length, carried in the type.
    length: PhantomData<N>,
}

impl<N: Length> BitVector<N> {
    /// Number of bytes holding `N` bits.
    const BYTES: usize = N::LEN.div_ceil(8);

    /// A bitvector with every bit clear.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bytes: vec![0; Self::BYTES],
            length: PhantomData,
        }
    }

    /// Number of bits.
    #[must_use]
    pub const fn len(&self) -> usize {
        N::LEN
    }

    /// Whether the bitvector has no bits, which SSZ never allows.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N::LEN == 0
    }

    /// The bit at an index, or nothing when the index is out of range.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<bool> {
        (index < N::LEN).then(|| self.bytes[index / 8] >> (index % 8) & 1 == 1)
    }

    /// Sets the bit at an index.
    ///
    /// # Panics
    ///
    /// Panics when the index is out of range.
    pub fn set(&mut self, index: usize, value: bool) {
        assert!(
            index < N::LEN,
            "bit index {index} out of range for length {}",
            N::LEN
        );
        let mask = 1 << (index % 8);
        if value {
            self.bytes[index / 8] |= mask;
        } else {
            self.bytes[index / 8] &= !mask;
        }
    }

    /// Iterates over the bits in order.
    pub fn iter(&self) -> impl Iterator<Item = bool> + '_ {
        (0..N::LEN).map(|index| self.bytes[index / 8] >> (index % 8) & 1 == 1)
    }

    /// Number of set bits.
    #[must_use]
    pub fn count_ones(&self) -> usize {
        self.bytes
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }

    /// The packed bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<N: Length> Default for BitVector<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N> Clone for BitVector<N> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            length: PhantomData,
        }
    }
}

impl<N: Length> fmt::Debug for BitVector<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BitVector(")?;
        for bit in self.iter() {
            f.write_str(if bit { "1" } else { "0" })?;
        }
        f.write_str(")")
    }
}

impl<N> PartialEq for BitVector<N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<N> Eq for BitVector<N> {}

impl<N> Hash for BitVector<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<N: Length> Ssz for BitVector<N> {
    const FIXED_SIZE: Option<usize> = Some(N::LEN.div_ceil(8));

    fn encoded_len(&self) -> usize {
        Self::BYTES
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != Self::BYTES {
            return Err(DecodeError::InvalidLength {
                expected: Self::BYTES,
                actual: bytes.len(),
            });
        }

        // Invariant: padding bits are zero, so each value has exactly one encoding.
        // A length that fills whole bytes leaves no padding to check.
        let used_bits = N::LEN % 8;
        if used_bits != 0 {
            let last_byte = bytes[Self::BYTES - 1];
            if last_byte >> used_bits != 0 {
                return Err(DecodeError::ExcessBits {
                    length: N::LEN,
                    last_byte,
                });
            }
        }

        Ok(Self {
            bytes: bytes.to_vec(),
            length: PhantomData,
        })
    }

    fn hash_tree_root(&self) -> Root {
        Merkleizer::root_of_bytes(&self.bytes, Self::BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Const;

    #[test]
    fn bits_pack_least_significant_first() {
        // Fixture state: bits 0, 2, 3 and 8 set in a 10-bit vector.
        let mut bits = BitVector::<Const<10>>::new();
        for index in [0, 2, 3, 8] {
            bits.set(index, true);
        }

        assert_eq!(bits.encode(), [0b0000_1101, 0b0000_0001]);
        assert_eq!(bits.count_ones(), 4);
    }

    #[test]
    fn padding_bits_are_rejected() {
        // Bit 10 lies past the 10-bit length, in the padding of the second byte.
        assert_eq!(
            BitVector::<Const<10>>::decode(&[0, 0b0000_0100]),
            Err(DecodeError::ExcessBits {
                length: 10,
                last_byte: 0b0000_0100
            })
        );
    }

    #[test]
    fn out_of_range_bit_reads_as_none() {
        assert_eq!(BitVector::<Const<4>>::new().get(4), None);
    }
}
