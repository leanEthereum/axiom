//! Basic types: booleans, unsigned integers, and fixed byte arrays.
//!
//! Integers encode little-endian, as the spec requires for every `uintN`.

use crate::{DecodeError, Root, Ssz, merkle::Merkleizer};

impl Ssz for bool {
    const FIXED_SIZE: Option<usize> = Some(1);
    const PACKED_SIZE: Option<usize> = Some(1);

    fn encoded_len(&self) -> usize {
        1
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        match bytes {
            [0] => Ok(false),
            [1] => Ok(true),
            // Any other byte would give a boolean two encodings.
            [other] => Err(DecodeError::InvalidBoolean(*other)),
            _ => Err(DecodeError::InvalidLength {
                expected: 1,
                actual: bytes.len(),
            }),
        }
    }

    fn hash_tree_root(&self) -> Root {
        Root::from_partial(&[u8::from(*self)])
    }
}

impl Ssz for u8 {
    const FIXED_SIZE: Option<usize> = Some(1);
    const PACKED_SIZE: Option<usize> = Some(1);

    fn encoded_len(&self) -> usize {
        1
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[Self; 1]>::decode(bytes).map(|[byte]| byte)
    }

    fn hash_tree_root(&self) -> Root {
        Root::from_partial(&[*self])
    }
}

impl Ssz for u16 {
    const FIXED_SIZE: Option<usize> = Some(2);
    const PACKED_SIZE: Option<usize> = Some(2);

    fn encoded_len(&self) -> usize {
        2
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 2]>::decode(bytes).map(Self::from_le_bytes)
    }

    fn hash_tree_root(&self) -> Root {
        Root::from_partial(&self.to_le_bytes())
    }
}

impl Ssz for u32 {
    const FIXED_SIZE: Option<usize> = Some(4);
    const PACKED_SIZE: Option<usize> = Some(4);

    fn encoded_len(&self) -> usize {
        4
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 4]>::decode(bytes).map(Self::from_le_bytes)
    }

    fn hash_tree_root(&self) -> Root {
        Root::from_partial(&self.to_le_bytes())
    }
}

impl Ssz for u64 {
    const FIXED_SIZE: Option<usize> = Some(8);
    const PACKED_SIZE: Option<usize> = Some(8);

    fn encoded_len(&self) -> usize {
        8
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 8]>::decode(bytes).map(Self::from_le_bytes)
    }

    fn hash_tree_root(&self) -> Root {
        Root::from_partial(&self.to_le_bytes())
    }
}

impl Ssz for u128 {
    const FIXED_SIZE: Option<usize> = Some(16);
    const PACKED_SIZE: Option<usize> = Some(16);

    fn encoded_len(&self) -> usize {
        16
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; 16]>::decode(bytes).map(Self::from_le_bytes)
    }

    fn hash_tree_root(&self) -> Root {
        Root::from_partial(&self.to_le_bytes())
    }
}

/// A fixed byte array is the spec's `ByteVector[N]`, a vector of packed bytes.
impl<const N: usize> Ssz for [u8; N] {
    const FIXED_SIZE: Option<usize> = Some(N);

    fn encoded_len(&self) -> usize {
        N
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        bytes.try_into().map_err(|_| DecodeError::InvalidLength {
            expected: N,
            actual: bytes.len(),
        })
    }

    fn hash_tree_root(&self) -> Root {
        Merkleizer::root_of_bytes(self, N)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn integers_encode_little_endian() {
        // The least significant byte comes first on the wire.
        assert_eq!(0x0102_u16.encode(), [0x02, 0x01]);
        assert_eq!(0x0102_0304_u32.encode(), [0x04, 0x03, 0x02, 0x01]);
        assert_eq!(1_u64.encode(), [1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn boolean_rejects_non_canonical_byte() {
        // Only 0 and 1 are booleans, so 2 must fail rather than read as true.
        assert_eq!(bool::decode(&[2]), Err(DecodeError::InvalidBoolean(2)));
    }

    #[test]
    fn boolean_rejects_wrong_length() {
        assert_eq!(
            bool::decode(&[1, 0]),
            Err(DecodeError::InvalidLength {
                expected: 1,
                actual: 2
            })
        );
    }

    #[test]
    fn integer_root_is_padded_encoding() {
        // A basic value's root is its encoding, zero-padded to one chunk.
        let mut expected = [0; 32];
        expected[..8].copy_from_slice(&7_u64.to_le_bytes());

        assert_eq!(7_u64.hash_tree_root(), Root(expected));
    }

    #[test]
    fn byte_array_of_one_chunk_is_its_own_root() {
        // Thirty-two bytes fill exactly one chunk, so no hashing happens.
        let bytes = [9_u8; 32];

        assert_eq!(bytes.hash_tree_root(), Root(bytes));
    }

    proptest! {
        #[test]
        fn u64_round_trips(value: u64) {
            prop_assert_eq!(u64::decode(&value.encode()), Ok(value));
        }

        #[test]
        fn u128_round_trips(value: u128) {
            prop_assert_eq!(u128::decode(&value.encode()), Ok(value));
        }

        #[test]
        fn byte_array_round_trips(bytes: [u8; 48]) {
            prop_assert_eq!(<[u8; 48]>::decode(&bytes.encode()), Ok(bytes));
        }
    }
}
