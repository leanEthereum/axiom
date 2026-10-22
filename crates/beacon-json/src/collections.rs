//! JSON forms of SSZ collections.
//!
//! ```text
//!     byte vectors and byte lists   hex                    length or limit checked
//!     bitlists and bitvectors       hex of the SSZ bytes   sentinel and padding checked
//!     lists and vectors             array                  count checked before any element
//! ```
//!
//! A bitlist travels as its SSZ bytes, sentinel bit included.
//! Decoding goes through the SSZ decoder, so only the canonical encoding is accepted.

use axiom_json::{Data, Json};
use axiom_ssz::{
    BitList, BitVector, ByteList, ByteVector, Length, List, ProgressiveBitList, ProgressiveList,
    Ssz, Vector,
};

use crate::{ApiJson, ApiJsonError, ApiJsonErrorKind, reader::Reader};

impl<N: Length> ApiJson for ByteVector<N> {
    fn to_json(&self) -> Json {
        Json::String(self.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let bytes = Reader::new(value)
            .hex_bytes(|actual| ApiJsonErrorKind::check_length(N::LEN, actual))?;
        // The count was checked before decoding, so the conversion holds.
        Self::try_from(bytes.as_slice())
            .map_err(|_| ApiJsonErrorKind::WrongLength {
                expected: N::LEN,
                actual: bytes.len(),
            })
            .map_err(ApiJsonError::new)
    }
}

impl<N: Length> ApiJson for ByteList<N> {
    fn to_json(&self) -> Json {
        Json::String(self.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let bytes =
            Reader::new(value).hex_bytes(|actual| ApiJsonErrorKind::check_limit(N::LEN, actual))?;
        let actual = bytes.len();
        // The count was checked before decoding, so the conversion holds.
        Self::try_from(bytes)
            .map_err(|_| ApiJsonErrorKind::TooLong {
                limit: N::LEN,
                actual,
            })
            .map_err(ApiJsonError::new)
    }
}

impl ApiJson for ProgressiveList<u8> {
    /// Hex of any length, as an unbounded byte list is.
    fn to_json(&self) -> Json {
        Json::String(self.as_slice().to_data())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        // No limit to check: the request size bounds the byte count.
        Reader::new(value).hex_bytes(|_| Ok(())).map(Self::from)
    }
}

impl<N: Length> ApiJson for BitList<N> {
    fn to_json(&self) -> Json {
        Json::String(self.encode().to_data())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        // N bits and the sentinel need N / 8 + 1 bytes, so more is refused unread.
        let bytes = Reader::new(value)
            .hex_bytes(|actual| ApiJsonErrorKind::check_limit(N::LEN / 8 + 1, actual))?;
        Self::decode(&bytes).map_err(|error| ApiJsonError::new(ApiJsonErrorKind::Bits(error)))
    }
}

impl<N: Length> ApiJson for BitVector<N> {
    fn to_json(&self) -> Json {
        Json::String(self.as_bytes().to_data())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let bytes = Reader::new(value)
            .hex_bytes(|actual| ApiJsonErrorKind::check_length(N::LEN.div_ceil(8), actual))?;
        Self::decode(&bytes).map_err(|error| ApiJsonError::new(ApiJsonErrorKind::Bits(error)))
    }
}

impl ApiJson for ProgressiveBitList {
    fn to_json(&self) -> Json {
        Json::String(self.encode().to_data())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let bytes = Reader::new(value).hex_bytes(|_| Ok(()))?;
        Self::decode(&bytes).map_err(|error| ApiJsonError::new(ApiJsonErrorKind::Bits(error)))
    }
}

impl<T: ApiJson, N: Length> ApiJson for List<T, N> {
    fn to_json(&self) -> Json {
        Json::Array(self.iter().map(ApiJson::to_json).collect())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let items = Reader::new(value).items()?;
        // Refuse an oversized list before decoding any element of it.
        ApiJsonErrorKind::check_limit(N::LEN, items.len())?;
        let actual = items.len();
        Self::try_from(items.decode()?)
            .map_err(|_| ApiJsonErrorKind::TooLong {
                limit: N::LEN,
                actual,
            })
            .map_err(ApiJsonError::new)
    }
}

impl<T: ApiJson, N: Length> ApiJson for Vector<T, N> {
    fn to_json(&self) -> Json {
        Json::Array(self.iter().map(ApiJson::to_json).collect())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let items = Reader::new(value).items()?;
        // A vector's length is exact.
        ApiJsonErrorKind::check_length(N::LEN, items.len())?;
        let actual = items.len();
        Self::try_from(items.decode()?)
            .map_err(|_| ApiJsonErrorKind::WrongLength {
                expected: N::LEN,
                actual,
            })
            .map_err(ApiJsonError::new)
    }
}

impl<T: ApiJson> ApiJson for ProgressiveList<T> {
    fn to_json(&self) -> Json {
        Json::Array(self.iter().map(ApiJson::to_json).collect())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        // No limit to check: the request size bounds the element count.
        Reader::new(value).items()?.decode().map(Self::from)
    }
}

#[cfg(test)]
mod tests {
    use axiom_json::HexError;
    use axiom_ssz::{Const, DecodeError};
    use proptest::{collection::vec, prelude::*};

    use super::*;
    use crate::DecimalError;

    /// The error of a broken rule at the outermost value.
    fn error(kind: ApiJsonErrorKind) -> ApiJsonError {
        ApiJsonError::new(kind)
    }

    #[test]
    fn byte_vector_checks_its_length() {
        // Four bytes against a vector of eight.
        assert_eq!(
            ByteVector::<Const<8>>::from_json(&Json::from("0x00000000")),
            Err(error(ApiJsonErrorKind::WrongLength {
                expected: 8,
                actual: 4
            }))
        );
    }

    #[test]
    fn byte_list_checks_its_limit() {
        // Two bytes fit a limit of two; three do not.
        assert_eq!(
            ByteList::<Const<2>>::from_json(&Json::from("0x0102")).map(ByteList::into_vec),
            Ok(vec![1, 2])
        );
        assert_eq!(
            ByteList::<Const<2>>::from_json(&Json::from("0x010203")),
            Err(error(ApiJsonErrorKind::TooLong {
                limit: 2,
                actual: 3
            }))
        );

        // The empty list is the bare prefix.
        assert_eq!(ByteList::<Const<2>>::new().to_json(), Json::from("0x"));
    }

    #[test]
    fn progressive_bytes_are_unbounded_hex() {
        // Any length reads, and the encoding is plain hex.
        let bytes = ProgressiveList::from(vec![0xab; 3]);
        assert_eq!(bytes.to_json(), Json::from("0xababab"));
        assert_eq!(
            ProgressiveList::<u8>::from_json(&Json::from("0xababab")),
            Ok(bytes)
        );
    }

    #[test]
    fn bitlist_is_hex_of_its_ssz_encoding() {
        // Bits 1 0 1 put the sentinel on bit 3: 0b0000_1101 is 0x0d.
        let mut bits = BitList::<Const<8>>::with_len(3).unwrap();
        bits.set(0, true);
        bits.set(2, true);
        assert_eq!(bits.to_json(), Json::from("0x0d"));
        assert_eq!(
            BitList::<Const<8>>::from_json(&Json::from("0x0d")),
            Ok(bits)
        );

        // The empty list is the sentinel alone.
        assert_eq!(
            BitList::<Const<8>>::from_json(&Json::from("0x01")),
            Ok(BitList::default())
        );
    }

    #[test]
    fn bitlist_rejects_non_canonical_encodings() {
        // Empty bytes and a zero last byte carry no sentinel.
        assert_eq!(
            BitList::<Const<8>>::from_json(&Json::from("0x")),
            Err(error(ApiJsonErrorKind::Bits(
                DecodeError::MissingSentinel { length: 0 }
            )))
        );
        assert_eq!(
            BitList::<Const<8>>::from_json(&Json::from("0x0d00")),
            Err(error(ApiJsonErrorKind::Bits(
                DecodeError::MissingSentinel { length: 2 }
            )))
        );

        // Nine bits against a limit of eight: 0xff then the sentinel on bit 1 of 0x03.
        assert_eq!(
            BitList::<Const<8>>::from_json(&Json::from("0xff03")),
            Err(error(ApiJsonErrorKind::Bits(
                DecodeError::TooManyElements {
                    limit: 8,
                    actual: 9
                }
            )))
        );

        // Three bytes cannot hold at most 8 bits and a sentinel, refused before decoding.
        assert_eq!(
            BitList::<Const<8>>::from_json(&Json::from("0xffff01")),
            Err(error(ApiJsonErrorKind::TooLong {
                limit: 2,
                actual: 3
            }))
        );
    }

    #[test]
    fn bitvector_checks_length_and_padding() {
        // Four bits fill the low half of one byte.
        let mut bits = BitVector::<Const<4>>::new();
        bits.set(1, true);
        assert_eq!(bits.to_json(), Json::from("0x02"));
        assert_eq!(
            BitVector::<Const<4>>::from_json(&Json::from("0x02")),
            Ok(bits)
        );

        // Two bytes for four bits.
        assert_eq!(
            BitVector::<Const<4>>::from_json(&Json::from("0x0200")),
            Err(error(ApiJsonErrorKind::WrongLength {
                expected: 1,
                actual: 2
            }))
        );

        // Bit 4 is padding, so 0x12 sets a bit past the end.
        assert_eq!(
            BitVector::<Const<4>>::from_json(&Json::from("0x12")),
            Err(error(ApiJsonErrorKind::Bits(DecodeError::ExcessBits {
                length: 4,
                last_byte: 0x12
            })))
        );
    }

    #[test]
    fn progressive_bitlist_needs_its_sentinel() {
        // 0x0d is bits 1 0 1; a zero byte has no sentinel.
        let mut bits = ProgressiveBitList::with_len(3);
        bits.set(0, true);
        bits.set(2, true);
        assert_eq!(ProgressiveBitList::from_json(&Json::from("0x0d")), Ok(bits));
        assert_eq!(
            ProgressiveBitList::from_json(&Json::from("0x00")),
            Err(error(ApiJsonErrorKind::Bits(
                DecodeError::MissingSentinel { length: 1 }
            )))
        );
    }

    #[test]
    fn lists_check_limits_and_locate_errors() {
        // Three items against a limit of two, refused before any element is read.
        let three = Json::Array(vec![Json::from("x"); 3]);
        assert_eq!(
            List::<u64, Const<2>>::from_json(&three),
            Err(error(ApiJsonErrorKind::TooLong {
                limit: 2,
                actual: 3
            }))
        );

        // A bad second element is reported at index 1.
        let bad = Json::Array(vec![Json::from("1"), Json::from("0x2")]);
        assert_eq!(
            List::<u64, Const<4>>::from_json(&bad),
            Err(error(ApiJsonErrorKind::Decimal(DecimalError::InvalidDigit {
                offset: 1
            }))
            .at_index(1))
        );
    }

    #[test]
    fn vectors_need_their_exact_length() {
        // Two items for a vector of three.
        let two = Json::Array(vec![Json::from("1"); 2]);
        assert_eq!(
            Vector::<u64, Const<3>>::from_json(&two),
            Err(error(ApiJsonErrorKind::WrongLength {
                expected: 3,
                actual: 2
            }))
        );

        // A hex string is no vector.
        assert_eq!(
            Vector::<u64, Const<3>>::from_json(&Json::from("0x")),
            Err(error(ApiJsonErrorKind::Type {
                expected: "an array",
                found: "string"
            }))
        );
    }

    #[test]
    fn byte_strings_with_bad_hex_fail_as_hex() {
        // A missing prefix reaches the hex decoder unchecked.
        assert_eq!(
            ByteList::<Const<4>>::from_json(&Json::from("0102")),
            Err(error(ApiJsonErrorKind::Hex(HexError::MissingPrefix)))
        );
    }

    proptest! {
        #[test]
        fn collections_round_trip(
            bits in vec(any::<bool>(), 0..=16),
            fixed in vec(any::<bool>(), 12),
            items in vec(any::<u64>(), 0..=4),
            bytes in vec(any::<u8>(), 0..=8),
        ) {
            // A bitlist of up to 16 bits, its limit.
            let mut list = BitList::<Const<16>>::with_len(bits.len()).unwrap();
            let mut progressive = ProgressiveBitList::with_len(bits.len());
            for (index, bit) in bits.iter().enumerate() {
                list.set(index, *bit);
                progressive.set(index, *bit);
            }
            prop_assert_eq!(BitList::from_json(&list.to_json()), Ok(list));
            prop_assert_eq!(
                ProgressiveBitList::from_json(&progressive.to_json()),
                Ok(progressive)
            );

            // A bitvector of 12 bits, which pads its second byte.
            let mut vector = BitVector::<Const<12>>::new();
            for (index, bit) in fixed.iter().enumerate() {
                vector.set(index, *bit);
            }
            prop_assert_eq!(BitVector::from_json(&vector.to_json()), Ok(vector));

            // A list of up to four decimals, and a byte list of up to eight bytes.
            let list = List::<u64, Const<4>>::try_from(items).unwrap();
            prop_assert_eq!(List::from_json(&list.to_json()), Ok(list));
            let byte_list = ByteList::<Const<8>>::try_from(bytes).unwrap();
            prop_assert_eq!(ByteList::from_json(&byte_list.to_json()), Ok(byte_list));
        }
    }
}
