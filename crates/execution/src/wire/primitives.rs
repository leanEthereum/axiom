//! JSON forms of scalars, byte strings, and SSZ collections.
//!
//! ```text
//!     u64, U256, Gwei, indices   QUANTITY   "0x0", "0x400"
//!     hashes, roots, addresses   DATA       fixed length, checked
//!     byte lists                 DATA       up to the list's limit
//!     lists and vectors          array      element by element
//! ```

use axiom_json::{Data, HexError, Json, Quantity};
use axiom_ssz::{ByteList, ByteVector, Length, List, U256, Vector};
use axiom_types::{
    Bytes32, ExecutionAddress, Gwei, Hash32, KzgCommitment, KzgProof, Root, ValidatorIndex,
    VersionedHash, WithdrawalIndex,
};

use super::{JsonCodec, wrong_type};
use crate::{WireError, WireErrorKind};

/// The text of a value that must be a string.
fn text(value: &Json) -> Result<&str, WireError> {
    value.as_str().ok_or_else(|| wrong_type("string", value))
}

/// Maps a hex error into the wire error that describes it best.
const fn hex_error(error: HexError) -> WireError {
    match error {
        // A DATA of the wrong size is a length problem, not an encoding one.
        HexError::WrongLength { expected, actual } => {
            WireError::new(WireErrorKind::WrongLength { expected, actual })
        }
        other => WireError::new(WireErrorKind::Hex(other)),
    }
}

/// Reads a QUANTITY of up to 64 bits.
fn read_quantity(value: &Json) -> Result<u64, WireError> {
    u64::from_quantity(text(value)?).map_err(hex_error)
}

/// Reads a DATA of exactly N bytes.
pub(crate) fn read_fixed<const N: usize>(value: &Json) -> Result<[u8; N], WireError> {
    <[u8; N]>::from_data(text(value)?).map_err(hex_error)
}

impl JsonCodec for u64 {
    fn to_json(&self) -> Json {
        Json::String(self.to_quantity())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        read_quantity(value)
    }
}

impl JsonCodec for U256 {
    fn to_json(&self) -> Json {
        Json::String(self.to_quantity())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        Self::from_quantity(text(value)?).map_err(hex_error)
    }
}

impl JsonCodec for bool {
    fn to_json(&self) -> Json {
        Json::Bool(*self)
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        value.as_bool().ok_or_else(|| wrong_type("boolean", value))
    }
}

impl JsonCodec for String {
    fn to_json(&self) -> Json {
        Json::from(self.as_str())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        text(value).map(str::to_owned)
    }
}

impl JsonCodec for Gwei {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        read_quantity(value).map(Self)
    }
}

impl JsonCodec for WithdrawalIndex {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        read_quantity(value).map(Self)
    }
}

impl JsonCodec for ValidatorIndex {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        read_quantity(value).map(Self)
    }
}

impl JsonCodec for Hash32 {
    fn to_json(&self) -> Json {
        Json::String(self.0.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        read_fixed(value).map(Self)
    }
}

impl JsonCodec for Bytes32 {
    fn to_json(&self) -> Json {
        Json::String(self.0.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        read_fixed(value).map(Self)
    }
}

impl JsonCodec for Root {
    fn to_json(&self) -> Json {
        Json::String(self.0.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        read_fixed(value).map(Self)
    }
}

impl JsonCodec for ExecutionAddress {
    fn to_json(&self) -> Json {
        Json::String(self.0.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        read_fixed(value).map(Self)
    }
}

impl JsonCodec for VersionedHash {
    fn to_json(&self) -> Json {
        Json::String(self.0.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        read_fixed(value).map(Self)
    }
}

impl JsonCodec for KzgCommitment {
    fn to_json(&self) -> Json {
        Json::String(self.0.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        read_fixed(value).map(Self)
    }
}

impl JsonCodec for KzgProof {
    fn to_json(&self) -> Json {
        Json::String(self.0.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        read_fixed(value).map(Self)
    }
}

impl JsonCodec for Vec<u8> {
    /// A DATA of any length.
    fn to_json(&self) -> Json {
        Json::String(self.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        Self::from_data(text(value)?).map_err(hex_error)
    }
}

impl<N: Length> JsonCodec for ByteVector<N> {
    fn to_json(&self) -> Json {
        Json::String(self.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let text = text(value)?;
        // Check the length from the text before decoding a 128 KiB blob that cannot fit.
        let expected_text = 2 + 2 * N::LEN;
        if text.len() != expected_text && text.starts_with("0x") && text.len() % 2 == 0 {
            return Err(WireError::new(WireErrorKind::WrongLength {
                expected: N::LEN,
                actual: (text.len() - 2) / 2,
            }));
        }
        let bytes = Vec::<u8>::from_data(text).map_err(hex_error)?;
        Self::try_from(bytes.as_slice()).map_err(|_| {
            WireError::new(WireErrorKind::WrongLength {
                expected: N::LEN,
                actual: bytes.len(),
            })
        })
    }
}

impl<N: Length> JsonCodec for ByteList<N> {
    fn to_json(&self) -> Json {
        Json::String(self.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let bytes = Vec::<u8>::from_data(text(value)?).map_err(hex_error)?;
        let actual = bytes.len();
        Self::try_from(bytes).map_err(|_| {
            WireError::new(WireErrorKind::TooLong {
                limit: N::LEN,
                actual,
            })
        })
    }
}

impl<T: JsonCodec, N: Length> JsonCodec for List<T, N> {
    fn to_json(&self) -> Json {
        Json::Array(self.iter().map(JsonCodec::to_json).collect())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let items = value.as_array().ok_or_else(|| wrong_type("array", value))?;
        // Refuse an oversized list before decoding any element of it.
        if items.len() > N::LEN {
            return Err(WireError::new(WireErrorKind::TooLong {
                limit: N::LEN,
                actual: items.len(),
            }));
        }
        let decoded = decode_items(items)?;
        // The length is checked above, so the conversion cannot fail.
        Self::try_from(decoded).map_err(|_| {
            WireError::new(WireErrorKind::TooLong {
                limit: N::LEN,
                actual: items.len(),
            })
        })
    }
}

impl<T: JsonCodec, N: Length> JsonCodec for Vector<T, N> {
    fn to_json(&self) -> Json {
        Json::Array(self.iter().map(JsonCodec::to_json).collect())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let items = value.as_array().ok_or_else(|| wrong_type("array", value))?;
        // A vector's length is exact.
        if items.len() != N::LEN {
            return Err(WireError::new(WireErrorKind::WrongLength {
                expected: N::LEN,
                actual: items.len(),
            }));
        }
        let decoded = decode_items(items)?;
        Self::try_from(decoded).map_err(|_| {
            WireError::new(WireErrorKind::WrongLength {
                expected: N::LEN,
                actual: items.len(),
            })
        })
    }
}

/// Decodes array elements, locating any error by its index.
fn decode_items<T: JsonCodec>(items: &[Json]) -> Result<Vec<T>, WireError> {
    items
        .iter()
        .enumerate()
        .map(|(index, item)| T::from_json(item).map_err(|error| error.at_index(index)))
        .collect()
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Const;

    use super::*;

    #[test]
    fn quantities() {
        // 1024 is "0x400"; a leading zero is a hex error, a number a type error.
        assert_eq!(1024_u64.to_json(), Json::from("0x400"));
        assert_eq!(u64::from_json(&Json::from("0x400")), Ok(1024));
        assert_eq!(
            u64::from_json(&Json::from("0x0400")),
            Err(WireError::new(WireErrorKind::Hex(HexError::LeadingZero)))
        );
        assert_eq!(
            u64::from_json(&Json::from(1024_u64)),
            Err(WireError::new(WireErrorKind::Type {
                expected: "string",
                found: "number"
            }))
        );
    }

    #[test]
    fn fixed_bytes_check_length() {
        // A 20-byte address given 19 bytes.
        let short = Json::String([0x11; 19].to_data());
        assert_eq!(
            ExecutionAddress::from_json(&short),
            Err(WireError::new(WireErrorKind::WrongLength {
                expected: 20,
                actual: 19
            }))
        );
    }

    #[test]
    fn lists_check_limits_and_locate_errors() {
        // Three items against a limit of two.
        let three = Json::Array(vec![Json::from("0x1"); 3]);
        assert_eq!(
            List::<u64, Const<2>>::from_json(&three),
            Err(WireError::new(WireErrorKind::TooLong {
                limit: 2,
                actual: 3
            }))
        );

        // A bad second element is reported at index 1.
        let bad = Json::Array(vec![Json::from("0x1"), Json::from("1")]);
        let error = List::<u64, Const<4>>::from_json(&bad).unwrap_err();
        assert_eq!(error.path(), "[1]");
        assert_eq!(error.kind(), &WireErrorKind::Hex(HexError::MissingPrefix));

        // A 3-byte list against a 2-byte limit.
        let bytes = Json::String([1, 2, 3].to_data());
        assert_eq!(
            ByteList::<Const<2>>::from_json(&bytes),
            Err(WireError::new(WireErrorKind::TooLong {
                limit: 2,
                actual: 3
            }))
        );
    }

    #[test]
    fn byte_vector_length_is_checked_before_decoding() {
        // Four bytes of DATA against a vector of eight.
        let four = Json::String([0; 4].to_data());
        assert_eq!(
            ByteVector::<Const<8>>::from_json(&four),
            Err(WireError::new(WireErrorKind::WrongLength {
                expected: 8,
                actual: 4
            }))
        );
    }
}
