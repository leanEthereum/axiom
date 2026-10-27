//! JSON forms of scalars and fixed-size byte strings.
//!
//! ```text
//!     u32, u64, U256, Slot, Gwei, indices   decimal string   "0", "1024"
//!     bool                                  JSON boolean     true
//!     roots, hashes, keys, signatures       hex              fixed length, checked
//! ```

use axiom_json::{Data, Json};
use axiom_ssz::U256;
use axiom_types::{
    BlobIndex, BlsPubkey, BlsSignature, BuilderIndex, Bytes32, ColumnIndex, CommitteeIndex, Epoch,
    ExecutionAddress, Gwei, Hash16, Hash32, KzgCommitment, KzgProof, ParticipationFlags, Root,
    Slot, ValidatorIndex, Version, WithdrawalIndex, XmssLeafIndex, XmssPublicKey,
};

use crate::{ApiJson, ApiJsonError, decimal::Decimal, reader::Reader};

/// Participation flags are a uint8, as every integer a decimal string.
///
/// Plain bytes have no impl: a list of them is a byte string, written as hex.
impl ApiJson for ParticipationFlags {
    fn to_json(&self) -> Json {
        Json::String(self.0.to_string())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        Reader::new(value).u8().map(Self)
    }
}

impl ApiJson for u64 {
    fn to_json(&self) -> Json {
        Json::String(self.to_string())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        Reader::new(value).u64()
    }
}

impl ApiJson for U256 {
    fn to_json(&self) -> Json {
        Json::String(Decimal::render_u256(*self))
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        Reader::new(value).u256()
    }
}

impl ApiJson for String {
    /// Free text, such as a status message or a graffiti string.
    fn to_json(&self) -> Json {
        Json::String(self.clone())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| ApiJsonError::wrong_type("a string", value))
    }
}

impl ApiJson for bool {
    fn to_json(&self) -> Json {
        Json::Bool(*self)
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        // The beacon API writes booleans as JSON literals, never as strings.
        value
            .as_bool()
            .ok_or_else(|| ApiJsonError::wrong_type("a boolean", value))
    }
}

impl<const N: usize> ApiJson for [u8; N] {
    /// Lowercase hex, two digits per byte.
    fn to_json(&self) -> Json {
        Json::String(self.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        Reader::new(value).hex_array()
    }
}

impl ApiJson for Slot {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        u64::from_json(value).map(Self)
    }
}

impl ApiJson for Epoch {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        u64::from_json(value).map(Self)
    }
}

impl ApiJson for Gwei {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        u64::from_json(value).map(Self)
    }
}

impl ApiJson for ValidatorIndex {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        u64::from_json(value).map(Self)
    }
}

impl ApiJson for BuilderIndex {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        u64::from_json(value).map(Self)
    }
}

impl ApiJson for CommitteeIndex {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        u64::from_json(value).map(Self)
    }
}

impl ApiJson for WithdrawalIndex {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        u64::from_json(value).map(Self)
    }
}

impl ApiJson for BlobIndex {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        u64::from_json(value).map(Self)
    }
}

impl ApiJson for ColumnIndex {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        u64::from_json(value).map(Self)
    }
}

impl ApiJson for XmssLeafIndex {
    /// A uint32, as every integer a decimal string.
    fn to_json(&self) -> Json {
        Json::String(self.0.to_string())
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        Reader::new(value).u32().map(Self)
    }
}

impl ApiJson for Hash16 {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        <[u8; 16]>::from_json(value).map(Self)
    }
}

impl ApiJson for XmssPublicKey {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        <[u8; 32]>::from_json(value).map(Self)
    }
}

impl ApiJson for Root {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        <[u8; 32]>::from_json(value).map(Self)
    }
}

impl ApiJson for Hash32 {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        <[u8; 32]>::from_json(value).map(Self)
    }
}

impl ApiJson for Bytes32 {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        <[u8; 32]>::from_json(value).map(Self)
    }
}

impl ApiJson for Version {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        <[u8; 4]>::from_json(value).map(Self)
    }
}

impl ApiJson for ExecutionAddress {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        <[u8; 20]>::from_json(value).map(Self)
    }
}

impl ApiJson for BlsPubkey {
    /// The compressed point as hex.
    ///
    /// Decoding checks only the length; the signature layer checks the point.
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        <[u8; 48]>::from_json(value).map(Self)
    }
}

impl ApiJson for BlsSignature {
    /// The compressed point as hex.
    ///
    /// Decoding checks only the length; the signature layer checks the point.
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        <[u8; 96]>::from_json(value).map(Self)
    }
}

impl ApiJson for KzgCommitment {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        <[u8; 48]>::from_json(value).map(Self)
    }
}

impl ApiJson for KzgProof {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        <[u8; 48]>::from_json(value).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use axiom_json::HexError;
    use proptest::prelude::*;

    use super::*;
    use crate::{ApiJsonErrorKind, DecimalError};

    /// The error of a decimal that breaks a rule, at the outermost value.
    fn decimal(error: DecimalError) -> ApiJsonError {
        ApiJsonError::new(ApiJsonErrorKind::Decimal(error))
    }

    #[test]
    fn u64_is_a_decimal_string() {
        // 1024 is "1024", and zero is "0".
        assert_eq!(1024_u64.to_json(), Json::from("1024"));
        assert_eq!(u64::from_json(&Json::from("1024")), Ok(1024));
        assert_eq!(u64::from_json(&Json::from("0")), Ok(0));

        // A JSON number is refused, even when it holds the same value.
        assert_eq!(
            u64::from_json(&Json::from(1024_u64)),
            Err(ApiJsonError::new(ApiJsonErrorKind::Type {
                expected: "a decimal string",
                found: "number"
            }))
        );

        // A sign, a leading zero, and 2^64 each break one rule.
        assert_eq!(
            u64::from_json(&Json::from("+1")),
            Err(decimal(DecimalError::InvalidDigit { offset: 0 }))
        );
        assert_eq!(
            u64::from_json(&Json::from("01")),
            Err(decimal(DecimalError::LeadingZero))
        );
        assert_eq!(
            u64::from_json(&Json::from("18446744073709551616")),
            Err(decimal(DecimalError::Overflow {
                digits: 20,
                max: "18446744073709551615"
            }))
        );
    }

    #[test]
    fn u256_is_a_decimal_string() {
        // 10^30 needs more than 64 bits and prints in full.
        let value = U256::from_u128(1_000_000_000_000_000_000_000_000_000_000);
        assert_eq!(
            value.to_json(),
            Json::from("1000000000000000000000000000000")
        );
        assert_eq!(U256::from_json(&value.to_json()), Ok(value));

        // Hex, the engine API's form, is refused at its x.
        assert_eq!(
            U256::from_json(&Json::from("0x1")),
            Err(decimal(DecimalError::InvalidDigit { offset: 1 }))
        );
    }

    #[test]
    fn newtypes_read_as_their_scalar() {
        // Slot 12 and epoch 3 are plain decimals.
        assert_eq!(Slot(12).to_json(), Json::from("12"));
        assert_eq!(Epoch::from_json(&Json::from("3")), Ok(Epoch(3)));

        // An empty string is no slot.
        assert_eq!(
            Slot::from_json(&Json::from("")),
            Err(decimal(DecimalError::Empty))
        );
    }

    #[test]
    fn bool_is_a_json_literal() {
        // True and false are literals, and the string "true" is refused.
        assert_eq!(true.to_json(), Json::Bool(true));
        assert_eq!(bool::from_json(&Json::Bool(false)), Ok(false));
        assert_eq!(
            bool::from_json(&Json::from("true")),
            Err(ApiJsonError::new(ApiJsonErrorKind::Type {
                expected: "a boolean",
                found: "string"
            }))
        );
    }

    #[test]
    fn fixed_bytes_are_hex_of_their_exact_length() {
        // A 4-byte version is 8 lowercase digits.
        assert_eq!(
            Version([0xde, 0xad, 0xbe, 0xef]).to_json(),
            Json::from("0xdeadbeef")
        );

        // Uppercase digits are accepted on input, as the API's pattern allows.
        assert_eq!(
            Version::from_json(&Json::from("0xDEADBEEF")),
            Ok(Version([0xde, 0xad, 0xbe, 0xef]))
        );

        // A 33-byte root is refused by its length.
        let long = Json::String([0; 33].to_data());
        assert_eq!(
            Root::from_json(&long),
            Err(ApiJsonError::new(ApiJsonErrorKind::WrongLength {
                expected: 32,
                actual: 33
            }))
        );

        // A missing prefix, an odd digit count, and a bad digit are hex errors.
        let hex = |error| Err(ApiJsonError::new(ApiJsonErrorKind::Hex(error)));
        assert_eq!(
            Version::from_json(&Json::from("deadbeef")),
            hex(HexError::MissingPrefix)
        );
        assert_eq!(
            Version::from_json(&Json::from("0xdeadbee")),
            hex(HexError::OddLength { digits: 7 })
        );
        assert_eq!(
            Version::from_json(&Json::from("0xdeadbeeg")),
            hex(HexError::InvalidDigit { offset: 9 })
        );
    }

    proptest! {
        #[test]
        fn scalars_round_trip(value in any::<u64>(), bytes in any::<[u8; 48]>()) {
            // Through the value and through its text.
            let json = Json::parse(Slot(value).to_json().to_string()).unwrap();
            prop_assert_eq!(Slot::from_json(&json), Ok(Slot(value)));
            let json = Json::parse(BlsPubkey(bytes).to_json().to_string()).unwrap();
            prop_assert_eq!(BlsPubkey::from_json(&json), Ok(BlsPubkey(bytes)));
        }
    }
}
