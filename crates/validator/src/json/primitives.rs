//! Integers, byte strings, bitfields, and lists in the beacon API's JSON form.

use axiom_json::{Data, Json};
use axiom_ssz::{
    BitList, BitVector, ByteList, Length, List, ProgressiveBitList, ProgressiveList, Ssz, U256,
};
use axiom_types::{
    BlsPubkey, BlsSignature, BuilderIndex, Bytes32, CommitteeIndex, Epoch, ExecutionAddress, Gwei,
    Hash32, KzgCommitment, KzgProof, Root, Slot, ValidatorIndex, Version,
};

use crate::json::{ApiJson, JsonError};

/// The string a value must be.
fn text(json: &Json) -> Result<&str, JsonError> {
    json.as_str()
        .ok_or_else(|| JsonError::mismatch("string", json))
}

/// The bytes of a hex string of a fixed length.
fn fixed<const N: usize>(json: &Json) -> Result<[u8; N], JsonError> {
    Ok(<[u8; N]>::from_data(text(json)?)?)
}

/// A value carried as the hex of its SSZ bytes, as bitfields are.
fn ssz_hex<T: Ssz>(json: &Json) -> Result<T, JsonError> {
    let bytes = Vec::<u8>::from_data(text(json)?)?;
    Ok(T::decode(&bytes)?)
}

impl ApiJson for u64 {
    fn to_json(&self) -> Json {
        Json::from(self.to_string())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let text = text(json)?;
        // Plain decimal digits only: no sign, no space, no empty string.
        let digits = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
        digits
            .then(|| text.parse().ok())
            .flatten()
            .ok_or_else(|| JsonError::Number {
                text: text.to_owned(),
                bits: 64,
            })
    }
}

impl ApiJson for U256 {
    fn to_json(&self) -> Json {
        Json::from(self.to_decimal())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let text = text(json)?;
        Self::from_decimal(text).ok_or_else(|| JsonError::Number {
            text: text.to_owned(),
            bits: 256,
        })
    }
}

impl ApiJson for bool {
    fn to_json(&self) -> Json {
        Json::Bool(*self)
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        json.as_bool()
            .ok_or_else(|| JsonError::mismatch("boolean", json))
    }
}

impl ApiJson for String {
    fn to_json(&self) -> Json {
        Json::from(self.as_str())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        text(json).map(str::to_owned)
    }
}

impl ApiJson for Slot {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        u64::from_json(json).map(Self)
    }
}

impl ApiJson for Epoch {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        u64::from_json(json).map(Self)
    }
}

impl ApiJson for ValidatorIndex {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        u64::from_json(json).map(Self)
    }
}

impl ApiJson for CommitteeIndex {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        u64::from_json(json).map(Self)
    }
}

impl ApiJson for BuilderIndex {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        u64::from_json(json).map(Self)
    }
}

impl ApiJson for Gwei {
    fn to_json(&self) -> Json {
        self.0.to_json()
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        u64::from_json(json).map(Self)
    }
}

impl ApiJson for Root {
    fn to_json(&self) -> Json {
        Json::from(self.0.to_data())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        fixed(json).map(Self)
    }
}

impl ApiJson for Bytes32 {
    fn to_json(&self) -> Json {
        Json::from(self.0.to_data())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        fixed(json).map(Self)
    }
}

impl ApiJson for Hash32 {
    fn to_json(&self) -> Json {
        Json::from(self.0.to_data())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        fixed(json).map(Self)
    }
}

impl ApiJson for BlsPubkey {
    fn to_json(&self) -> Json {
        Json::from(self.0.to_data())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        fixed(json).map(Self)
    }
}

impl ApiJson for BlsSignature {
    fn to_json(&self) -> Json {
        Json::from(self.0.to_data())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        fixed(json).map(Self)
    }
}

impl ApiJson for Version {
    fn to_json(&self) -> Json {
        Json::from(self.0.to_data())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        fixed(json).map(Self)
    }
}

impl ApiJson for ExecutionAddress {
    fn to_json(&self) -> Json {
        Json::from(self.0.to_data())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        fixed(json).map(Self)
    }
}

impl ApiJson for KzgCommitment {
    fn to_json(&self) -> Json {
        Json::from(self.0.to_data())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        fixed(json).map(Self)
    }
}

impl ApiJson for KzgProof {
    fn to_json(&self) -> Json {
        Json::from(self.0.to_data())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        fixed(json).map(Self)
    }
}

impl<N: Length> ApiJson for BitList<N> {
    fn to_json(&self) -> Json {
        Json::from(self.encode().to_data())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        ssz_hex(json)
    }
}

impl<N: Length> ApiJson for BitVector<N> {
    fn to_json(&self) -> Json {
        Json::from(self.encode().to_data())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        ssz_hex(json)
    }
}

impl ApiJson for ProgressiveBitList {
    fn to_json(&self) -> Json {
        Json::from(self.encode().to_data())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        ssz_hex(json)
    }
}

impl<N: Length> ApiJson for ByteList<N> {
    fn to_json(&self) -> Json {
        Json::from(self.to_data())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let bytes = Vec::<u8>::from_data(text(json)?)?;
        let len = bytes.len();
        Self::try_from(bytes).map_err(|_| JsonError::TooLong { len, max: N::LEN })
    }
}

impl<T: ApiJson> ApiJson for Vec<T> {
    fn to_json(&self) -> Json {
        Json::Array(self.iter().map(ApiJson::to_json).collect())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        let items = json
            .as_array()
            .ok_or_else(|| JsonError::mismatch("array", json))?;
        items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                T::from_json(item).map_err(|source| JsonError::Item {
                    index,
                    source: Box::new(source),
                })
            })
            .collect()
    }
}

impl<T: ApiJson, N: Length> ApiJson for List<T, N> {
    fn to_json(&self) -> Json {
        Json::Array(self.iter().map(ApiJson::to_json).collect())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        // Invariant: the bound is checked before any item decodes, so a huge array costs nothing.
        let len = json.as_array().map_or(0, <[Json]>::len);
        if len > N::LEN {
            return Err(JsonError::TooLong { len, max: N::LEN });
        }
        let items = Vec::<T>::from_json(json)?;
        Self::try_from(items).map_err(|_| JsonError::TooLong { len, max: N::LEN })
    }
}

impl<T: ApiJson> ApiJson for ProgressiveList<T> {
    fn to_json(&self) -> Json {
        Json::Array(self.iter().map(ApiJson::to_json).collect())
    }

    fn from_json(json: &Json) -> Result<Self, JsonError> {
        Vec::<T>::from_json(json).map(Self::from)
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Const;
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn integers_are_plain_decimal_strings() {
        // A sign, a space, an empty string, a JSON number, and 2^64 are all refused.
        for text in ["+1", " 1", "", "18446744073709551616"] {
            assert_eq!(
                u64::from_json(&Json::from(text)),
                Err(JsonError::Number {
                    text: text.to_owned(),
                    bits: 64,
                })
            );
        }
        assert_eq!(
            u64::from_json(&Json::from(7_u64)),
            Err(JsonError::Type {
                expected: "string",
                found: "number",
            })
        );
    }

    #[test]
    fn a_list_longer_than_its_bound_is_refused_before_decoding() {
        // Fixture state: a list bounded at 2 items, given 3 that are not even integers.
        let json = Json::Array(vec![Json::Null, Json::Null, Json::Null]);
        assert_eq!(
            List::<u64, Const<2>>::from_json(&json),
            Err(JsonError::TooLong { len: 3, max: 2 })
        );
    }

    proptest! {
        #[test]
        fn values_round_trip(
            value in any::<u64>(),
            root in any::<[u8; 32]>(),
            bits in prop::collection::vec(any::<bool>(), 0..40),
        ) {
            prop_assert_eq!(u64::from_json(&value.to_json()), Ok(value));
            prop_assert_eq!(Root::from_json(&Root(root).to_json()), Ok(Root(root)));
            let mut list = BitList::<Const<64>>::with_len(bits.len()).unwrap();
            for (index, bit) in bits.into_iter().enumerate() {
                list.set(index, bit);
            }
            prop_assert_eq!(BitList::from_json(&list.to_json()), Ok(list));
        }
    }
}
