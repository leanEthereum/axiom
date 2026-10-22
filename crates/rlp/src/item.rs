//! An owned RLP value of any shape: a byte string or a list of values.

use crate::{Decoder, Encoder, RlpError, header::Kind};

/// Deepest list nesting the generic decoder follows.
///
/// Every protocol here nests at most three lists deep.
/// The bound keeps hostile input from exhausting the stack.
const MAX_DEPTH: usize = 64;

/// One RLP value, owning its bytes.
///
/// Typed codecs read and write fields directly.
/// This tree serves inputs of unknown shape, such as test vectors.
///
/// # Examples
///
/// ```
/// use axiom_rlp::Item;
///
/// let item = Item::List(vec![Item::String(b"cat".to_vec()), Item::List(vec![])]);
/// let encoded = item.encode();
/// assert_eq!(encoded, [0xc5, 0x83, b'c', b'a', b't', 0xc0]);
/// assert_eq!(Item::decode(&encoded).unwrap(), item);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Item {
    /// A byte string.
    String(Vec<u8>),

    /// A list of values.
    List(Vec<Self>),
}

impl Item {
    /// The canonical encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        // One encoder carries the whole tree.
        let mut encoder = Encoder::new();
        self.encode_to(&mut encoder);
        encoder.finish()
    }

    /// Appends the canonical encoding to an encoder.
    pub fn encode_to(&self, encoder: &mut Encoder) {
        // Strings append directly; lists recurse inside their closure.
        match self {
            Self::String(bytes) => {
                encoder.bytes(bytes);
            }
            Self::List(items) => {
                encoder.list(|list| {
                    for item in items {
                        item.encode_to(list);
                    }
                });
            }
        }
    }

    /// Decodes an input that holds exactly one item.
    ///
    /// # Errors
    ///
    /// Fails on any non-canonical form, on trailing bytes, and past 64 levels of nesting.
    pub fn decode(input: &[u8]) -> Result<Self, RlpError> {
        // One item, then nothing.
        let mut decoder = Decoder::new(input);
        let item = Self::decode_next(&mut decoder, 0)?;
        decoder.finish()?;
        Ok(item)
    }

    /// Reads the next item of a decoder, at a given nesting depth.
    fn decode_next(decoder: &mut Decoder<'_>, depth: usize) -> Result<Self, RlpError> {
        // Threshold: refuse before recursing, so the stack stays bounded.
        if depth > MAX_DEPTH {
            return Err(RlpError::TooDeep { limit: MAX_DEPTH });
        }
        match decoder.peek_kind()? {
            Kind::String => Ok(Self::String(decoder.bytes()?.to_vec())),
            Kind::List => {
                let mut list = decoder.list()?;
                let mut items = Vec::new();
                while !list.is_empty() {
                    items.push(Self::decode_next(&mut list, depth + 1)?);
                }
                Ok(Self::List(items))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn wrap(item: &[u8]) -> Vec<u8> {
        // One more list level around an encoded item.
        let mut encoder = Encoder::new();
        encoder.list(|list| {
            list.raw(item);
        });
        encoder.finish()
    }

    #[test]
    fn nesting_is_bounded() {
        // 64 wraps put the innermost empty list at depth 64, the deepest allowed.
        let mut deep = vec![0xc0];
        for _ in 0..MAX_DEPTH {
            deep = wrap(&deep);
        }
        assert!(Item::decode(&deep).is_ok());
        // One more level crosses the bound.
        assert_eq!(
            Item::decode(&wrap(&deep)),
            Err(RlpError::TooDeep { limit: 64 })
        );
    }

    #[test]
    fn trailing_bytes_are_refused() {
        // 0x01 is a whole item; 0x02 after it is left over.
        assert_eq!(
            Item::decode(&[0x01, 0x02]),
            Err(RlpError::TrailingBytes { remaining: 1 })
        );
    }

    /// Arbitrary items: strings up to 80 bytes, lists up to 6 items, 4 levels deep.
    fn arb_item() -> impl Strategy<Value = Item> {
        let leaf = prop::collection::vec(any::<u8>(), 0..80).prop_map(Item::String);
        leaf.prop_recursive(4, 64, 6, |inner| {
            prop::collection::vec(inner, 0..6).prop_map(Item::List)
        })
    }

    proptest! {
        #[test]
        fn items_round_trip(item in arb_item()) {
            // Decoding an encoding returns the value.
            prop_assert_eq!(Item::decode(&item.encode()), Ok(item));
        }

        #[test]
        fn accepted_inputs_are_canonical(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            // Whatever decodes re-encodes to the same bytes, so the encoding is injective.
            if let Ok(item) = Item::decode(&bytes) {
                prop_assert_eq!(item.encode(), bytes);
            }
        }
    }
}
