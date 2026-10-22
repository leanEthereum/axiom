//! Laws of the RLP codec: round-trips, canonicity, and total decoding.

use axiom_rlp::{Decoder, Encoder, Item};
use proptest::prelude::*;

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

    #[test]
    fn decoding_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        // Every typed read returns a value or an error.
        let _ = Item::decode(&bytes);
        let mut decoder = Decoder::new(&bytes);
        let _ = decoder.uint();
        let _ = Decoder::new(&bytes).u16();
        let _ = Decoder::new(&bytes).array::<32>();
        let _ = Decoder::new(&bytes).list().map(|mut list| list.raw());
    }

    #[test]
    fn integers_round_trip(value in any::<u64>()) {
        // The minimal big-endian form decodes back to the value.
        let mut encoder = Encoder::new();
        encoder.uint(value);
        let encoded = encoder.finish();
        let mut decoder = Decoder::new(&encoded);
        prop_assert_eq!(decoder.uint(), Ok(value));
        prop_assert!(decoder.finish().is_ok());
    }
}
