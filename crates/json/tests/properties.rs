//! Laws of the parser, the serializer, and the hex encodings, checked on random input.

use axiom_json::{Data, Json, Limits, Number, Object, Quantity};
use axiom_ssz::U256;
use proptest::prelude::*;

/// Any number the grammar allows, built from its four optional parts.
fn number() -> impl Strategy<Value = Number> {
    (
        any::<bool>(),
        prop_oneof![Just("0".to_owned()), "[1-9][0-9]{0,30}"],
        proptest::option::of("[0-9]{1,10}"),
        proptest::option::of(("[eE]", "[+-]?", "[0-9]{1,4}")),
    )
        .prop_map(|(negative, int, frac, exp)| {
            // Assemble sign, integer, fraction, and exponent in grammar order.
            let mut text = String::new();
            if negative {
                text.push('-');
            }
            text.push_str(&int);
            if let Some(frac) = frac {
                text.push('.');
                text.push_str(&frac);
            }
            if let Some((e, sign, digits)) = exp {
                text.push_str(&e);
                text.push_str(&sign);
                text.push_str(&digits);
            }
            text.parse().expect("assembled from the grammar")
        })
}

/// Any value up to a few levels deep, including every control character and astral planes.
fn json() -> impl Strategy<Value = Json> {
    let leaf = prop_oneof![
        Just(Json::Null),
        any::<bool>().prop_map(Json::Bool),
        number().prop_map(Json::Number),
        any::<String>().prop_map(Json::String),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..8).prop_map(Json::Array),
            // Names may collide in the generator; collecting keeps them unique.
            proptest::collection::vec((any::<String>(), inner), 0..8)
                .prop_map(|members| Json::Object(members.into_iter().collect::<Object>())),
        ]
    })
}

/// Inserts whitespace between every token of a compact text.
///
/// Whitespace inside strings must stay put, so the walk tracks whether it is inside one.
fn spread(compact: &str, pad: &str) -> String {
    let mut out = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for c in compact.chars() {
        out.push(c);
        if in_string {
            // Track escapes so an escaped quote does not end the string.
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
        } else if c == '"' {
            in_string = true;
        } else if matches!(c, '[' | ']' | '{' | '}' | ',' | ':') {
            out.push_str(pad);
        }
    }
    out
}

proptest! {
    #[test]
    fn serialize_then_parse_is_identity(value in json()) {
        // Writing a value and reading it back yields the same value.
        let text = value.to_string();
        prop_assert_eq!(Json::parse(&text), Ok(value));
    }

    #[test]
    fn parse_then_serialize_is_idempotent(value in json(), pad in "[ \t\n\r]{0,3}") {
        // A padded text parses to the same value, and writes back to the compact form.
        let compact = value.to_string();
        let padded = format!("{pad}{}{pad}", spread(&compact, &pad));
        let parsed = Json::parse(&padded).unwrap();
        prop_assert_eq!(parsed.to_string(), compact);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        // Any outcome is fine; an error must point inside the input or at its end.
        if let Err(error) = Json::parse(&bytes) {
            prop_assert!(error.offset() <= bytes.len());
        }
    }

    #[test]
    fn json_alphabet_never_panics(text in "[\\[\\]{}\",:0-9eE.+\\-a-z\\\\ ]{0,64}") {
        // Bytes drawn from the JSON alphabet reach far deeper into the grammar than noise.
        let limits = Limits { max_depth: 4, max_bytes: 64 };
        if let Err(error) = Json::parse_with(&text, limits) {
            prop_assert!(error.offset() <= text.len());
        }
    }

    #[test]
    fn truncation_is_always_rejected(value in json(), cut in any::<prop::sample::Index>()) {
        // Cutting a container's compact text short always fails.
        // A scalar may survive, as "12" cut to "1" is still a number.
        let text = value.to_string();
        if matches!(value, Json::Array(_) | Json::Object(_)) {
            let end = cut.index(text.len());
            if text.is_char_boundary(end) {
                prop_assert!(Json::parse(&text[..end]).is_err());
            }
        }
    }

    #[test]
    fn quantity_u64_round_trip(value in any::<u64>()) {
        // The minimal form decodes back and carries no leading zero.
        let text = value.to_quantity();
        prop_assert!(value == 0 || !text.starts_with("0x0"));
        prop_assert_eq!(u64::from_quantity(&text), Ok(value));
    }

    #[test]
    fn quantity_u256_round_trip(bytes in any::<[u8; 32]>()) {
        // Same law over 256 bits.
        let value = U256(bytes);
        prop_assert_eq!(U256::from_quantity(&value.to_quantity()), Ok(value));
    }

    #[test]
    fn quantity_widths_agree(value in any::<u64>()) {
        // A 64-bit value has the same text whether read as 64 or 256 bits.
        prop_assert_eq!(U256::from_u64(value).to_quantity(), value.to_quantity());
    }

    #[test]
    fn data_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        // Every byte string encodes to 2 + 2n characters and decodes back.
        let text = bytes.to_data();
        prop_assert_eq!(text.len(), 2 + 2 * bytes.len());
        prop_assert_eq!(Vec::<u8>::from_data(&text), Ok(bytes));
    }

    #[test]
    fn hex_decoders_never_panic(text in "(0x)?[0-9a-fA-Fg-z]{0,70}") {
        // Only the outcome's existence matters here.
        let _ = u64::from_quantity(&text);
        let _ = U256::from_quantity(&text);
        let _ = Vec::<u8>::from_data(&text);
        let _ = <[u8; 32]>::from_data(&text);
    }
}
