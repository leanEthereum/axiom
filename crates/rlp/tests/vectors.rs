//! The RLPTests of ethereum/tests: valid encodings and invalid inputs.
//!
//! Source: `ethereum/tests`, branch `develop`, files `RLPTests/rlptest.json` and `RLPTests/invalidRLPTest.json`.

use axiom_json::Json;
use axiom_rlp::Item;

/// Converts a decimal string to minimal big-endian bytes.
fn decimal_to_bytes(digits: &str) -> Vec<u8> {
    // Schoolbook: multiply the big-endian accumulator by ten and add each digit.
    let mut bytes: Vec<u8> = Vec::new();
    for digit in digits.bytes() {
        let mut carry = u32::from(digit - b'0');
        for byte in bytes.iter_mut().rev() {
            let value = u32::from(*byte) * 10 + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    bytes
}

/// The item a vector's input describes.
fn expected_item(input: &Json) -> Item {
    match input {
        // A leading # marks a big integer in decimal.
        Json::String(text) => match text.strip_prefix('#') {
            Some(digits) => Item::String(decimal_to_bytes(digits)),
            None => Item::String(text.as_bytes().to_vec()),
        },
        // Integers are minimal big-endian strings.
        Json::Number(_) => {
            let value = input.as_u64().expect("integer inputs fit 64 bits");
            Item::String(decimal_to_bytes(&value.to_string()))
        }
        Json::Array(items) => Item::List(items.iter().map(expected_item).collect()),
        other => panic!("unexpected input kind {}", other.kind()),
    }
}

/// Decodes a hex string, with or without its 0x prefix.
fn hex(text: &str) -> Vec<u8> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

#[test]
fn valid_vectors_encode_and_decode() {
    let document = Json::parse(include_str!("vectors/rlptest.json")).expect("valid JSON");
    let cases = document.as_object().expect("an object of cases");
    let mut count = 0;
    for (name, case) in cases {
        let item = expected_item(case.get("in").expect("input"));
        let out = hex(case.get("out").and_then(Json::as_str).expect("output"));
        // Encoding the described value gives the expected bytes.
        assert_eq!(item.encode(), out, "{name}: encoding");
        // Decoding the bytes gives the described value back.
        assert_eq!(Item::decode(&out).as_ref(), Ok(&item), "{name}: decoding");
        count += 1;
    }
    // The file holds 28 cases.
    assert_eq!(count, 28);
}

#[test]
fn invalid_vectors_are_refused() {
    let document = Json::parse(include_str!("vectors/invalidRLPTest.json")).expect("valid JSON");
    let cases = document.as_object().expect("an object of cases");
    let mut count = 0;
    for (name, case) in cases {
        let out = hex(case.get("out").and_then(Json::as_str).expect("output"));
        // Every input breaks a rule, so the strict decoder refuses it.
        assert!(Item::decode(&out).is_err(), "{name}: accepted");
        count += 1;
    }
    // The file holds 26 cases.
    assert_eq!(count, 26);
}
