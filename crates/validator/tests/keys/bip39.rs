//! The BIP-39 reference vectors of the English wordlist, under passphrase TREZOR.
//!
//! Each vector is a JSON array: entropy hex, mnemonic, seed hex, and a BIP-32 extended key.
//! The extended key belongs to BIP-32, which validator keys do not use, so it is not checked.

use std::fs;

use axiom_json::Json;
use axiom_validator::keys::Mnemonic;

use crate::vector_file;

/// English vectors in the pinned file.
const ENGLISH_VECTORS: usize = 24;

/// The passphrase every vector uses.
const PASSPHRASE: &str = "TREZOR";

/// Decodes a hex string of a vector.
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("vector hex"))
        .collect()
}

#[test]
fn english_vectors() {
    let Some(file) = vector_file("bip39/vectors.json") else {
        return;
    };
    let json =
        Json::parse(fs::read(file).expect("vectors are readable")).expect("vectors are JSON");
    let vectors = json
        .get("english")
        .and_then(Json::as_array)
        .expect("an english array");

    let mut checked = 0;
    for vector in vectors {
        let fields = vector.as_array().expect("a vector is an array");
        let text = |index: usize| fields[index].as_str().expect("vector fields are strings");
        let (entropy, phrase, seed) = (hex(text(0)), text(1), hex(text(2)));

        // Entropy to words.
        let written = Mnemonic::from_entropy(&entropy).expect("vector entropy has a valid length");
        assert_eq!(written.phrase(), phrase, "entropy {}", text(0));

        // Words back to entropy, checksum included.
        let parsed = Mnemonic::parse(phrase).expect("vector phrases parse");
        assert_eq!(parsed.entropy(), entropy, "phrase {phrase}");

        // Words and passphrase to seed.
        assert_eq!(
            parsed.to_seed(PASSPHRASE).as_bytes().to_vec(),
            seed,
            "phrase {phrase}"
        );
        checked += 1;
    }
    assert_eq!(checked, ENGLISH_VECTORS);
}
