//! Wycheproof ECDH suites over secp256k1.
//!
//! # Overview
//!
//! The shared secret is the x-coordinate of d Q, per SEC 1, section 3.3.1.
//! The crate decodes SEC 1 points but not the containers these files wrap them in.
//!
//! - The ASN.1 file wraps the point in a SubjectPublicKeyInfo.
//!   Only the two canonical headers for secp256k1 are unwrapped here.
//!   Any other header is rejected by this reader: another curve, explicit parameters, or bad DER.
//! - The WebCrypto file gives a JWK, whose coordinates are joined into the uncompressed form.
//!
//! Point validation, the heart of invalid-curve attacks, is the crate's own.

use axiom_crypto::secp256k1::{PublicKey, SecretKey};
use axiom_json::Json;

use crate::{
    vectors::hex,
    wycheproof::{Case, Outcome, Tally, VectorFile},
};

/// The SubjectPublicKeyInfo header of an uncompressed secp256k1 point, per RFC 5480.
///
/// It is the DER of the id-ecPublicKey and secp256k1 identifiers, then a 66-byte BIT STRING.
const SPKI_UNCOMPRESSED: &str = "3056301006072a8648ce3d020106052b8104000a034200";

/// The SubjectPublicKeyInfo header of a compressed secp256k1 point.
const SPKI_COMPRESSED: &str = "3036301006072a8648ce3d020106052b8104000a032200";

/// Derives the shared x-coordinate and compares it with the published one.
fn agree(case: &Case<'_>, private: &[u8; 32], public: &[u8]) -> Outcome {
    let Ok(public) = PublicKey::from_sec1_bytes(public) else {
        return Outcome::Rejected;
    };
    let Ok(private) = SecretKey::from_bytes(private) else {
        return Outcome::Rejected;
    };
    let shared = private.diffie_hellman(&public).x_coordinate();
    if shared[..] == case.hex("shared")[..] {
        Outcome::Accepted
    } else {
        Outcome::WrongOutput(format!("computed {shared:02x?}"))
    }
}

/// Reads a private key written as a big-endian integer of any length, left-padded to 32 bytes.
fn private_key(integer: &[u8]) -> [u8; 32] {
    // The files write it as a signed integer, so a leading zero byte may precede 32 bytes.
    let start = integer
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(integer.len());
    let magnitude = &integer[start..];
    let mut key = [0_u8; 32];
    key[32 - magnitude.len()..].copy_from_slice(magnitude);
    key
}

/// Decodes unpadded base64url, per RFC 4648, section 5.
fn base64url(text: &str) -> Vec<u8> {
    // Each character carries 6 bits; whole bytes are emitted as they fill.
    let mut out = Vec::new();
    let mut buffer = 0_u32;
    let mut bits = 0;
    for character in text.bytes() {
        let value = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("not base64url: {text}"),
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

#[test]
fn ecdh_secp256k1_asn() {
    let Some(file) = VectorFile::load("ecdh_secp256k1_test.json") else {
        return;
    };
    let tally = file.run(|case| {
        let private = private_key(&case.hex("private"));
        let public = case.str("public");
        // Unwrap the canonical headers, and reject every other container.
        let point = [SPKI_UNCOMPRESSED, SPKI_COMPRESSED]
            .iter()
            .find_map(|header| public.strip_prefix(header));
        match point.and_then(hex) {
            Some(point) => agree(case, &private, &point),
            None => Outcome::Rejected,
        }
    });
    // 752 cases: 473 valid, 49 invalid, and 230 acceptable.
    // The one acceptable case accepted is the compressed point.
    // The other 229 are alternative or broken ASN.1 encodings, refused by the strict reader.
    assert_eq!(
        tally,
        Tally {
            valid: 473,
            invalid: 49,
            acceptable_accepted: 1,
            acceptable_rejected: 229,
            ..Tally::default()
        }
    );
}

#[test]
fn ecdh_secp256k1_webcrypto() {
    let Some(file) = VectorFile::load("ecdh_secp256k1_webcrypto_test.json") else {
        return;
    };
    let tally = file.run(|case| {
        let public = case.field("public");
        let member = |name: &str| public.get(name).and_then(Json::as_str);
        // A key for another curve is rejected before any point arithmetic.
        if member("kty") != Some("EC") || member("crv") != Some("P-256K") {
            return Outcome::Rejected;
        }
        let x = base64url(member("x").expect("x coordinate"));
        let y = base64url(member("y").expect("y coordinate"));
        if x.len() != 32 || y.len() != 32 {
            return Outcome::Rejected;
        }
        let point = [&[0x04][..], &x, &y].concat();

        let d = case
            .field("private")
            .get("d")
            .and_then(Json::as_str)
            .expect("private scalar");
        agree(case, &private_key(&base64url(d)), &point)
    });
    // 496 cases: 473 valid and 23 invalid, invalid-curve points among them.
    assert_eq!(
        tally,
        Tally {
            valid: 473,
            invalid: 23,
            ..Tally::default()
        }
    );
}
