//! Wycheproof ECDH suites over secp256k1 and NIST P-256.
//!
//! # Overview
//!
//! The shared secret is the x-coordinate of d Q, per SEC 1, section 3.3.1.
//! The crate decodes SEC 1 points but not the containers these files wrap them in.
//!
//! - The ASN.1 files wrap the point in a SubjectPublicKeyInfo.
//!   Only the two canonical headers for the file's curve are unwrapped here.
//!   Any other header is rejected by this reader: another curve, explicit parameters, or bad DER.
//! - The ecpoint file gives the bare SEC 1 point, compressed or not.
//! - The WebCrypto file gives a JWK, whose coordinates are joined into the uncompressed form.
//!
//! Point validation, the heart of invalid-curve attacks, is the crate's own.

use axiom_crypto::{p256, secp256k1};
use axiom_json::Json;

use crate::{
    vectors::hex,
    wycheproof::{Case, Outcome, Tally, VectorFile},
};

/// The SubjectPublicKeyInfo headers of secp256k1 points, uncompressed then compressed, per RFC 5480.
///
/// Each is the DER of the id-ecPublicKey and secp256k1 identifiers, then a BIT STRING header.
const SECP256K1_SPKI: [&str; 2] = [
    "3056301006072a8648ce3d020106052b8104000a034200",
    "3036301006072a8648ce3d020106052b8104000a032200",
];

/// The SubjectPublicKeyInfo headers of P-256 points, uncompressed then compressed, per RFC 5480.
///
/// Each is the DER of the id-ecPublicKey and prime256v1 identifiers, then a BIT STRING header.
const P256_SPKI: [&str; 2] = [
    "3059301306072a8648ce3d020106082a8648ce3d030107034200",
    "3039301306072a8648ce3d020106082a8648ce3d030107032200",
];

/// The curve a file exercises.
#[derive(Clone, Copy, Debug)]
enum Curve {
    /// secp256k1, the curve of discv5.
    Secp256k1,
    /// NIST P-256, the secp256r1 group of TLS.
    P256,
}

impl Curve {
    /// The shared x-coordinate, or none when either key is refused.
    fn agree(self, private: &[u8; 32], public: &[u8]) -> Option<[u8; 32]> {
        match self {
            Self::Secp256k1 => {
                let public = secp256k1::PublicKey::from_sec1_bytes(public).ok()?;
                let private = secp256k1::SecretKey::from_bytes(private).ok()?;
                Some(private.diffie_hellman(&public).x_coordinate())
            }
            Self::P256 => {
                let public = p256::PublicKey::from_sec1_bytes(public).ok()?;
                let private = p256::SecretKey::from_bytes(private).ok()?;
                Some(private.diffie_hellman(&public).x_coordinate())
            }
        }
    }

    /// Derives the shared x-coordinate and compares it with the published one.
    fn check(self, case: &Case<'_>, private: &[u8; 32], public: &[u8]) -> Outcome {
        match self.agree(private, public) {
            None => Outcome::Rejected,
            Some(shared) if shared[..] == case.hex("shared")[..] => Outcome::Accepted,
            Some(shared) => Outcome::WrongOutput(format!("computed {shared:02x?}")),
        }
    }

    /// Checks a case whose public key sits in a SubjectPublicKeyInfo.
    fn check_asn(self, case: &Case<'_>) -> Outcome {
        let private = private_key(&case.hex("private"));
        let headers = match self {
            Self::Secp256k1 => SECP256K1_SPKI,
            Self::P256 => P256_SPKI,
        };
        // Unwrap the canonical headers, and reject every other container.
        let public = case.str("public");
        let point = headers
            .iter()
            .find_map(|header| public.strip_prefix(header));
        match point.and_then(hex) {
            Some(point) => self.check(case, &private, &point),
            None => Outcome::Rejected,
        }
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
    let tally = file.run(|case| Curve::Secp256k1.check_asn(case));
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
        Curve::Secp256k1.check(case, &private_key(&base64url(d)), &point)
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

#[test]
fn ecdh_secp256r1_asn() {
    let Some(file) = VectorFile::load("ecdh_secp256r1_test.json") else {
        return;
    };
    let tally = file.run(|case| Curve::P256.check_asn(case));
    // 612 cases: 330 valid, 52 invalid, and 230 acceptable.
    // The one acceptable case accepted is the compressed point.
    // The other 229 are alternative ASN.1 encodings or explicit curve parameters.
    // The strict reader refuses them all, so no explicit parameters ever reach the crate.
    assert_eq!(
        tally,
        Tally {
            valid: 330,
            invalid: 52,
            acceptable_accepted: 1,
            acceptable_rejected: 229,
            ..Tally::default()
        }
    );
}

#[test]
fn ecdh_secp256r1_ecpoint() {
    let Some(file) = VectorFile::load("ecdh_secp256r1_ecpoint_test.json") else {
        return;
    };
    // The bare SEC 1 point goes straight to the decoder.
    let tally = file.run(|case| {
        let private = private_key(&case.hex("private"));
        Curve::P256.check(case, &private, &case.hex("public"))
    });
    // 355 cases: 330 valid, 24 invalid, and the acceptable compressed point, accepted.
    // The invalid ones are invalid-curve points, wrong-curve points, and bad encodings.
    assert_eq!(
        tally,
        Tally {
            valid: 330,
            invalid: 24,
            acceptable_accepted: 1,
            ..Tally::default()
        }
    );
}
