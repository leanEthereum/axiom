//! Wycheproof ECDSA suites over NIST P-384, with SHA-384, SHA-256 and SHA-512.
//!
//! # Overview
//!
//! The crate verifies the 96-byte compact form r || s, which is the P1363 encoding.
//! The DER files pass through the strict DER reader of this suite first.
//! Verification accepts both halves of s, as plain ECDSA does, so no case needs a policy.
//!
//! The hash may be shorter or longer than the 384-bit order.
//! The SHA-256 and SHA-512 files pin the bits2int conversion of FIPS 186-4, section 6.4.

use axiom_crypto::p384::{PublicKey, Signature};
use axiom_json::Json;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::{
    der::DerReader,
    vectors::hex,
    wycheproof::{Case, Outcome, Tally, VectorFile},
};

/// How a file encodes its signatures.
#[derive(Clone, Copy, Debug)]
enum Encoding {
    /// IEEE P1363: r then s, each 48 bytes big-endian.
    P1363,
    /// The ASN.1 DER sequence of two integers.
    Der,
}

impl Encoding {
    /// The compact form of an encoded signature, none when the encoding is malformed.
    fn compact(self, signature: &[u8]) -> Option<[u8; 96]> {
        match self {
            Self::P1363 => signature.try_into().ok(),
            Self::Der => DerReader::ecdsa_signature(signature, 48)?.try_into().ok(),
        }
    }
}

/// Checks one signature case under the encoding of its file.
fn check(case: &Case<'_>, encoding: Encoding) -> Outcome {
    // Every group shares one public key, given in uncompressed SEC 1 form.
    let key = case
        .group_field("publicKey")
        .get("uncompressed")
        .and_then(Json::as_str)
        .and_then(hex)
        .expect("uncompressed public key");
    let key = PublicKey::from_sec1_bytes(&key).expect("every group key is on the curve");

    // The group names the hash; the message is hashed here.
    let message = case.hex("msg");
    let hash = match case.group_field("sha").as_str() {
        Some("SHA-256") => Sha256::digest(&message).to_vec(),
        Some("SHA-384") => Sha384::digest(&message).to_vec(),
        Some("SHA-512") => Sha512::digest(&message).to_vec(),
        other => panic!("tcId {}: unknown hash {other:?}", case.id),
    };

    // Decoding: a malformed encoding or a component outside [1, n) is rejected.
    let Some(compact) = encoding.compact(&case.hex("sig")) else {
        return Outcome::Rejected;
    };
    let Ok(signature) = Signature::from_bytes(&compact) else {
        return Outcome::Rejected;
    };
    match key.verify(&hash, &signature) {
        Ok(()) => Outcome::Accepted,
        Err(_) => Outcome::Rejected,
    }
}

#[test]
fn ecdsa_secp384r1_sha384_der() {
    let Some(file) = VectorFile::load("ecdsa_secp384r1_sha384_test.json") else {
        return;
    };
    let tally = file.run(|case| check(case, Encoding::Der));
    // 504 cases: 194 valid, high s included, and 310 invalid, BER and other DER defects among them.
    assert_eq!(
        tally,
        Tally {
            valid: 194,
            invalid: 310,
            ..Tally::default()
        }
    );
}

#[test]
fn ecdsa_secp384r1_sha384_p1363() {
    let Some(file) = VectorFile::load("ecdsa_secp384r1_sha384_p1363_test.json") else {
        return;
    };
    let tally = file.run(|case| check(case, Encoding::P1363));
    // 280 cases: 193 valid and 87 invalid.
    assert_eq!(
        tally,
        Tally {
            valid: 193,
            invalid: 87,
            ..Tally::default()
        }
    );
}

#[test]
fn ecdsa_secp384r1_sha256_der() {
    let Some(file) = VectorFile::load("ecdsa_secp384r1_sha256_test.json") else {
        return;
    };
    let tally = file.run(|case| check(case, Encoding::Der));
    // 472 cases: 162 valid and 310 invalid, with a 256-bit hash read whole.
    assert_eq!(
        tally,
        Tally {
            valid: 162,
            invalid: 310,
            ..Tally::default()
        }
    );
}

#[test]
fn ecdsa_secp384r1_sha512_der() {
    let Some(file) = VectorFile::load("ecdsa_secp384r1_sha512_test.json") else {
        return;
    };
    let tally = file.run(|case| check(case, Encoding::Der));
    // 542 cases: 231 valid and 311 invalid, with a 512-bit hash cut to its first 384 bits.
    assert_eq!(
        tally,
        Tally {
            valid: 231,
            invalid: 311,
            ..Tally::default()
        }
    );
}
