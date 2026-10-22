//! Wycheproof ECDSA suites over secp256k1 with SHA-256.
//!
//! # Overview
//!
//! The crate verifies the 64-byte compact form r || s, which is the P1363 encoding.
//! It has no DER decoder, so the strict DER reader of this suite turns the ASN.1 files into compact form.
//! Encoding defects in those files are therefore caught by this reader, not by the crate.
//!
//! # Low s
//!
//! Verification is strict: s above n / 2 is refused, per EIP-2 and BIP 62.
//! Wycheproof's generic files mark such signatures valid, since plain ECDSA accepts them.
//! A valid high-s case counts as refused only when its normalized form verifies.
//! The Bitcoin file marks them invalid, with the SignatureMalleabilityBitcoin flag, matching the crate.

use axiom_crypto::secp256k1::{PublicKey, Secp256k1Error, Signature};
use axiom_json::Json;
use sha2::{Digest, Sha256};

use crate::{
    der::DerReader,
    vectors::hex,
    wycheproof::{Case, Outcome, Tally, VectorFile},
};

/// How a file encodes its signatures.
#[derive(Clone, Copy, Debug)]
enum Encoding {
    /// IEEE P1363: r then s, each 32 bytes big-endian.
    P1363,
    /// The ASN.1 DER sequence of two integers.
    Der,
}

impl Encoding {
    /// The compact form of an encoded signature, none when the encoding is malformed.
    fn compact(self, signature: &[u8]) -> Option<[u8; 64]> {
        match self {
            Self::P1363 => signature.try_into().ok(),
            Self::Der => DerReader::ecdsa_signature(signature, 32)?.try_into().ok(),
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
    let hash: [u8; 32] = Sha256::digest(case.hex("msg")).into();

    // Decoding: a malformed encoding or a component outside [1, n) is rejected.
    let Some(compact) = encoding.compact(&case.hex("sig")) else {
        return Outcome::Rejected;
    };
    let Ok(signature) = Signature::from_bytes(&compact) else {
        return Outcome::Rejected;
    };

    match key.verify(&hash, &signature) {
        Ok(()) => Outcome::Accepted,
        // The refusal is the low-s policy alone exactly when the normalized form verifies.
        Err(Secp256k1Error::HighS) if key.verify(&hash, &signature.normalize_s()).is_ok() => {
            Outcome::Refused("high s, normalized form verifies")
        }
        Err(_) => Outcome::Rejected,
    }
}

#[test]
fn ecdsa_secp256k1_sha256_p1363() {
    let Some(file) = VectorFile::load("ecdsa_secp256k1_sha256_p1363_test.json") else {
        return;
    };
    let tally = file.run(|case| check(case, Encoding::P1363));
    // 252 cases: 167 valid, of which 72 have a high s, and 85 invalid.
    assert_eq!(
        tally,
        Tally {
            valid: 95,
            invalid: 85,
            refused: 72,
            ..Tally::default()
        }
    );
}

#[test]
fn ecdsa_secp256k1_sha256_der() {
    let Some(file) = VectorFile::load("ecdsa_secp256k1_sha256_test.json") else {
        return;
    };
    let tally = file.run(|case| check(case, Encoding::Der));
    // 476 cases: 168 valid, of which 72 have a high s, and 308 invalid.
    assert_eq!(
        tally,
        Tally {
            valid: 96,
            invalid: 308,
            refused: 72,
            ..Tally::default()
        }
    );
}

#[test]
fn ecdsa_secp256k1_sha256_bitcoin() {
    let Some(file) = VectorFile::load("ecdsa_secp256k1_sha256_bitcoin_test.json") else {
        return;
    };
    // The Bitcoin profile requires low s, as the crate does, so no case needs the policy.
    let tally = file.run(|case| check(case, Encoding::Der));
    assert_eq!(
        tally,
        Tally {
            valid: 162,
            invalid: 302,
            ..Tally::default()
        }
    );
}
