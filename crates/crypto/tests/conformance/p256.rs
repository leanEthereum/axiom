//! Wycheproof ECDSA suite over NIST P-256 with SHA-256, in the P1363 encoding.
//!
//! The crate verifies the 64-byte compact form r || s, which is exactly the P1363 encoding.
//! A signature of any other length is malformed in this encoding and is rejected before decoding.
//! Verification accepts both halves of s, as plain ECDSA does, so no case needs a policy.

use axiom_crypto::p256::{PublicKey, Signature};
use axiom_json::Json;
use sha2::{Digest, Sha256};

use crate::{
    vectors::hex,
    wycheproof::{Case, Outcome, Tally, VectorFile},
};

/// Checks one signature case.
fn check(case: &Case<'_>) -> Outcome {
    // Every group shares one public key, given in uncompressed SEC 1 form.
    let key = case
        .group_field("publicKey")
        .get("uncompressed")
        .and_then(Json::as_str)
        .and_then(hex)
        .expect("uncompressed public key");
    let key = PublicKey::from_sec1_bytes(&key).expect("every group key is on the curve");
    let hash: [u8; 32] = Sha256::digest(case.hex("msg")).into();

    // Decoding: a wrong length or a component outside [1, n) is rejected.
    let Ok(compact) = <[u8; 64]>::try_from(case.hex("sig")) else {
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
fn ecdsa_secp256r1_sha256_p1363() {
    let Some(file) = VectorFile::load("ecdsa_secp256r1_sha256_p1363_test.json") else {
        return;
    };
    let tally = file.run(check);
    // 262 cases: 173 valid, high s included, and 89 invalid.
    assert_eq!(
        tally,
        Tally {
            valid: 173,
            invalid: 89,
            ..Tally::default()
        }
    );
}
