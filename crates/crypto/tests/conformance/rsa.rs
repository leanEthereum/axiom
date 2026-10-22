//! Wycheproof RSA suites: PKCS #1 v1.5 verification and signing, and PSS verification.
//!
//! # Overview
//!
//! The crate takes raw big-endian integers, so this suite unwraps the containers.
//!
//! - Verification groups give the modulus and exponent as hex.
//! - Signing groups give a PKCS #8 private key, read here by the strict DER reader.
//!
//! PKCS #1 v1.5 signing is deterministic, so a valid signing case must reproduce the published bytes.
//! The crate offers SHA-256, SHA-384 and SHA-512, with MGF1 over the same hash for PSS.
//! A case naming any other hash, or a different MGF1 hash, counts as unsupported.

use axiom_crypto::rsa::{RsaHash, RsaPrivateKey, RsaPublicKey};
use axiom_json::Json;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::{
    der::DerReader,
    vectors::hex,
    wycheproof::{Case, Outcome, Tally, VectorFile},
};

/// The reason recorded for a hash the API cannot express.
const UNSUPPORTED_HASH: &str = "hash outside SHA-256, SHA-384 and SHA-512";

/// The reason recorded for a PSS mask generation the API cannot express.
const UNSUPPORTED_MGF: &str = "MGF1 over a hash other than the message hash";

/// The hash a Wycheproof name stands for, none when the API cannot express it.
fn rsa_hash(name: Option<&str>) -> Option<RsaHash> {
    match name {
        Some("SHA-256") => Some(RsaHash::Sha256),
        Some("SHA-384") => Some(RsaHash::Sha384),
        Some("SHA-512") => Some(RsaHash::Sha512),
        _ => None,
    }
}

/// The digest of a message under a hash.
fn digest(hash: RsaHash, message: &[u8]) -> Vec<u8> {
    match hash {
        RsaHash::Sha256 => Sha256::digest(message).to_vec(),
        RsaHash::Sha384 => Sha384::digest(message).to_vec(),
        RsaHash::Sha512 => Sha512::digest(message).to_vec(),
    }
}

/// The group's public key, from the hex modulus and exponent.
fn public_key(case: &Case<'_>) -> Option<RsaPublicKey> {
    let key = case.group_field("publicKey");
    let field = |name: &str| key.get(name).and_then(Json::as_str).and_then(hex);
    RsaPublicKey::new(&field("modulus")?, &field("publicExponent")?).ok()
}

/// Reads the RSAPrivateKey inside a PKCS #8 PrivateKeyInfo, per RFC 5208 and RFC 8017, appendix A.1.2.
///
/// Returns the eight integers n, e, d, p, q, dp, dq, qinv, or none on any defect.
fn pkcs8_components(der: &[u8]) -> Option<Vec<&[u8]>> {
    // PrivateKeyInfo: version, algorithm identifier, then the key as an OCTET STRING.
    let mut outer = DerReader::new(der);
    let mut info = outer.sequence()?;
    if !outer.is_empty() || info.integer()? != [0] {
        return None;
    }
    info.sequence()?;
    let key = info.element(0x04)?;

    // RSAPrivateKey: version 0, then the eight integers in order.
    let mut wrapper = DerReader::new(key);
    let mut fields = wrapper.sequence()?;
    if !wrapper.is_empty() || fields.integer()? != [0] {
        return None;
    }
    let components = (0..8)
        .map(|_| fields.integer())
        .collect::<Option<Vec<_>>>()?;
    fields.is_empty().then_some(components)
}

/// Checks one PKCS #1 v1.5 verification case.
fn check_pkcs1_verify(case: &Case<'_>) -> Outcome {
    let Some(hash) = rsa_hash(case.group_field("sha").as_str()) else {
        return Outcome::Unsupported(UNSUPPORTED_HASH);
    };
    let Some(key) = public_key(case) else {
        return Outcome::Rejected;
    };
    match key.verify_pkcs1v15(hash, &digest(hash, &case.hex("msg")), &case.hex("sig")) {
        Ok(()) => Outcome::Accepted,
        Err(_) => Outcome::Rejected,
    }
}

/// Checks one PKCS #1 v1.5 signing case: the fresh signature must equal the published one.
fn check_pkcs1_sign(case: &Case<'_>) -> Outcome {
    let Some(hash) = rsa_hash(case.group_field("sha").as_str()) else {
        return Outcome::Unsupported(UNSUPPORTED_HASH);
    };
    let der = case
        .group_field("privateKeyPkcs8")
        .as_str()
        .and_then(hex)
        .expect("PKCS #8 private key");
    let parts = pkcs8_components(&der).expect("well-formed PKCS #8 key");
    let Ok(key) = RsaPrivateKey::from_components(
        parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7],
    ) else {
        return Outcome::Rejected;
    };
    match key.sign_pkcs1v15(hash, &digest(hash, &case.hex("msg"))) {
        Ok(signature) if signature == case.hex("sig") => Outcome::Accepted,
        Ok(signature) => Outcome::WrongOutput(format!("computed {signature:02x?}")),
        Err(_) => Outcome::Rejected,
    }
}

/// Checks one PSS verification case with the group's hash, MGF1 hash and salt length.
fn check_pss_verify(case: &Case<'_>) -> Outcome {
    let Some(hash) = rsa_hash(case.group_field("sha").as_str()) else {
        return Outcome::Unsupported(UNSUPPORTED_HASH);
    };
    let mgf = case.group_field("mgf").as_str();
    let mgf_hash = rsa_hash(case.group_field("mgfSha").as_str());
    if mgf != Some("MGF1") || mgf_hash != Some(hash) {
        return Outcome::Unsupported(UNSUPPORTED_MGF);
    }
    let salt_len = case.group_field("sLen").as_u64().expect("salt length");
    let Some(key) = public_key(case) else {
        return Outcome::Rejected;
    };
    let digest = digest(hash, &case.hex("msg"));
    match key.verify_pss(hash, &digest, &case.hex("sig"), salt_len as usize) {
        Ok(()) => Outcome::Accepted,
        Err(_) => Outcome::Rejected,
    }
}

/// Runs every file through a check and asserts its tally.
fn run_all(expected: &[(&str, Tally)], check: fn(&Case<'_>) -> Outcome) {
    for (name, tally) in expected {
        let Some(file) = VectorFile::load(name) else {
            return;
        };
        assert_eq!(&file.run(check), tally, "{name}");
    }
}

/// The tally of a PKCS #1 v1.5 verification file.
///
/// Every file has one acceptable case: a DigestInfo without its NULL parameters.
/// Comparing whole encoded blocks rejects it, which RFC 8017, section 9.2, note 2, allows.
fn verify_tally(valid: usize, invalid: usize) -> Tally {
    Tally {
        valid,
        invalid,
        acceptable_rejected: 1,
        ..Tally::default()
    }
}

/// The tally of a PSS verification file, whose cases are all valid or invalid.
fn pss_tally(valid: usize, invalid: usize) -> Tally {
    Tally {
        valid,
        invalid,
        ..Tally::default()
    }
}

#[test]
fn rsa_pkcs1_verify() {
    // About 250 invalid cases per file: forged padding, wrong hashes, and malleated signatures.
    let expected = [
        ("rsa_signature_2048_sha256_test.json", verify_tally(9, 249)),
        ("rsa_signature_2048_sha384_test.json", verify_tally(7, 250)),
        ("rsa_signature_2048_sha512_test.json", verify_tally(8, 250)),
        ("rsa_signature_3072_sha256_test.json", verify_tally(8, 250)),
        ("rsa_signature_3072_sha384_test.json", verify_tally(7, 251)),
        ("rsa_signature_3072_sha512_test.json", verify_tally(8, 251)),
        ("rsa_signature_4096_sha256_test.json", verify_tally(7, 250)),
        ("rsa_signature_4096_sha384_test.json", verify_tally(7, 251)),
        ("rsa_signature_4096_sha512_test.json", verify_tally(7, 251)),
        ("rsa_signature_8192_sha256_test.json", verify_tally(7, 250)),
        ("rsa_signature_8192_sha384_test.json", verify_tally(7, 251)),
        ("rsa_signature_8192_sha512_test.json", verify_tally(7, 251)),
    ];
    run_all(&expected, check_pkcs1_verify);
}

#[test]
fn rsa_pkcs1_sign() {
    // Every supported case reproduces the published signature byte for byte.
    // The acceptable ones use e = 3, flagged SmallPublicKey, and are signed all the same.
    // The 2048-bit file also has 8 SHA-1 and 8 SHA-224 cases, which the API cannot name.
    let expected = [
        (
            "rsa_pkcs1_2048_sig_gen_test.json",
            Tally {
                valid: 24,
                acceptable_accepted: 3,
                unsupported: 16,
                ..Tally::default()
            },
        ),
        (
            "rsa_pkcs1_3072_sig_gen_test.json",
            Tally {
                valid: 24,
                acceptable_accepted: 2,
                ..Tally::default()
            },
        ),
        (
            "rsa_pkcs1_4096_sig_gen_test.json",
            Tally {
                valid: 24,
                ..Tally::default()
            },
        ),
    ];
    run_all(&expected, check_pkcs1_sign);
}

#[test]
fn rsa_pss_verify() {
    // The misc file crosses five hashes with five MGF1 hashes and six salt lengths.
    // Of its 150 cases, 18 pair a supported hash with the same MGF1 hash.
    // The other 132 name SHA-1 or SHA-224, or a different MGF1 hash.
    let expected = [
        ("rsa_pss_2048_sha256_mgf1_0_test.json", pss_tally(61, 42)),
        ("rsa_pss_2048_sha256_mgf1_32_test.json", pss_tally(63, 45)),
        ("rsa_pss_2048_sha384_mgf1_48_test.json", pss_tally(95, 46)),
        ("rsa_pss_3072_sha256_mgf1_32_test.json", pss_tally(63, 45)),
        ("rsa_pss_4096_sha256_mgf1_32_test.json", pss_tally(63, 45)),
        ("rsa_pss_4096_sha384_mgf1_48_test.json", pss_tally(95, 46)),
        ("rsa_pss_4096_sha512_mgf1_32_test.json", pss_tally(132, 45)),
        ("rsa_pss_4096_sha512_mgf1_64_test.json", pss_tally(132, 47)),
        (
            "rsa_pss_misc_test.json",
            Tally {
                valid: 18,
                unsupported: 132,
                ..Tally::default()
            },
        ),
    ];
    run_all(&expected, check_pss_verify);
}
