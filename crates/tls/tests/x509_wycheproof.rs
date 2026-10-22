//! Wycheproof signature suites through the certificate layer: SubjectPublicKeyInfo, then verify.
//!
//! Each group gives its key as a DER SubjectPublicKeyInfo, as a certificate carries it.
//! Each signature then goes through the same dispatch a certificate signature takes.
//! This pins the key decoders, the DER ECDSA reader, the hash per algorithm, and the RSA paddings.
//!
//! The vectors live outside the repository and come from make -C testing/ef-tests.
//! Point AXIOM_VECTORS at their root, which defaults to the workspace's testing/vectors.

use std::{env, fs, path::PathBuf};

use axiom_json::Json;
use axiom_tls::x509::{PublicKey, SignatureAlgorithm};

/// The verdict tally of one file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Tally {
    /// Valid cases accepted.
    valid: usize,
    /// Invalid cases rejected.
    invalid: usize,
    /// Acceptable cases accepted.
    acceptable_accepted: usize,
    /// Acceptable cases rejected.
    acceptable_rejected: usize,
}

/// Decodes hex without a prefix.
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digits"))
        .collect()
}

/// A string field of an object.
fn text<'a>(object: &'a Json, key: &str) -> &'a str {
    object
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("string field {key}"))
}

/// A suite file, or none when the vectors are absent and not required.
#[expect(
    clippy::print_stderr,
    reason = "a skipped suite says why in the test output"
)]
fn load(name: &str) -> Option<Json> {
    let root = env::var_os("AXIOM_VECTORS").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors"),
        PathBuf::from,
    );
    let path = root.join("wycheproof/testvectors_v1").join(name);
    if !path.is_file() {
        assert!(
            env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
            "vectors required but missing: {}",
            path.display()
        );
        eprintln!("skipping: {} not found (set AXIOM_VECTORS)", path.display());
        return None;
    }
    Some(Json::parse(fs::read(&path).expect("readable")).expect("well-formed JSON"))
}

/// Runs a file under one algorithm, failing on any case whose outcome breaks its verdict.
fn run(name: &str, algorithm: SignatureAlgorithm) -> Option<Tally> {
    let document = load(name)?;
    let mut tally = Tally::default();
    let mut failures = Vec::new();
    let mut seen = 0;
    for group in document
        .get("testGroups")
        .and_then(Json::as_array)
        .expect("groups")
    {
        let key = PublicKey::from_spki(&hex(text(group, "publicKeyDer"))).expect("group key");
        for test in group.get("tests").and_then(Json::as_array).expect("tests") {
            seen += 1;
            let accepted = key
                .verify(algorithm, &hex(text(test, "msg")), &hex(text(test, "sig")))
                .is_ok();
            match (text(test, "result"), accepted) {
                ("valid", true) => tally.valid += 1,
                ("invalid", false) => tally.invalid += 1,
                ("acceptable", true) => tally.acceptable_accepted += 1,
                ("acceptable", false) => tally.acceptable_rejected += 1,
                (result, _) => failures.push(format!(
                    "tcId {}: {result} but accepted = {accepted} ({})",
                    test.get("tcId").and_then(Json::as_u64).expect("tcId"),
                    text(test, "comment")
                )),
            }
        }
    }
    assert!(failures.is_empty(), "{name}:\n{}", failures.join("\n"));
    assert_eq!(
        document.get("numberOfTests").and_then(Json::as_u64),
        Some(seen),
        "{name}: cases seen"
    );
    Some(tally)
}

#[test]
fn suites_through_the_certificate_layer() {
    // Each tuple: file, algorithm, then valid, invalid, acceptable accepted, acceptable rejected.
    // The one acceptable RSA case per file omits the DigestInfo NULL; whole-block comparison refuses it.
    let cases = [
        (
            "ecdsa_secp256r1_sha256_test.json",
            SignatureAlgorithm::EcdsaSha256,
            [174, 310, 0, 0],
        ),
        (
            "ecdsa_secp384r1_sha384_test.json",
            SignatureAlgorithm::EcdsaSha384,
            [194, 310, 0, 0],
        ),
        (
            "ecdsa_secp384r1_sha256_test.json",
            SignatureAlgorithm::EcdsaSha256,
            [162, 310, 0, 0],
        ),
        (
            "rsa_signature_2048_sha256_test.json",
            SignatureAlgorithm::RsaPkcs1Sha256,
            [9, 249, 0, 1],
        ),
        (
            "rsa_signature_3072_sha384_test.json",
            SignatureAlgorithm::RsaPkcs1Sha384,
            [7, 251, 0, 1],
        ),
        (
            "rsa_signature_4096_sha512_test.json",
            SignatureAlgorithm::RsaPkcs1Sha512,
            [7, 251, 0, 1],
        ),
        (
            "rsa_pss_2048_sha256_mgf1_32_test.json",
            SignatureAlgorithm::RsaPssSha256,
            [63, 45, 0, 0],
        ),
        (
            "rsa_pss_2048_sha384_mgf1_48_test.json",
            SignatureAlgorithm::RsaPssSha384,
            [95, 46, 0, 0],
        ),
        (
            "rsa_pss_4096_sha512_mgf1_64_test.json",
            SignatureAlgorithm::RsaPssSha512,
            [132, 47, 0, 0],
        ),
    ];
    for (name, algorithm, [valid, invalid, accepted, rejected]) in cases {
        let Some(tally) = run(name, algorithm) else {
            continue;
        };
        assert_eq!(
            tally,
            Tally {
                valid,
                invalid,
                acceptable_accepted: accepted,
                acceptable_rejected: rejected,
            },
            "{name}"
        );
    }
}
