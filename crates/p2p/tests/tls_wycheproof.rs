//! Wycheproof ECDSA P-256 with SHA-256 in DER, through the TLS signature decoder and P-256 verify.
//!
//! Certificates and CertificateVerify messages carry ECDSA signatures in DER.
//! The suite targets that decoder: non-minimal lengths and integers, wrong tags, and trailing bytes.
//!
//! The vectors live outside the repository and come from make -C testing/ef-tests.
//! Point AXIOM_VECTORS at their root, which defaults to the workspace's testing/vectors.
//!
//! ```text
//!     $AXIOM_VECTORS/wycheproof/testvectors_v1/ecdsa_secp256r1_sha256_test.json
//! ```

use std::{env, fs, path::PathBuf};

use axiom_crypto::p256::PublicKey;
use axiom_json::Json;
use axiom_p2p::tls::EcdsaSigValue;
use sha2::{Digest, Sha256};

/// The suite file.
const FILE: &str = "wycheproof/testvectors_v1/ecdsa_secp256r1_sha256_test.json";

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
        .expect("string field")
}

/// The suite, or none when the vectors are absent and not required.
#[expect(
    clippy::print_stderr,
    reason = "a skipped suite says why in the test output"
)]
fn load() -> Option<Json> {
    let root = env::var_os("AXIOM_VECTORS").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors"),
        PathBuf::from,
    );
    let path = root.join(FILE);
    if !path.is_file() {
        assert!(
            env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
            "vectors required but missing: {}",
            path.display()
        );
        eprintln!("skipping: {} not found (set AXIOM_VECTORS)", path.display());
        return None;
    }
    let bytes = fs::read(&path).expect("readable vector file");
    Some(Json::parse(bytes).expect("well-formed JSON"))
}

#[test]
fn ecdsa_secp256r1_sha256_der() {
    let Some(document) = load() else {
        return;
    };
    let (mut valid, mut invalid, mut seen) = (0, 0, 0);
    let mut failures = Vec::new();
    for group in document.get("testGroups").and_then(Json::as_array).unwrap() {
        let key = text(group.get("publicKey").unwrap(), "uncompressed");
        let key = PublicKey::from_sec1_bytes(&hex(key)).unwrap();
        for test in group.get("tests").and_then(Json::as_array).unwrap() {
            seen += 1;
            let hash: [u8; 32] = Sha256::digest(hex(text(test, "msg"))).into();
            let accepted = EcdsaSigValue::from_der(&hex(text(test, "sig")))
                .is_ok_and(|value| key.verify(&hash, &value.signature()).is_ok());
            // Every case is valid or invalid; none is merely acceptable.
            match (text(test, "result"), accepted) {
                ("valid", true) => valid += 1,
                ("invalid", false) => invalid += 1,
                (result, _) => failures.push(format!(
                    "tcId {}: {result} but accepted = {accepted} ({})",
                    test.get("tcId").and_then(Json::as_u64).unwrap(),
                    text(test, "comment")
                )),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    // 484 cases: 174 valid, high s included, and 310 invalid.
    assert_eq!(
        document.get("numberOfTests").and_then(Json::as_u64),
        Some(seen)
    );
    assert_eq!((valid, invalid), (174, 310));
}
