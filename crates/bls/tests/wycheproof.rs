//! Conformance against the Wycheproof BLS12-381 vectors.
//!
//! The vectors live outside the repository and come from make -C testing/ef-tests.
//! Point AXIOM_VECTORS at their root, which defaults to the workspace's testing/vectors.
//! Setting AXIOM_REQUIRE_VECTORS, as CI does, turns a missing file into a failure.
//!
//! ```text
//!     $AXIOM_VECTORS/wycheproof/testvectors_v1/bls_*.json
//! ```
//!
//! Ethereum signs with the proof-of-possession ciphersuite, so its tag is the only one the crate serves.
//! The basic ciphersuite, with tag suffix NUL, verifies through the curve crate under its own tag.
//! Its aggregate check needs distinct messages, which the crate never enforces, so it counts as unsupported.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use axiom_bls::{DST, PublicKey, Signature};
use axiom_bls12_381::{G1Affine, G2Affine, G2Projective, Gt};
use axiom_json::Json;

/// The count of cases by how they ended.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Tally {
    /// Valid cases accepted with the published output.
    valid: usize,
    /// Invalid cases rejected.
    invalid: usize,
    /// Cases under a ciphersuite the crate does not serve.
    unsupported: usize,
}

/// One parsed Wycheproof vector file.
#[derive(Debug)]
struct VectorFile {
    /// The file name, for messages.
    name: String,
    /// The whole document.
    document: Json,
}

impl VectorFile {
    /// Loads a file of testvectors_v1, or none when the vectors are absent.
    #[expect(
        clippy::print_stderr,
        reason = "a skipped suite says why in the test output"
    )]
    fn load(name: &str) -> Option<Self> {
        // The variable wins, so a worktree can point at a shared checkout.
        let path = env::var_os("AXIOM_VECTORS")
            .map_or_else(
                || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors"),
                PathBuf::from,
            )
            .join("wycheproof/testvectors_v1")
            .join(name);
        if !path.is_file() {
            assert!(
                env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
                "vectors required but missing: {}; run make -C testing/ef-tests",
                path.display()
            );
            eprintln!("skipping: {} not found (set AXIOM_VECTORS)", path.display());
            return None;
        }
        let text = fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let document = Json::parse(text).unwrap_or_else(|error| panic!("{name}: {error}"));
        Some(Self {
            name: name.to_owned(),
            document,
        })
    }

    /// Runs a check on every case of every group and returns the tally.
    ///
    /// The check returns whether the implementation accepted the case, or none when unsupported.
    /// A valid case must be accepted and an invalid one rejected; the file has no other verdict.
    fn run(&self, mut check: impl FnMut(&Json, &Json) -> Option<bool>) -> Tally {
        let mut tally = Tally::default();
        let mut failures = Vec::new();
        let mut seen = 0_u64;
        let groups = self.document.get("testGroups").and_then(Json::as_array);
        for group in groups.expect("testGroups") {
            for test in group.get("tests").and_then(Json::as_array).expect("tests") {
                seen += 1;
                let id = test.get("tcId").and_then(Json::as_u64).expect("tcId");
                let result = test.get("result").and_then(Json::as_str);
                match (result, check(group, test)) {
                    (_, None) => tally.unsupported += 1,
                    (Some("valid"), Some(true)) => tally.valid += 1,
                    (Some("invalid"), Some(false)) => tally.invalid += 1,
                    (result, Some(accepted)) => {
                        failures.push(format!("tcId {id}: {result:?}, accepted {accepted}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}: {failures:#?}", self.name);
        let declared = self.document.get("numberOfTests").and_then(Json::as_u64);
        assert_eq!(Some(seen), declared, "{}: cases seen", self.name);
        tally
    }
}

/// Decodes a hex string field without a prefix.
fn hex(value: Option<&Json>) -> Vec<u8> {
    let text = value.and_then(Json::as_str).expect("hex field");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Whether a group uses the proof-of-possession ciphersuite that Ethereum signs with.
fn is_pop_suite(group: &Json) -> bool {
    // The ciphersuite identifier is the domain separation tag itself.
    group
        .get("ciphersuite")
        .and_then(Json::as_str)
        .map(str::as_bytes)
        == Some(DST)
}

/// Decodes a public key; any length or encoding defect rejects it.
fn public_key(bytes: &[u8]) -> Option<PublicKey> {
    PublicKey::from_bytes(bytes.try_into().ok()?).ok()
}

/// Decodes a signature; any length or encoding defect rejects it.
fn signature(bytes: &[u8]) -> Option<Signature> {
    Signature::from_bytes(bytes.try_into().ok()?).ok()
}

#[test]
fn hash_to_g2() {
    let Some(file) = VectorFile::load("bls_hash_to_g2_test.json") else {
        return;
    };
    // The tag is RFC 9380's test tag, and the output a compressed G2 point.
    let tally = file.run(|group, test| {
        let dst = group.get("dst").and_then(Json::as_str).expect("dst");
        let point = G2Projective::hash_to_curve(&hex(test.get("msg")), dst.as_bytes());
        Some(G2Affine::from(point).to_compressed()[..] == hex(test.get("expected"))[..])
    });
    assert_eq!(
        tally,
        Tally {
            valid: 34,
            ..Tally::default()
        }
    );
}

#[test]
fn pop_verify() {
    let Some(file) = VectorFile::load("bls_sig_g2_pop_verify_test.json") else {
        return;
    };
    let tally = file.run(|group, test| {
        assert!(
            is_pop_suite(group),
            "the file uses the Ethereum ciphersuite"
        );
        let key = hex(group.get("publicKey").and_then(|key| key.get("pk")));
        // A key or signature that fails to decode rejects the case.
        Some(match (public_key(&key), signature(&hex(test.get("sig")))) {
            (Some(key), Some(signature)) => signature.verify(&key, &hex(test.get("msg"))),
            _ => false,
        })
    });
    // 26 cases: 13 valid, and 13 with a wrong tag, key, or point, or a malformed encoding.
    assert_eq!(
        tally,
        Tally {
            valid: 13,
            invalid: 13,
            ..Tally::default()
        }
    );
}

#[test]
fn basic_verify() {
    let Some(file) = VectorFile::load("bls_sig_g2_basic_verify_test.json") else {
        return;
    };
    // The basic ciphersuite differs from Ethereum's only in its tag, so the crate cannot verify it.
    // Decoding is shared and runs through the crate: KeyValidate for the key, the G2 check for the signature.
    // The pairing equation then runs here, under the basic tag, on the curve crate's primitives.
    let tally = file.run(|group, test| {
        assert!(!is_pop_suite(group), "the file uses the basic ciphersuite");
        let dst = group
            .get("ciphersuite")
            .and_then(Json::as_str)
            .expect("ciphersuite");
        let key = hex(group.get("publicKey").and_then(|key| key.get("pk")));
        let (Some(key), Some(signature)) = (public_key(&key), signature(&hex(test.get("sig"))))
        else {
            return Some(false);
        };
        // CoreVerify, draft-irtf-cfrg-bls-signature-05 section 2.7: e(pk, H(m)) e(-G1, sig) = 1.
        let hashed = G2Projective::hash_to_curve(&hex(test.get("msg")), dst.as_bytes());
        Some(
            Gt::multi_pairing(&[
                (*key.as_point(), G2Affine::from(hashed)),
                (-G1Affine::GENERATOR, *signature.as_point()),
            ])
            .is_identity(),
        )
    });
    // 88 cases: 29 valid, and 59 with a bad encoding, point, key, or message.
    assert_eq!(
        tally,
        Tally {
            valid: 29,
            invalid: 59,
            ..Tally::default()
        }
    );
}

#[test]
fn basic_aggregate_verify() {
    let Some(file) = VectorFile::load("bls_sig_g2_aggregate_verify_test.json") else {
        return;
    };
    // The basic scheme's aggregate check also demands distinct messages, a rule Ethereum never applies.
    // The crate implements only the proof-of-possession rule, so all 19 cases are unsupported.
    let tally = file.run(|group, _| {
        assert!(!is_pop_suite(group), "the file uses the basic ciphersuite");
        None
    });
    assert_eq!(
        tally,
        Tally {
            unsupported: 19,
            ..Tally::default()
        }
    );
}
