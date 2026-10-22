//! The x509-limbo path validation suite, BetterTLS included, through the web PKI verifier.
//!
//! Each case names roots, intermediates, a server certificate, a time, and a peer name.
//! The verifier must accept exactly the chains the suite marks valid.
//!
//! Cases outside what a TLS client checks are counted as skipped, by reason:
//!
//! - client certificate validation, which no HTTPS client of this stack performs;
//! - revocation lists, ML-DSA keys, and caller-set depth, key usage or algorithm limits;
//! - a case with no peer name, since every TLS connection has one.
//!
//! The vectors live outside the repository and come from make -C testing/ef-tests.
//! Point AXIOM_VECTORS at their root, which defaults to the workspace's testing/vectors.
//!
//! ```text
//!     $AXIOM_VECTORS/x509-limbo/limbo.json
//! ```

use std::{collections::BTreeMap, env, fs, path::PathBuf};

use axiom_json::{Json, Limits};
use axiom_tls::{
    PemBlock,
    der::Timestamp,
    pki::{RootStore, ServerName, TrustAnchor},
};

/// The suite file.
const FILE: &str = "x509-limbo/limbo.json";

/// The date of the pinned commit, 2026-09-24, the present of the suite's untimed cases.
const SUITE_DATE: Timestamp = Timestamp::from_civil(2026, 9, 24, 0);

/// Features whose cases need checks outside a TLS client's path validation.
const SKIPPED_FEATURES: [&str; 3] = ["has-crl", "has-mldsa", "max-chain-depth"];

/// Cases where this verifier's verdict differs from the suite's, each for a stated reason.
///
/// Every entry is a rule that RFC 5280 or the CA/Browser Forum places on issuers, or a pedantic check.
/// Path validation for TLS, as the deployed clients run it, does not enforce these.
const DIVERGENCES: [(&str, &str); 43] = [
    (
        "pathlen::validation-ignores-pathlen-in-leaf",
        "a CA certificate never serves as the server's own",
    ),
    (
        "rfc5280::aki::critical-aki",
        "key identifiers are an issuance rule; paths match by name and signature",
    ),
    (
        "rfc5280::aki::leaf-missing-aki",
        "key identifiers are an issuance rule; paths match by name and signature",
    ),
    (
        "rfc5280::aki::intermediate-missing-aki",
        "key identifiers are an issuance rule; paths match by name and signature",
    ),
    (
        "rfc5280::aki::cross-signed-root-missing-aki",
        "key identifiers are an issuance rule; paths match by name and signature",
    ),
    (
        "rfc5280::nc::permitted-dns-match-noncritical",
        "the CA/Browser Forum allows non-critical name constraints",
    ),
    (
        "rfc5280::nc::invalid-dnsname-leading-period",
        "a leading period is read as subdomains only, as deployed constraints use it",
    ),
    (
        "rfc5280::pc::ica-noncritical-pc",
        "certificate policies are not processed",
    ),
    (
        "rfc5280::serial::zero",
        "serial numbers are not checked beyond their length",
    ),
    (
        "rfc5280::ski::critical-ski",
        "key identifiers are an issuance rule; paths match by name and signature",
    ),
    (
        "rfc5280::ski::root-missing-ski",
        "key identifiers are an issuance rule; paths match by name and signature",
    ),
    (
        "rfc5280::ski::intermediate-missing-ski",
        "key identifiers are an issuance rule; paths match by name and signature",
    ),
    (
        "rfc5280::validity::expired-root",
        "a trust anchor is its name and key; the rest of a root is the store's business",
    ),
    (
        "rfc5280::unknown-critical-extension-root",
        "a trust anchor is its name and key; the rest of a root is the store's business",
    ),
    (
        "rfc5280::root-missing-basic-constraints",
        "a trust anchor is its name and key; the rest of a root is the store's business",
    ),
    (
        "rfc5280::root-non-critical-basic-constraints",
        "a trust anchor is its name and key; the rest of a root is the store's business",
    ),
    (
        "rfc5280::root-inconsistent-ca-extensions",
        "a trust anchor is its name and key; the rest of a root is the store's business",
    ),
    (
        "rfc5280::ca-as-leaf",
        "a CA certificate never serves as the server's own",
    ),
    (
        "webpki::aki::root-with-aki-missing-keyidentifier",
        "key identifiers are an issuance rule; paths match by name and signature",
    ),
    (
        "webpki::aki::root-with-aki-authoritycertissuer",
        "key identifiers are an issuance rule; paths match by name and signature",
    ),
    (
        "webpki::aki::root-with-aki-authoritycertserialnumber",
        "key identifiers are an issuance rule; paths match by name and signature",
    ),
    (
        "webpki::aki::root-with-aki-all-fields",
        "key identifiers are an issuance rule; paths match by name and signature",
    ),
    (
        "webpki::aki::root-with-aki-ski-mismatch",
        "key identifiers are an issuance rule; paths match by name and signature",
    ),
    (
        "webpki::cn::ipv4-hex-mismatch",
        "the common name is never read, per RFC 9525, section 6.3",
    ),
    (
        "webpki::cn::ipv4-leading-zeros-mismatch",
        "the common name is never read, per RFC 9525, section 6.3",
    ),
    (
        "webpki::cn::ipv6-uppercase-mismatch",
        "the common name is never read, per RFC 9525, section 6.3",
    ),
    (
        "webpki::cn::ipv6-uncompressed-mismatch",
        "the common name is never read, per RFC 9525, section 6.3",
    ),
    (
        "webpki::cn::ipv6-non-rfc5952-mismatch",
        "the common name is never read, per RFC 9525, section 6.3",
    ),
    (
        "webpki::cn::punycode-not-in-san",
        "the common name is never read, per RFC 9525, section 6.3",
    ),
    (
        "webpki::cn::utf8-vs-punycode-mismatch",
        "the common name is never read, per RFC 9525, section 6.3",
    ),
    (
        "webpki::cn::not-in-san",
        "the common name is never read, per RFC 9525, section 6.3",
    ),
    (
        "webpki::cn::case-mismatch",
        "the common name is never read, per RFC 9525, section 6.3",
    ),
    (
        "webpki::eku::ee-anyeku",
        "an issuance rule on extended key usage, beyond what a client checks",
    ),
    (
        "webpki::eku::ee-critical-eku",
        "an issuance rule on extended key usage, beyond what a client checks",
    ),
    (
        "webpki::eku::ee-without-eku",
        "an issuance rule on extended key usage, beyond what a client checks",
    ),
    (
        "webpki::eku::root-has-eku",
        "a trust anchor is its name and key; the rest of a root is the store's business",
    ),
    (
        "webpki::san::public-suffix-multi-label-wildcard-san",
        "no public suffix list is compiled in",
    ),
    (
        "webpki::san::public-suffix-private-namespace-wildcard-san",
        "no public suffix list is compiled in",
    ),
    (
        "webpki::san::san-critical-with-nonempty-subject",
        "criticality of the alternative name is an issuance rule",
    ),
    (
        "webpki::malformed-aia",
        "authority information access is not read",
    ),
    (
        "webpki::forbidden-weak-rsa-in-leaf",
        "the server key's size is checked when it signs the handshake",
    ),
    (
        "webpki::forbidden-rsa-not-divisible-by-8-in-root",
        "a trust anchor is its name and key; the rest of a root is the store's business",
    ),
    (
        "webpki::forbidden-rsa-key-not-divisible-by-8-in-leaf",
        "the server key's size is checked when it signs the handshake",
    ),
];

/// How one case ended.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Verdict {
    /// The chain was accepted.
    Accepted,
    /// The chain was refused, with the reason.
    Refused(String),
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
    let limits = Limits {
        max_depth: 32,
        max_bytes: 64 << 20,
    };
    Some(Json::parse_with(bytes, limits).expect("well-formed JSON"))
}

/// A string field of an object.
fn text<'a>(object: &'a Json, key: &str) -> &'a str {
    object
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("string field {key}"))
}

/// An array field of an object.
fn array<'a>(object: &'a Json, key: &str) -> &'a [Json] {
    object
        .get(key)
        .and_then(Json::as_array)
        .unwrap_or_else(|| panic!("array field {key}"))
}

/// The DER of every certificate in PEM texts.
fn certificates<'a>(pems: impl Iterator<Item = &'a str>) -> Vec<Vec<u8>> {
    pems.flat_map(|pem| PemBlock::parse_all(pem.as_bytes()).expect("PEM"))
        .filter(|block| block.label == "CERTIFICATE")
        .map(|block| block.der)
        .collect()
}

/// Reads an RFC 3339 time in UTC: YYYY-MM-DDTHH:MM:SS, then Z or +00:00.
fn time(text: &str) -> Timestamp {
    let number = |range: std::ops::Range<usize>| -> u32 { text[range].parse().expect("digits") };
    assert!(
        text.ends_with("+00:00") || text.ends_with('Z'),
        "UTC time {text}"
    );
    let seconds = number(11..13) * 3600 + number(14..16) * 60 + number(17..19);
    Timestamp::from_civil(
        i64::from(number(0..4)),
        number(5..7),
        number(8..10),
        i64::from(seconds),
    )
}

/// Why a case is skipped, if it is.
fn skip_reason(case: &Json) -> Option<&'static str> {
    if text(case, "validation_kind") != "SERVER" {
        return Some("client validation");
    }
    let features = array(case, "features");
    if let Some(feature) = SKIPPED_FEATURES
        .iter()
        .find(|skipped| features.iter().any(|f| f.as_str() == Some(skipped)))
    {
        return Some(feature);
    }
    if !array(case, "signature_algorithms").is_empty() || !array(case, "key_usage").is_empty() {
        return Some("caller-set algorithms or key usage");
    }
    if case.get("expected_peer_name").is_none_or(Json::is_null) {
        return Some("no peer name");
    }
    None
}

/// Runs one case through the verifier.
fn evaluate(case: &Json) -> Verdict {
    let mut roots = RootStore::new();
    for der in certificates(array(case, "trusted_certs").iter().filter_map(Json::as_str)) {
        // A root this stack cannot read anchors nothing, as in a platform bundle.
        if let Ok(anchor) = TrustAnchor::from_der(&der) {
            roots.add(anchor);
        }
    }
    let leaf = certificates([text(case, "peer_certificate")].into_iter());
    let intermediates = certificates(
        array(case, "untrusted_intermediates")
            .iter()
            .filter_map(Json::as_str),
    );
    let chain: Vec<&[u8]> = leaf
        .iter()
        .chain(&intermediates)
        .map(Vec::as_slice)
        .collect();
    // An untimed case means the suite's own present, so the pinned commit's date stands in.
    // Its live chains, captured then, would expire against a moving clock.
    let now = case
        .get("validation_time")
        .and_then(Json::as_str)
        .map_or(SUITE_DATE, time);
    let peer = case.get("expected_peer_name").expect("peer name");
    let Ok(name) = text(peer, "value").parse::<ServerName>() else {
        return Verdict::Refused("invalid peer name".to_owned());
    };
    match roots.verify_server(&chain, &name, now) {
        Ok(_) => Verdict::Accepted,
        Err(error) => Verdict::Refused(error.to_string()),
    }
}

#[test]
#[expect(
    clippy::print_stderr,
    reason = "the suite reports its tally to the test output"
)]
fn limbo() {
    let Some(suite) = load() else {
        return;
    };
    let mut skipped: BTreeMap<&str, usize> = BTreeMap::new();
    let mut agreed = BTreeMap::from([("SUCCESS", 0_usize), ("FAILURE", 0_usize)]);
    let mut diverged = Vec::new();
    let cases = array(&suite, "testcases");
    for case in cases {
        if let Some(reason) = skip_reason(case) {
            *skipped.entry(reason).or_default() += 1;
            continue;
        }
        let id = text(case, "id");
        let expected = text(case, "expected_result");
        let verdict = evaluate(case);
        let matches = matches!(
            (expected, &verdict),
            ("SUCCESS", Verdict::Accepted) | ("FAILURE", Verdict::Refused(_))
        );
        if matches {
            *agreed.get_mut(expected).expect("known verdict") += 1;
        } else {
            diverged.push((id.to_owned(), expected.to_owned(), verdict));
        }
    }
    for (id, expected, verdict) in &diverged {
        eprintln!("{id}: expected {expected}, got {verdict:?}");
    }
    let ids: Vec<&str> = diverged.iter().map(|(id, ..)| id.as_str()).collect();
    let known: Vec<&str> = DIVERGENCES.iter().map(|&(id, _)| id).collect();
    eprintln!(
        "agreed {agreed:?}, skipped {skipped:?}, diverged {}",
        ids.len()
    );
    assert_eq!(ids, known, "divergences");
    // 9802 cases: 9718 agree, 43 diverge for the reasons above, 41 are skipped.
    assert_eq!(cases.len(), 9802, "cases in the pinned suite");
    assert_eq!(
        agreed,
        BTreeMap::from([("FAILURE", 8805), ("SUCCESS", 913)]),
        "agreed verdicts"
    );
    assert_eq!(
        skipped,
        BTreeMap::from([
            ("caller-set algorithms or key usage", 2),
            ("client validation", 10),
            ("has-crl", 17),
            ("has-mldsa", 6),
            ("max-chain-depth", 5),
            ("no peer name", 1),
        ]),
        "skipped cases"
    );
}
