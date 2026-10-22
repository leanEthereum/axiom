//! Conformance against the multiformats multibase test vectors.
//!
//! The vectors live outside the repository, downloaded by the vector Makefile.
//! AXIOM_VECTORS names their root, else the nearest ancestor's testing/vectors is used.
//!
//! ```text
//!     $AXIOM_VECTORS/multibase/tests/<file>.csv
//! ```
//!
//! Each file encodes one input under every encoding of the multibase table.
//! Axiom implements base58btc and base32, the two forms a peer identifier takes.
//! Every other encoding is counted as unsupported, and the counts are asserted.
//! Source: https://github.com/multiformats/multibase, at the commit pinned in testing/ef-tests/Makefile.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use axiom_p2p::multibase::Multibase;

/// One vector file: its name, the input it encodes, and whether its texts are canonical.
///
/// The case-insensitivity file mixes cases on purpose, so only decoding applies to it.
const FILES: [(&str, &[u8], bool); 4] = [
    ("basic.csv", b"yes mani !", true),
    ("leading_zero.csv", b"\x00yes mani !", true),
    ("two_leading_zeros.csv", b"\x00\x00yes mani !", true),
    ("case_insensitivity.csv", b"hello world", false),
];

/// The encoding and prefix character Axiom implements for a multibase table name.
fn supported(name: &str) -> Option<(Multibase, char)> {
    match name {
        "base58btc" => Some((Multibase::Base58Btc, 'z')),
        "base32" => Some((Multibase::Base32Lower, 'b')),
        _ => None,
    }
}

/// The multibase test directory, or nothing when it is absent and not required.
///
/// # Panics
///
/// Panics when the vectors are missing and AXIOM_REQUIRE_VECTORS is set, as in CI.
fn vectors_dir() -> Option<PathBuf> {
    let root = env::var_os("AXIOM_VECTORS").map(PathBuf::from).or_else(|| {
        // Vectors are gitignored, so a git worktree finds them in the main checkout above it.
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .map(|dir| dir.join("testing/vectors"))
            .find(|dir| dir.join("multibase").is_dir())
    });
    let dir = root.map(|root| root.join("multibase/tests"));
    let found = dir.as_ref().is_some_and(|dir| dir.is_dir());
    assert!(
        found || env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
        "multibase vectors required but missing; run `make -C testing/ef-tests`"
    );
    dir.filter(|_| found)
}

/// The rows of a vector file after its header, as encoding name and quoted text.
fn rows(path: &Path) -> Vec<(String, String)> {
    let text = fs::read_to_string(path).expect("vector file is readable");
    text.lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (name, value) = line.split_once(',').expect("a row has two columns");
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .expect("the text column is quoted");
            (name.trim().to_owned(), value.to_owned())
        })
        .collect()
}

#[test]
fn decodes_and_encodes_every_supported_vector() {
    let Some(dir) = vectors_dir() else {
        eprintln!("skipping multibase vectors: not found, run `make -C testing/ef-tests`");
        return;
    };

    let mut checked = 0_usize;
    let mut unsupported = 0_usize;
    for (file, input, canonical) in FILES {
        for (name, text) in rows(&dir.join(file)) {
            let Some((base, prefix)) = supported(&name) else {
                unsupported += 1;
                continue;
            };

            // The first character names the encoding, the rest is the body.
            let body = text
                .strip_prefix(prefix)
                .unwrap_or_else(|| panic!("{file} {name}: prefix of {text}"));
            assert_eq!(base.decode(body).as_deref(), Some(input), "{file} {name}");

            // A canonical text is exactly what the encoder writes.
            if canonical {
                assert_eq!(base.encode(input), body, "{file} {name}");
            }
            checked += 1;
        }
    }
    eprintln!("multibase: {checked} vectors checked, {unsupported} in unsupported encodings");

    // Base58btc appears in the three canonical files, base32 in all four.
    // The other 74 rows are encodings Axiom never reads, such as base64 or base36.
    assert_eq!((checked, unsupported), (7, 74));
}
