//! Conformance against the Ethereum BLS vectors and the Altair spec's BLS vectors.
//!
//! The vectors live outside the repository.
//! Point AXIOM_VECTORS at their root.
//! It defaults to the workspace's testing/vectors directory, and every suite skips when it is absent.
//! Setting AXIOM_REQUIRE_VECTORS, as CI does, turns a missing suite into a failure.
//! Each suite asserts its case count, so a shrinking download cannot pass silently.
//!
//! ```text
//!     $AXIOM_VECTORS/bls12-381-tests/{sign,verify,aggregate,...}/*.yaml
//!     $AXIOM_VECTORS/consensus-spec-tests/tests/general/altair/bls/<handler>/bls/<case>/data.yaml
//! ```

use std::{
    env,
    fmt::Write,
    fs,
    iter::Peekable,
    path::{Path, PathBuf},
    str::Chars,
};

use axiom_bls::{PublicKey, SecretKey, Signature, SignatureSet};
use axiom_bls12_381::{G1Affine, G2Affine, G2Projective};

/// A YAML value, restricted to what the vector files use.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Yaml {
    /// The plain scalar null.
    Null,
    /// The plain scalars true and false.
    Bool(bool),
    /// Any other scalar, quoted or plain.
    Str(String),
    /// A block or flow sequence.
    List(Vec<Self>),
    /// A block or flow mapping, in file order.
    Map(Vec<(String, Self)>),
}

impl Yaml {
    /// Parses a whole document: block mappings and sequences, with flow collections inside.
    fn parse(text: &str) -> Self {
        // Blank lines and comments carry no structure.
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .collect();
        // The document is one block node at indentation zero.
        let mut cursor = 0;
        Self::parse_block(&lines, &mut cursor, 0)
    }

    /// Parses the block node whose lines start at the cursor with the given indentation.
    fn parse_block(lines: &[&str], cursor: &mut usize, indent: usize) -> Self {
        let line = lines[*cursor];
        if line[indent..].starts_with("- ") {
            // Block sequence: consecutive "- item" lines at this indentation.
            let mut items = Vec::new();
            while *cursor < lines.len()
                && indentation(lines[*cursor]) == indent
                && lines[*cursor][indent..].starts_with("- ")
            {
                let rest = lines[*cursor][indent + 2..].to_owned();
                *cursor += 1;
                items.push(Self::parse_inline(&rest, lines, cursor));
            }
            return Self::List(items);
        }

        // Block mapping: consecutive "key: value" lines at this indentation.
        let mut entries = Vec::new();
        while *cursor < lines.len() && indentation(lines[*cursor]) == indent {
            let line = &lines[*cursor][indent..];
            if line.starts_with("- ") {
                break;
            }
            let (key, rest) = line.split_once(':').expect("mapping line has a colon");
            let rest = rest.trim().to_owned();
            *cursor += 1;
            let value = if rest.is_empty() {
                // The value is a nested block, more indented or a same-level sequence.
                let child_indent = indentation(lines[*cursor]);
                Self::parse_block(lines, cursor, child_indent)
            } else {
                Self::parse_inline(&rest, lines, cursor)
            };
            entries.push((key.trim().to_owned(), value));
        }
        Self::Map(entries)
    }

    /// Parses a value that starts on the current line, pulling continuation lines for flow nodes.
    fn parse_inline(first: &str, lines: &[&str], cursor: &mut usize) -> Self {
        let mut text = first.to_owned();
        // A flow collection may wrap: keep appending lines until the brackets balance.
        while !brackets_balanced(&text) {
            text.push(' ');
            text.push_str(lines[*cursor].trim());
            *cursor += 1;
        }
        let mut chars = text.trim().chars().peekable();
        Self::parse_flow(&mut chars)
    }

    /// Parses one flow node: a sequence, a mapping, or a scalar.
    fn parse_flow(chars: &mut Peekable<Chars<'_>>) -> Self {
        skip_spaces(chars);
        match chars.peek() {
            Some('[') => {
                chars.next();
                let mut items = Vec::new();
                loop {
                    skip_spaces(chars);
                    if chars.peek() == Some(&']') {
                        chars.next();
                        return Self::List(items);
                    }
                    items.push(Self::parse_flow(chars));
                    skip_spaces(chars);
                    if chars.peek() == Some(&',') {
                        chars.next();
                    }
                }
            }
            Some('{') => {
                chars.next();
                let mut entries = Vec::new();
                loop {
                    skip_spaces(chars);
                    if chars.peek() == Some(&'}') {
                        chars.next();
                        return Self::Map(entries);
                    }
                    let key: String = chars.by_ref().take_while(|c| *c != ':').collect();
                    let value = Self::parse_flow(chars);
                    entries.push((key.trim().to_owned(), value));
                    skip_spaces(chars);
                    if chars.peek() == Some(&',') {
                        chars.next();
                    }
                }
            }
            Some('\'') => {
                // Single-quoted scalar.
                // A doubled quote stands for one quote.
                chars.next();
                let mut value = String::new();
                while let Some(c) = chars.next() {
                    if c == '\'' {
                        if chars.peek() == Some(&'\'') {
                            chars.next();
                            value.push('\'');
                            continue;
                        }
                        break;
                    }
                    value.push(c);
                }
                Self::Str(value)
            }
            _ => {
                // Plain scalar: runs until a flow delimiter.
                let mut value = String::new();
                while let Some(c) = chars.peek() {
                    if matches!(c, ',' | ']' | '}') {
                        break;
                    }
                    value.push(*c);
                    chars.next();
                }
                match value.trim() {
                    "null" | "~" => Self::Null,
                    "true" => Self::Bool(true),
                    "false" => Self::Bool(false),
                    other => Self::Str(other.to_owned()),
                }
            }
        }
    }

    /// The value under a mapping key.
    fn get(&self, key: &str) -> &Self {
        // Keys are few, so a linear scan suffices.
        let Self::Map(entries) = self else {
            panic!("expected a mapping, found {self:?}");
        };
        entries
            .iter()
            .find(|(name, _)| name == key)
            .map_or_else(|| panic!("missing key {key}"), |(_, value)| value)
    }

    /// The items of a sequence.
    fn list(&self) -> &[Self] {
        // Any other node is a malformed vector.
        match self {
            Self::List(items) => items,
            other => panic!("expected a sequence, found {other:?}"),
        }
    }

    /// The text of a scalar.
    fn str(&self) -> &str {
        // Any other node is a malformed vector.
        match self {
            Self::Str(value) => value,
            other => panic!("expected a string, found {other:?}"),
        }
    }

    /// The bytes of a hex scalar, with or without a 0x prefix.
    fn bytes(&self) -> Vec<u8> {
        hex(self.str())
    }
}

/// Number of leading spaces.
fn indentation(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// Whether every bracket and brace opened outside quotes is closed.
fn brackets_balanced(text: &str) -> bool {
    // Count open minus closed brackets, ignoring those inside single quotes.
    let mut depth = 0_i32;
    let mut quoted = false;
    for c in text.chars() {
        match c {
            '\'' => quoted = !quoted,
            '[' | '{' if !quoted => depth += 1,
            ']' | '}' if !quoted => depth -= 1,
            _ => {}
        }
    }
    depth == 0
}

/// Advances past spaces.
fn skip_spaces(chars: &mut Peekable<Chars<'_>>) {
    while chars.peek() == Some(&' ') {
        chars.next();
    }
}

/// Decodes hex, with or without a 0x prefix.
fn hex(text: &str) -> Vec<u8> {
    // Vectors write hex both with and without the prefix.
    let digits = text.strip_prefix("0x").unwrap_or(text);
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// The vectors root: AXIOM_VECTORS, or the workspace's testing/vectors.
fn vectors_root() -> PathBuf {
    // The variable wins, so worktrees can point at a shared checkout.
    env::var_os("AXIOM_VECTORS").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors"),
        PathBuf::from,
    )
}

/// Runs a check on every YAML file of a directory, which must hold exactly the given count.
///
/// The check returns the expected and the actual outcome.
/// Any mismatch fails the test.
#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the suite reports its case count, or why it skipped, to the test output"
)]
fn run_suite(directory: &Path, count: usize, check: impl Fn(&Yaml) -> (Yaml, Yaml)) {
    if !directory.is_dir() {
        // CI sets the variable, so a missing download fails there instead of skipping.
        assert!(
            env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
            "vectors required but missing under {}; run make -C testing/ef-tests",
            directory.display()
        );
        eprintln!(
            "skipping {}: vectors not found (set AXIOM_VECTORS)",
            directory.display()
        );
        return;
    }
    let mut files: Vec<PathBuf> = fs::read_dir(directory)
        .expect("readable directory")
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    files.sort();

    let mut failures = Vec::new();
    for file in &files {
        // Spec-test cases are folders holding a data.yaml.
        // The bls12-381 suite uses bare files.
        let path = if file.is_dir() {
            file.join("data.yaml")
        } else {
            file.clone()
        };
        let case = Yaml::parse(&fs::read_to_string(&path).expect("readable vector"));
        let (expected, actual) = check(&case);
        if expected != actual {
            failures.push(format!(
                "{}: expected {expected:?}, got {actual:?}",
                path.display()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(files.len(), count, "{}: case count", directory.display());
    println!("{}: {} cases passed", directory.display(), files.len());
}

/// Root of the bls12-381-tests suites.
fn bls_suite(name: &str) -> PathBuf {
    vectors_root().join("bls12-381-tests").join(name)
}

/// Root of an Altair BLS handler in the consensus spec tests.
fn altair_suite(handler: &str) -> PathBuf {
    // Layout: general/altair/bls/<handler>/bls/<case>/data.yaml.
    vectors_root()
        .join("consensus-spec-tests/tests/general/altair/bls")
        .join(handler)
        .join("bls")
}

/// Decodes a public key, failing on a wrong length as on any other defect.
fn public_key(value: &Yaml) -> Option<PublicKey> {
    PublicKey::from_bytes(&value.bytes().try_into().ok()?).ok()
}

/// Decodes a signature, failing on a wrong length as on any other defect.
fn signature(value: &Yaml) -> Option<Signature> {
    Signature::from_bytes(&value.bytes().try_into().ok()?).ok()
}

/// Decodes every public key of a list, or nothing if one fails.
fn public_keys(value: &Yaml) -> Option<Vec<PublicKey>> {
    value.list().iter().map(public_key).collect()
}

/// Encodes bytes as 0x-prefixed hex, the form of the expected outputs.
fn to_hex(bytes: &[u8]) -> Yaml {
    // Lowercase, 0x-prefixed, as the vectors print bytes.
    let text = bytes.iter().fold(String::from("0x"), |mut text, byte| {
        write!(text, "{byte:02x}").expect("writing to a string cannot fail");
        text
    });
    Yaml::Str(text)
}

#[test]
fn yaml_reader_handles_the_vector_shapes() {
    // Fixture state: a block map holding a wrapped flow list, a block list, and plain scalars.
    let text =
        "input:\n  keys: ['0xaa',\n    '0xbb']\n  more:\n  - 'x'\n  flag: true\noutput: null\n";
    let parsed = Yaml::parse(text);
    assert_eq!(
        parsed.get("input").get("keys"),
        &Yaml::List(vec![Yaml::Str("0xaa".into()), Yaml::Str("0xbb".into())])
    );
    assert_eq!(
        parsed.get("input").get("more"),
        &Yaml::List(vec![Yaml::Str("x".into())])
    );
    assert_eq!(parsed.get("input").get("flag"), &Yaml::Bool(true));
    assert_eq!(parsed.get("output"), &Yaml::Null);

    // A flow map with a plain scalar and an empty quoted one.
    let parsed = Yaml::parse("input: {msg: abc, other: ''}\n");
    assert_eq!(parsed.get("input").get("msg"), &Yaml::Str("abc".into()));
    assert_eq!(parsed.get("input").get("other"), &Yaml::Str(String::new()));
}

#[test]
fn sign() {
    run_suite(&bls_suite("sign"), 10, |case| {
        let input = case.get("input");
        // A key that fails to decode expects no signature at all.
        let actual = input
            .get("privkey")
            .bytes()
            .try_into()
            .ok()
            .and_then(|bytes| SecretKey::from_bytes(&bytes).ok())
            .map_or(Yaml::Null, |key| {
                to_hex(&key.sign(&input.get("message").bytes()).to_bytes())
            });
        (case.get("output").clone(), actual)
    });
}

#[test]
fn verify() {
    run_suite(&bls_suite("verify"), 29, |case| {
        // Fixture state: one key, one message, one signature.
        let input = case.get("input");
        // A key or signature that fails to decode means the vector expects false.
        let valid = match (
            public_key(input.get("pubkey")),
            signature(input.get("signature")),
        ) {
            (Some(key), Some(signature)) => signature.verify(&key, &input.get("message").bytes()),
            _ => false,
        };
        (case.get("output").clone(), Yaml::Bool(valid))
    });
}

#[test]
fn aggregate() {
    run_suite(&bls_suite("aggregate"), 6, |case| {
        // One undecodable signature voids the whole aggregate.
        let signatures: Option<Vec<Signature>> =
            case.get("input").list().iter().map(signature).collect();
        // An empty list has no aggregate, which the vector writes as null.
        let actual = signatures
            .and_then(|signatures| Signature::aggregate(&signatures).ok())
            .map_or(Yaml::Null, |aggregate| to_hex(&aggregate.to_bytes()));
        (case.get("output").clone(), actual)
    });
}

#[test]
fn aggregate_verify() {
    run_suite(&bls_suite("aggregate_verify"), 5, |case| {
        // Fixture state: n keys, n messages, one aggregate signature.
        let input = case.get("input");
        let messages: Vec<Vec<u8>> = input
            .get("messages")
            .list()
            .iter()
            .map(Yaml::bytes)
            .collect();
        let messages: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
        // Any undecodable key or signature means the vector expects false.
        let valid = match (
            public_keys(input.get("pubkeys")),
            signature(input.get("signature")),
        ) {
            (Some(keys), Some(signature)) => {
                let keys: Vec<&PublicKey> = keys.iter().collect();
                signature.aggregate_verify(&keys, &messages)
            }
            _ => false,
        };
        (case.get("output").clone(), Yaml::Bool(valid))
    });
}

#[test]
fn fast_aggregate_verify() {
    run_suite(&bls_suite("fast_aggregate_verify"), 12, |case| {
        // Fixture state: n keys over one message, one aggregate signature.
        let input = case.get("input");
        // Any undecodable key or signature means the vector expects false.
        let valid = match (
            public_keys(input.get("pubkeys")),
            signature(input.get("signature")),
        ) {
            (Some(keys), Some(signature)) => {
                let keys: Vec<&PublicKey> = keys.iter().collect();
                signature.fast_aggregate_verify(&keys, &input.get("message").bytes())
            }
            _ => false,
        };
        (case.get("output").clone(), Yaml::Bool(valid))
    });
}

#[test]
fn batch_verify() {
    run_suite(&bls_suite("batch_verify"), 4, |case| {
        let input = case.get("input");
        let keys = input.get("pubkeys").list();
        let messages = input.get("messages").list();
        let signatures = input.get("signatures").list();
        // Build one set per triple.
        // Any undecodable part makes the whole batch invalid.
        let sets: Option<Vec<SignatureSet>> = keys
            .iter()
            .zip(messages)
            .zip(signatures)
            .map(|((key, message), sig)| {
                Some(SignatureSet {
                    signature: signature(sig)?,
                    public_key: public_key(key)?,
                    message: message.bytes().try_into().ok()?,
                })
            })
            .collect();
        let valid = sets.is_some_and(|sets| SignatureSet::verify_batch(&sets));
        (case.get("output").clone(), Yaml::Bool(valid))
    });
}

#[test]
fn deserialization_g1() {
    run_suite(&bls_suite("deserialization_G1"), 13, |case| {
        // Point decoding with the subgroup check.
        // Infinity is a valid point here.
        let bytes = case.get("input").get("pubkey").bytes();
        let valid = <[u8; 48]>::try_from(bytes.as_slice())
            .is_ok_and(|bytes| G1Affine::from_compressed(&bytes).is_ok());
        (case.get("output").clone(), Yaml::Bool(valid))
    });
}

#[test]
fn deserialization_g2() {
    run_suite(&bls_suite("deserialization_G2"), 15, |case| {
        // Signature decoding is the subgroup-checked G2 decoding.
        // Infinity is valid.
        let bytes = case.get("input").get("signature").bytes();
        let valid = <[u8; 96]>::try_from(bytes.as_slice())
            .is_ok_and(|bytes| G2Affine::from_compressed(&bytes).is_ok());
        (case.get("output").clone(), Yaml::Bool(valid))
    });
}

#[test]
fn hash_to_g2() {
    // These are the RFC 9380 appendix J.10.1 vectors, under the RFC's test tag.
    let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
    run_suite(&bls_suite("hash_to_G2"), 4, |case| {
        let message = case.get("input").get("msg").str().as_bytes().to_vec();
        let point = G2Affine::from(G2Projective::hash_to_curve(&message, dst));
        let (x, y) = point.coordinates().expect("hash output is finite");
        // Expected coordinates read "0x<c0>,0x<c1>".
        let render = |c0: [u8; 48], c1: [u8; 48]| {
            let Yaml::Str(c0) = to_hex(&c0) else {
                unreachable!()
            };
            let Yaml::Str(c1) = to_hex(&c1) else {
                unreachable!()
            };
            Yaml::Str(format!("{c0},{c1}"))
        };
        let actual = Yaml::Map(vec![
            (
                "x".to_owned(),
                render(x.c0.to_bytes_be(), x.c1.to_bytes_be()),
            ),
            (
                "y".to_owned(),
                render(y.c0.to_bytes_be(), y.c1.to_bytes_be()),
            ),
        ]);
        (case.get("output").clone(), actual)
    });
}

#[test]
fn eth_aggregate_pubkeys() {
    run_suite(&altair_suite("eth_aggregate_pubkeys"), 8, |case| {
        // Empty lists, invalid keys, and infinite sums all expect null.
        let actual = public_keys(case.get("input"))
            .and_then(|keys| PublicKey::aggregate(&keys).ok())
            .map_or(Yaml::Null, |aggregate| to_hex(&aggregate.to_bytes()));
        (case.get("output").clone(), actual)
    });
}

#[test]
fn eth_fast_aggregate_verify() {
    run_suite(&altair_suite("eth_fast_aggregate_verify"), 12, |case| {
        // Fixture state: possibly no keys, one message, one signature.
        let input = case.get("input");
        // The Altair rule accepts no keys with the infinity signature.
        let valid = match (
            public_keys(input.get("pubkeys")),
            signature(input.get("signature")),
        ) {
            (Some(keys), Some(signature)) => {
                let keys: Vec<&PublicKey> = keys.iter().collect();
                signature.eth_fast_aggregate_verify(&keys, &input.get("message").bytes())
            }
            _ => false,
        };
        (case.get("output").clone(), Yaml::Bool(valid))
    });
}
