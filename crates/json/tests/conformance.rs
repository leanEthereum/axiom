//! Conformance against JSONTestSuite, the RFC 8259 parsing corpus.
//!
//! The corpus lives outside the repository, downloaded by the vector Makefile.
//! AXIOM_VECTORS names its root, else the nearest ancestor's testing/vectors is used.
//!
//! ```text
//!     $AXIOM_VECTORS/json-test-suite/test_parsing/<prefix>_<name>.json
//! ```
//!
//! A y_ file must parse, an n_ file must be rejected.
//! An i_ file is the implementation's choice, and each one is pinned below with its reason.
//! Source: https://github.com/nst/JSONTestSuite, at the commit pinned in testing/ef-tests/Makefile.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use axiom_json::{ErrorKind, Json, Limits};

/// Files in the pinned corpus, so a shrinking download or a listing bug cannot pass.
const CORPUS_SIZE: usize = 318;

/// Files the corpus says must parse.
const ACCEPT_COUNT: usize = 95;

/// Files the corpus says must be rejected.
const REJECT_COUNT: usize = 188;

/// What Axiom does with an input the corpus leaves to the implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Choice {
    /// The text parses, and its compact form is the input without its trailing newline.
    Accept,
    /// The text fails at this offset for this reason.
    Reject(usize, ErrorKind),
}

/// Valid RFC 8259 texts that Axiom rejects on purpose.
///
/// RFC 8259 section 4 says names SHOULD be unique and leaves duplicates to the reader.
/// Two readers that pick different duplicates see two different messages.
/// The engine API is authenticated and consensus critical, so Axiom refuses the ambiguity.
const REJECTED_BY_DESIGN: &[(&str, usize, &str)] = &[
    ("y_object_duplicated_key.json", 9, "a"),
    ("y_object_duplicated_key_and_value.json", 9, "a"),
];

/// Every i_ file of the corpus with Axiom's pinned outcome.
///
/// Numbers keep their exact text, so no size or exponent overflows at parse time.
/// A float view of an out-of-range number declines instead, checked separately.
///
/// Strings must be valid UTF-8 and hold scalar values only.
/// A lone or misordered surrogate escape cannot live in a Rust string, so it fails at its backslash.
/// Overlong, truncated, or out-of-range UTF-8 fails at the string's first content byte.
///
/// UTF-16 input and a UTF-8 byte order mark are refused at their first byte.
/// RFC 8259 section 8.1 requires UTF-8 and forbids a sender from adding a mark.
///
/// Default limits cap nesting at 128, so 500 nested arrays fail at the 129th bracket.
fn implementation_choices() -> Vec<(&'static str, Choice)> {
    let lone = |offset, unit| Choice::Reject(offset, ErrorKind::LoneSurrogate(unit));
    let utf8 = |offset| Choice::Reject(offset, ErrorKind::InvalidUtf8);
    let byte = |offset, value| Choice::Reject(offset, ErrorKind::UnexpectedByte(value));
    vec![
        ("i_number_double_huge_neg_exp.json", Choice::Accept),
        ("i_number_huge_exp.json", Choice::Accept),
        ("i_number_neg_int_huge_exp.json", Choice::Accept),
        ("i_number_pos_double_huge_exp.json", Choice::Accept),
        ("i_number_real_neg_overflow.json", Choice::Accept),
        ("i_number_real_pos_overflow.json", Choice::Accept),
        ("i_number_real_underflow.json", Choice::Accept),
        ("i_number_too_big_neg_int.json", Choice::Accept),
        ("i_number_too_big_pos_int.json", Choice::Accept),
        ("i_number_very_big_negative_int.json", Choice::Accept),
        ("i_object_key_lone_2nd_surrogate.json", lone(2, 0xdfaa)),
        (
            "i_string_1st_surrogate_but_2nd_missing.json",
            lone(2, 0xdada),
        ),
        (
            "i_string_1st_valid_surrogate_2nd_invalid.json",
            lone(2, 0xd888),
        ),
        ("i_string_UTF-16LE_with_BOM.json", byte(0, 0xff)),
        ("i_string_UTF-8_invalid_sequence.json", utf8(7)),
        ("i_string_UTF8_surrogate_U+D800.json", utf8(2)),
        (
            "i_string_incomplete_surrogate_and_escape_valid.json",
            lone(2, 0xd800),
        ),
        ("i_string_incomplete_surrogate_pair.json", lone(2, 0xdd1e)),
        (
            "i_string_incomplete_surrogates_escape_valid.json",
            lone(2, 0xd800),
        ),
        ("i_string_invalid_lonely_surrogate.json", lone(2, 0xd800)),
        ("i_string_invalid_surrogate.json", lone(2, 0xd800)),
        ("i_string_invalid_utf-8.json", utf8(2)),
        ("i_string_inverted_surrogates_U+1D11E.json", lone(2, 0xdd1e)),
        ("i_string_iso_latin_1.json", utf8(2)),
        ("i_string_lone_second_surrogate.json", lone(2, 0xdfaa)),
        ("i_string_lone_utf8_continuation_byte.json", utf8(2)),
        ("i_string_not_in_unicode_range.json", utf8(2)),
        ("i_string_overlong_sequence_2_bytes.json", utf8(2)),
        ("i_string_overlong_sequence_6_bytes.json", utf8(2)),
        ("i_string_overlong_sequence_6_bytes_null.json", utf8(2)),
        ("i_string_truncated-utf-8.json", utf8(2)),
        ("i_string_utf16BE_no_BOM.json", byte(0, 0x00)),
        ("i_string_utf16LE_no_BOM.json", byte(1, 0x00)),
        (
            "i_structure_500_nested_arrays.json",
            Choice::Reject(128, ErrorKind::TooDeep { limit: 128 }),
        ),
        ("i_structure_UTF-8_BOM_empty_object.json", byte(0, 0xef)),
    ]
}

/// The corpus directory, or nothing when it is absent and not required.
///
/// # Panics
///
/// Panics when the corpus is missing and AXIOM_REQUIRE_VECTORS is set, as in CI.
fn corpus_dir() -> Option<PathBuf> {
    let root = env::var_os("AXIOM_VECTORS").map(PathBuf::from).or_else(|| {
        // Vectors are gitignored, so a git worktree finds them in the main checkout above it.
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .map(|dir| dir.join("testing/vectors"))
            .find(|dir| dir.join("json-test-suite").is_dir())
    });
    let dir = root.map(|root| root.join("json-test-suite/test_parsing"));
    let found = dir.as_ref().is_some_and(|dir| dir.is_dir());
    assert!(
        found || env::var_os("AXIOM_REQUIRE_VECTORS").is_none(),
        "JSONTestSuite required but missing; run `make -C testing/ef-tests`"
    );
    dir.filter(|_| found)
}

/// Every file of the corpus as its name and bytes, sorted by name.
fn corpus(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(String, Vec<u8>)> = fs::read_dir(dir)
        .expect("corpus directory is readable")
        .map(|entry| {
            let path = entry.expect("directory entry is readable").path();
            let name = path
                .file_name()
                .expect("a directory entry has a name")
                .to_string_lossy()
                .into_owned();
            (name, fs::read(&path).expect("corpus file is readable"))
        })
        .collect();
    files.sort();
    files
}

/// The corpus files whose names start with a prefix, or nothing when the corpus is absent.
#[expect(
    clippy::print_stderr,
    reason = "the suite reports why it skipped to the test output"
)]
fn files_with_prefix(prefix: &str) -> Option<Vec<(String, Vec<u8>)>> {
    let Some(dir) = corpus_dir() else {
        eprintln!("skipping JSONTestSuite: corpus not found, run `make -C testing/ef-tests`");
        return None;
    };
    let files = corpus(&dir);
    assert_eq!(files.len(), CORPUS_SIZE, "corpus size");
    Some(
        files
            .into_iter()
            .filter(|(name, _)| name.starts_with(prefix))
            .collect(),
    )
}

#[test]
fn accepts_every_y_file() {
    let Some(files) = files_with_prefix("y_") else {
        return;
    };
    assert_eq!(files.len(), ACCEPT_COUNT);

    let mut accepted = 0_usize;
    let mut refused = 0_usize;
    for (name, input) in &files {
        let outcome = Json::parse(input);

        // The two duplicate-name files fail at the second "a", offset 9 in {"a":"b","a":...}.
        if let Some((_, offset, key)) = REJECTED_BY_DESIGN.iter().find(|(file, ..)| file == name) {
            let error = outcome.expect_err(name);
            assert_eq!(
                (error.offset(), error.kind()),
                (*offset, &ErrorKind::DuplicateKey((*key).to_owned())),
                "{name}"
            );
            refused += 1;
            continue;
        }

        // Every other y_ file parses, and its compact form parses back to the same value.
        let value = outcome.unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(Json::parse(value.to_string()), Ok(value), "{name}");
        accepted += 1;
    }

    // 93 files parse, 2 are refused by design, 95 in all.
    assert_eq!((accepted, refused), (93, REJECTED_BY_DESIGN.len()));
}

#[test]
fn rejects_every_n_file() {
    let Some(files) = files_with_prefix("n_") else {
        return;
    };
    assert_eq!(files.len(), REJECT_COUNT);

    // Each of the 188 files fails, at an offset inside the input or at its end.
    for (name, input) in &files {
        let error = Json::parse(input).expect_err(name);
        assert!(
            error.offset() <= input.len(),
            "{name}: offset {} beyond {} bytes",
            error.offset(),
            input.len()
        );
    }
}

#[test]
fn pins_every_i_file() {
    let Some(files) = files_with_prefix("i_") else {
        return;
    };
    let choices = implementation_choices();

    // The table names exactly the 35 i_ files of the corpus, no more and no fewer.
    let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
    let pinned: Vec<&str> = choices.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, pinned);
    assert_eq!(files.len() + ACCEPT_COUNT + REJECT_COUNT, CORPUS_SIZE);

    for ((name, input), (_, choice)) in files.iter().zip(&choices) {
        let actual = match Json::parse(input) {
            Ok(value) => {
                // An accepted number keeps its exact digits, so the compact form is the input.
                assert_eq!(
                    value.to_string().as_bytes(),
                    input.trim_ascii_end(),
                    "{name}"
                );
                Choice::Accept
            }
            Err(error) => Choice::Reject(error.offset(), error.kind().clone()),
        };
        assert_eq!(&actual, choice, "{name}");
    }
}

#[test]
fn huge_numbers_keep_their_text_but_decline_a_float() {
    // i_number_huge_exp: the exponent overflows a double.
    // The number parses with its text kept, and the float view returns nothing.
    let text = "0.4e00669999999999999999999999999999999999999999999999";
    let value = Json::parse(format!("[{text}]")).unwrap();
    let number = value.as_array().unwrap()[0].as_number().unwrap();
    assert_eq!((number.as_str(), number.as_f64()), (text, None));
}

#[test]
fn error_offsets_point_at_the_fault() {
    // Each case names the byte the parser stops at.
    //
    //     [1,,2]      second comma at offset 3
    //     [012]       the 1 after a lone zero at offset 2
    //     ["a\nb"]    raw line feed at offset 3
    //     [tru]       closing bracket where e belongs, offset 4
    //     [1          end of input at offset 2
    //     {"a" 1}     the 1 where a colon belongs, offset 5
    //     [] x        trailing x at offset 3
    let cases: [(&[u8], usize, ErrorKind); 7] = [
        (b"[1,,2]", 3, ErrorKind::UnexpectedByte(b',')),
        (b"[012]", 2, ErrorKind::InvalidNumber),
        (b"[\"a\nb\"]", 3, ErrorKind::ControlCharacter(b'\n')),
        (b"[tru]", 4, ErrorKind::UnexpectedByte(b']')),
        (b"[1", 2, ErrorKind::UnexpectedEnd),
        (b"{\"a\" 1}", 5, ErrorKind::UnexpectedByte(b'1')),
        (b"[] x", 3, ErrorKind::TrailingCharacters),
    ];
    for (input, offset, kind) in cases {
        let error = Json::parse(input).unwrap_err();
        assert_eq!((error.offset(), error.kind()), (offset, &kind));
    }
}

#[test]
fn limits_bound_depth_and_size() {
    // Depth 3 admits three nested arrays and refuses the fourth bracket at offset 3.
    let limits = Limits {
        max_depth: 3,
        max_bytes: 100,
    };
    assert!(Json::parse_with(b"[[[]]]", limits).is_ok());
    let error = Json::parse_with(b"[[[[]]]]", limits).unwrap_err();
    assert_eq!(
        (error.offset(), error.kind()),
        (3, &ErrorKind::TooDeep { limit: 3 })
    );

    // A 101-byte text breaks a 100-byte limit, reported at the limit.
    let long = format!("\"{}\"", "a".repeat(99));
    let error = Json::parse_with(&long, limits).unwrap_err();
    assert_eq!(
        (error.offset(), error.kind()),
        (
            100,
            &ErrorKind::TooLarge {
                length: 101,
                limit: 100
            }
        )
    );

    // A million nested brackets under a generous limit still return an error, not a crash.
    // The parser's own stack holds the open arrays, so the thread stack never grows.
    let deep = "[".repeat(1_000_000);
    let unbounded = Limits {
        max_depth: usize::MAX,
        max_bytes: usize::MAX,
    };
    let error = Json::parse_with(&deep, unbounded).unwrap_err();
    assert_eq!(
        (error.offset(), error.kind()),
        (1_000_000, &ErrorKind::UnexpectedEnd)
    );
}
