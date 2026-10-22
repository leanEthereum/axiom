//! One test per rejection, each asserting the exact kind, line, and column.

use axiom_yaml::{ErrorKind, Unsupported, Yaml};
use proptest::prelude::*;

/// Parses text that must fail and returns its kind, line, and column.
fn fail(text: &str) -> (ErrorKind, usize, usize) {
    let err = Yaml::parse(text).expect_err("text is invalid YAML");
    (err.kind().clone(), err.line(), err.column())
}

#[test]
fn tab_in_indentation() {
    // The tab sits where the nested key's indentation should be.
    //
    //     a:
    //     \tb: 1    <- line 2, column 1
    assert_eq!(fail("a:\n\tb: 1\n"), (ErrorKind::TabIndentation, 2, 1));
}

#[test]
fn deeper_line_after_a_complete_entry() {
    // A quoted value is complete, so nothing may sit deeper below it.
    assert_eq!(
        fail("a: 'x'\n  b: 2\n"),
        (ErrorKind::InvalidIndentation, 2, 3)
    );

    // A line shallower than the root block fits no block at all.
    assert_eq!(
        fail("  a: 1\nb: 2\n"),
        (ErrorKind::InvalidIndentation, 2, 1)
    );
}

#[test]
fn line_without_a_key_inside_a_mapping() {
    // "b" sits at the mapping's column but has no colon.
    assert_eq!(fail("a: 1\nb\n"), (ErrorKind::ExpectedKey, 2, 1));
}

#[test]
fn key_inside_a_value() {
    // The second colon on the line would make "b" a key.
    //
    //     a: b: c
    //         ^ column 5
    assert_eq!(fail("a: b: c\n"), (ErrorKind::UnexpectedMappingValue, 1, 5));

    // A continuation line cannot turn a multi-line scalar into a key.
    assert_eq!(
        fail("a: b\n  c: d\n"),
        (ErrorKind::UnexpectedMappingValue, 2, 4)
    );
}

#[test]
fn sequence_entry_on_a_key_line() {
    // Block sequences start on their own line.
    assert_eq!(fail("a: - b\n"), (ErrorKind::UnexpectedBlockEntry, 1, 4));
}

#[test]
fn duplicate_keys_in_block_and_flow_mappings() {
    // The error points at the second occurrence.
    let dup = ErrorKind::DuplicateKey("a".into());
    assert_eq!(fail("a: 1\na: 2\n"), (dup.clone(), 2, 1));
    assert_eq!(fail("{a: 1, a: 2}"), (dup, 1, 8));
}

#[test]
fn unterminated_quotes_point_at_the_opening_quote() {
    assert_eq!(fail("a: 'abc\n"), (ErrorKind::UnterminatedQuote, 1, 4));
    assert_eq!(fail("a: \"abc"), (ErrorKind::UnterminatedQuote, 1, 4));
}

#[test]
fn unterminated_flow_points_at_the_opening_bracket() {
    assert_eq!(fail("a: [1, 2\n"), (ErrorKind::UnterminatedFlow, 1, 4));
    assert_eq!(fail("{a: 1"), (ErrorKind::UnterminatedFlow, 1, 1));
}

#[test]
fn bad_escapes() {
    // An unknown letter, a short hex escape, and a surrogate.
    assert_eq!(fail(r#""\q""#), (ErrorKind::InvalidEscape('q'), 1, 2));
    assert_eq!(fail(r#""\x4""#), (ErrorKind::InvalidEscape('x'), 1, 2));
    assert_eq!(
        fail(r#""\ud800""#),
        (ErrorKind::InvalidCodePoint(0xd800), 1, 2)
    );
}

#[test]
fn unexpected_characters_in_flow_and_block() {
    // A closing brace where a sequence item should start.
    assert_eq!(fail("a: [1, }]"), (ErrorKind::UnexpectedChar('}'), 1, 8));

    // Two flow items without a comma.
    assert_eq!(fail("[[1] [2]]"), (ErrorKind::UnexpectedChar('['), 1, 6));

    // Reserved indicators cannot start a scalar.
    assert_eq!(fail("a: @b"), (ErrorKind::UnexpectedChar('@'), 1, 4));
}

#[test]
fn content_after_a_complete_value() {
    // The quoted scalar ends the value; "y" is left over.
    assert_eq!(fail("a: 'x' y\n"), (ErrorKind::TrailingContent, 1, 8));

    // A flow collection followed by a colon would be a collection key.
    assert_eq!(fail("[a]: b\n"), (ErrorKind::TrailingContent, 1, 4));
}

#[test]
fn document_marker_inside_quotes_or_flow() {
    // A marker at column 0 cannot hide inside a scalar or a collection.
    assert_eq!(
        fail("'a\n--- b'"),
        (ErrorKind::UnexpectedDocumentMarker, 2, 1)
    );
    assert_eq!(
        fail("[a,\n--- ]"),
        (ErrorKind::UnexpectedDocumentMarker, 2, 1)
    );
}

#[test]
fn nesting_beyond_the_depth_bound() {
    // 200 open brackets: the 129th crosses the bound of 128.
    let text = "[".repeat(200);
    assert_eq!(fail(&text), (ErrorKind::TooDeep, 1, 129));
}

#[test]
fn unsupported_features_are_named() {
    // Each feature is rejected where it starts.
    let cases = [
        ("a: &x 1", Unsupported::Anchor, 1, 4),
        ("a: *x", Unsupported::Alias, 1, 4),
        ("a: !!str 1", Unsupported::Tag, 1, 4),
        ("a: |\n  x\n", Unsupported::BlockScalar, 1, 4),
        ("%YAML 1.2\n---\na: 1\n", Unsupported::Directive, 1, 1),
        ("? a\n: b\n", Unsupported::ComplexKey, 1, 1),
        ("a: 1\n---\nb: 2\n", Unsupported::MultipleDocuments, 2, 1),
        ("a: 1\n...\nb: 2\n", Unsupported::MultipleDocuments, 3, 1),
        ("[a: 1]", Unsupported::FlowPair, 1, 3),
        ("{[a]: 1}", Unsupported::CollectionKey, 1, 2),
    ];
    for (text, feature, line, column) in cases {
        assert_eq!(
            fail(text),
            (ErrorKind::Unsupported(feature), line, column),
            "{text:?}"
        );
    }
}

#[test]
fn display_names_the_position_and_the_rule() {
    let err = Yaml::parse("a: 1\na: 2\n").unwrap_err();
    assert_eq!(
        err.to_string(),
        "line 2, column 1: duplicate mapping key \"a\""
    );

    let err = Yaml::parse("a: &x 1").unwrap_err();
    assert_eq!(
        err.to_string(),
        "line 1, column 4: anchors are not supported"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20_000))]

    #[test]
    fn garbage_never_panics(text in "[ \n\r\t:,#'\"\\\\\\[\\]{}&*!|>%?@`.~a-c0-9-]{0,48}") {
        // Law: any text over the indicator alphabet parses or fails, never panics.
        //
        // Positions in an error stay inside the text.
        if let Err(err) = Yaml::parse(&text) {
            prop_assert!(err.line() >= 1 && err.line() <= text.split(['\n', '\r']).count());
            prop_assert!(err.column() >= 1);
        }
    }

    #[test]
    fn arbitrary_unicode_never_panics(text in any::<String>()) {
        // Law: multi-byte characters never split a slice inside the scanner.
        let _ = Yaml::parse(&text);
    }
}
