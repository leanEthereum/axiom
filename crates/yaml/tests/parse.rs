//! One test per supported construct, each asserting the whole parsed document.

use axiom_yaml::{Mapping, Yaml};

/// A string node.
fn s(text: &str) -> Yaml {
    Yaml::String(text.into())
}

/// A sequence node.
const fn seq(items: Vec<Yaml>) -> Yaml {
    Yaml::Sequence(items)
}

/// A mapping node, entries in the given order.
fn map(entries: Vec<(&str, Yaml)>) -> Yaml {
    let mut mapping = Mapping::new();
    for (key, value) in entries {
        mapping.insert(key, value);
    }
    Yaml::Mapping(mapping)
}

/// Parses text that must be valid.
fn parse(text: &str) -> Yaml {
    Yaml::parse(text).expect("text is valid YAML")
}

#[test]
fn nested_block_mappings() {
    // Three levels, two spaces each, with a scalar back at level one.
    let text = "\
a:
  b:
    c: 1
  d: x y
e: 2
";
    let expected = map(vec![
        (
            "a",
            map(vec![("b", map(vec![("c", s("1"))])), ("d", s("x y"))]),
        ),
        ("e", s("2")),
    ]);
    assert_eq!(parse(text), expected);
}

#[test]
fn indentless_sequence_under_a_key() {
    // The light-client proof shape: dashes at the key's own column.
    let text = "\
leaf_index: 25
branch:
- '0xaa'
- '0xbb'
after: 1
";
    let expected = map(vec![
        ("leaf_index", s("25")),
        ("branch", seq(vec![s("0xaa"), s("0xbb")])),
        ("after", s("1")),
    ]);
    assert_eq!(parse(text), expected);
}

#[test]
fn compact_mappings_and_sequences_after_dashes() {
    // The fork choice steps shape: a mapping starts on its dash's line.
    let text = "\
- tick: 6
  valid: false
- - a
  - b
- checks:
    head: {slot: 1}
";
    let expected = seq(vec![
        map(vec![("tick", s("6")), ("valid", Yaml::Bool(false))]),
        seq(vec![s("a"), s("b")]),
        map(vec![(
            "checks",
            map(vec![("head", map(vec![("slot", s("1"))]))]),
        )]),
    ]);
    assert_eq!(parse(text), expected);
}

#[test]
fn dash_alone_takes_the_deeper_block_or_null() {
    // A dash with nothing after it: the entry is the indented block below, or null.
    let text = "\
-
  k: v
-
- x
";
    let expected = seq(vec![map(vec![("k", s("v"))]), Yaml::Null, s("x")]);
    assert_eq!(parse(text), expected);
}

#[test]
fn empty_values_are_null() {
    // A key with nothing after it, at the end and before a sibling.
    let text = "a:\nb: ~\nc:\n";
    let expected = map(vec![
        ("a", Yaml::Null),
        ("b", Yaml::Null),
        ("c", Yaml::Null),
    ]);
    assert_eq!(parse(text), expected);
}

#[test]
fn multi_line_flow_sequence_with_ragged_indentation() {
    // The shuffling mapping shape: lines wrap at varying depths with trailing spaces.
    let text = "\
mapping: [1, 2,
    3,
  4, ]
";
    let expected = map(vec![("mapping", seq(vec![s("1"), s("2"), s("3"), s("4")]))]);
    assert_eq!(parse(text), expected);
}

#[test]
fn flow_mappings_nest_and_allow_missing_values() {
    // Flow mappings inside flow sequences, an implicit null, and an empty collection.
    let text = "{a: [{b: 1}, []], c, d: , e: 'x'}";
    let expected = map(vec![
        ("a", seq(vec![map(vec![("b", s("1"))]), seq(vec![])])),
        ("c", Yaml::Null),
        ("d", Yaml::Null),
        ("e", s("x")),
    ]);
    assert_eq!(parse(text), expected);
}

#[test]
fn colon_without_space_stays_inside_a_plain_scalar() {
    // "a:1" is one scalar in flow context, and "http://x" one in block context.
    assert_eq!(parse("{ a:1 }"), map(vec![("a:1", Yaml::Null)]));
    assert_eq!(parse("url: http://x"), map(vec![("url", s("http://x"))]));
}

#[test]
fn plain_scalars_fold_across_lines() {
    // The light-client update shape: the value starts on the next, deeper line.
    //
    //     one break   ->  space
    //     empty line  ->  newline
    let text = "\
update:
  part_one
  part two

  part three
next: 1
";
    let expected = map(vec![
        ("update", s("part_one part two\npart three")),
        ("next", s("1")),
    ]);
    assert_eq!(parse(text), expected);
}

#[test]
fn single_quotes_escape_by_doubling_and_fold() {
    // '' is one quote; a break folds to a space and leading spaces drop.
    let text = "a: 'it''s\n  here'\nb: ''\n";
    let expected = map(vec![("a", s("it's here")), ("b", s(""))]);
    assert_eq!(parse(text), expected);
}

#[test]
fn double_quotes_decode_every_escape_family() {
    // Named escapes, hex escapes of three widths, and an escaped line break.
    let text = r#"a: "\"q\" \\ \t\n\0 \x41\u00e9\U0001F600 \N\_\L\P \/ \e""#;
    let expected = map(vec![(
        "a",
        s("\"q\" \\ \t\n\0 A\u{e9}\u{1f600} \u{85}\u{a0}\u{2028}\u{2029} / \u{1b}"),
    )]);
    assert_eq!(parse(text), expected);

    // An escaped break joins lines with no space; an escaped tab survives folding.
    let text = "a: \"ab\\\n  cd \\t\n  ef\"";
    assert_eq!(parse(text), map(vec![("a", s("abcd \t ef"))]));
}

#[test]
fn comments_are_ignored_but_hashes_inside_words_are_content() {
    // Full-line, trailing, and in-flow comments, next to a hash that is not one.
    let text = "\
# header
a: 1  # trailing
b: x#y
c: [1, # inside
  2]
";
    let expected = map(vec![
        ("a", s("1")),
        ("b", s("x#y")),
        ("c", seq(vec![s("1"), s("2")])),
    ]);
    assert_eq!(parse(text), expected);
}

#[test]
fn document_markers_and_top_level_scalars() {
    // The sanity slots shape: a bare scalar, then an end marker.
    assert_eq!(parse("8\n...\n"), s("8"));
    assert_eq!(parse("true\n...\n"), Yaml::Bool(true));

    // An explicit start, with the root on the next line or on the marker's line.
    assert_eq!(parse("---\na: 1\n"), map(vec![("a", s("1"))]));
    assert_eq!(parse("--- [1]\n"), seq(vec![s("1")]));

    // No content at all is a null document.
    assert_eq!(parse(""), Yaml::Null);
    assert_eq!(parse("# only a comment\n"), Yaml::Null);
}

#[test]
fn top_level_flow_mapping() {
    // The meta.yaml shape.
    assert_eq!(
        parse("{blocks_count: 24}\n"),
        map(vec![("blocks_count", s("24"))])
    );
}

#[test]
fn quoted_keys_and_quoted_core_words() {
    // Quoted text never resolves: 'true' and "null" stay strings.
    let text = "'k 1': 'true'\n\"k2\": \"null\"\n";
    let expected = map(vec![("k 1", s("true")), ("k2", s("null"))]);
    assert_eq!(parse(text), expected);
}

#[test]
fn crlf_line_breaks_and_byte_order_mark() {
    // Windows line breaks and a leading BOM read like plain newlines.
    let text = "\u{feff}a: 1\r\nb:\r\n- 2\r\n";
    let expected = map(vec![("a", s("1")), ("b", seq(vec![s("2")]))]);
    assert_eq!(parse(text), expected);
}

#[test]
fn tabs_separate_tokens_after_the_indentation() {
    // A tab after the colon is whitespace, not indentation.
    assert_eq!(parse("a:\t1\n"), map(vec![("a", s("1"))]));
}
