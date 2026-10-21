//! Block-style YAML output that parses back to the same node.

use std::fmt::{self, Display, Formatter, Write};

use crate::Yaml;

/// Spaces added per nesting level.
const STEP: usize = 2;

impl Display for Yaml {
    /// Writes the node as a block-style document ending in a newline.
    ///
    /// ```text
    /// key: value
    /// list:
    ///   - a
    ///   - k: v
    ///     j: "two words"
    /// empty: []
    /// ```
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write_block(f, self, 0, false)
    }
}

/// Writes a node in block style.
///
/// # Arguments
///
/// - `indent`: column of the node's entries.
/// - `compact`: whether the first line is already written up to the indent, as after "- ".
fn write_block(f: &mut Formatter<'_>, node: &Yaml, indent: usize, compact: bool) -> fmt::Result {
    match node {
        Yaml::Mapping(mapping) if !mapping.is_empty() => {
            for (i, (key, value)) in mapping.iter().enumerate() {
                // The first entry of a compact mapping shares the dash's line.
                if i > 0 || !compact {
                    pad(f, indent)?;
                }
                write_string(f, key)?;
                f.write_char(':')?;
                write_child(f, value, indent, false)?;
            }
            Ok(())
        }
        Yaml::Sequence(items) if !items.is_empty() => {
            for (i, item) in items.iter().enumerate() {
                if i > 0 || !compact {
                    pad(f, indent)?;
                }
                f.write_char('-')?;
                write_child(f, item, indent, true)?;
            }
            Ok(())
        }
        // Scalars and empty collections fit on one line.
        _ => {
            write_scalar(f, node)?;
            f.write_char('\n')
        }
    }
}

/// Writes what follows a key's colon or an entry's dash.
///
/// ```text
/// key:            dash:
///   nested: 1     - nested: 1     (compact, shares the dash's line)
/// ```
fn write_child(f: &mut Formatter<'_>, node: &Yaml, indent: usize, after_dash: bool) -> fmt::Result {
    let nested = match node {
        Yaml::Mapping(mapping) => !mapping.is_empty(),
        Yaml::Sequence(items) => !items.is_empty(),
        _ => false,
    };
    if nested && !after_dash {
        // A collection under a key starts on the next line, one step deeper.
        f.write_char('\n')?;
        write_block(f, node, indent + STEP, false)
    } else {
        // A scalar follows on the same line.
        // A collection after a dash starts compactly, its entries aligned past "- ".
        f.write_char(' ')?;
        write_block(f, node, indent + STEP, true)
    }
}

/// Writes a scalar or an empty collection on one line.
fn write_scalar(f: &mut Formatter<'_>, node: &Yaml) -> fmt::Result {
    match node {
        Yaml::Null => f.write_str("null"),
        Yaml::Bool(true) => f.write_str("true"),
        Yaml::Bool(false) => f.write_str("false"),
        Yaml::String(text) => write_string(f, text),
        Yaml::Sequence(_) => f.write_str("[]"),
        Yaml::Mapping(_) => f.write_str("{}"),
    }
}

/// Writes text plain when it reads back as the same text, double-quoted otherwise.
fn write_string(f: &mut Formatter<'_>, text: &str) -> fmt::Result {
    if is_plain_safe(text) {
        return f.write_str(text);
    }
    f.write_char('"')?;
    for c in text.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\t' => f.write_str("\\t")?,
            '\r' => f.write_str("\\r")?,
            // YAML 1.1 line breaks and the byte order mark get named escapes.
            '\u{85}' => f.write_str("\\N")?,
            '\u{2028}' => f.write_str("\\L")?,
            '\u{2029}' => f.write_str("\\P")?,
            '\u{feff}' => f.write_str("\\ufeff")?,
            // Other control characters, C0, DEL, and C1, as two hex digits.
            c if c.is_control() => write!(f, "\\x{:02x}", u32::from(c))?,
            c => f.write_char(c)?,
        }
    }
    f.write_char('"')
}

/// Whether text can be written without quotes and still read back as the same string.
///
/// The test is conservative: a letter or digit first, then a small safe alphabet.
/// Words the core schema resolves to null or a boolean must be quoted.
fn is_plain_safe(text: &str) -> bool {
    let bytes = text.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'/' | b'+'))
        && matches!(Yaml::from_plain(text.to_owned()), Yaml::String(_))
}

/// Writes the indentation of a line.
fn pad(f: &mut Formatter<'_>, indent: usize) -> fmt::Result {
    write!(f, "{:indent$}", "")
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::{Mapping, Yaml};

    fn string(text: &str) -> Yaml {
        Yaml::String(text.into())
    }

    #[test]
    fn writes_nested_blocks_compactly_after_dashes() {
        // Fixture: a mapping holding a sequence of one scalar and one mapping.
        let mut item = Mapping::new();
        item.insert("k", string("v"));
        item.insert("j", string("two words"));
        let mut root = Mapping::new();
        root.insert("key", string("value"));
        root.insert(
            "list",
            Yaml::Sequence(vec![string("a"), Yaml::Mapping(item)]),
        );
        root.insert("empty", Yaml::Sequence(vec![]));
        root.insert("none", Yaml::Null);
        let root = Yaml::Mapping(root);

        // The compact mapping's second key aligns with its first, past "- ".
        let expected = "\
key: value
list:
  - a
  - k: v
    j: \"two words\"
empty: []
none: null
";
        assert_eq!(root.to_string(), expected);
        assert_eq!(Yaml::parse(expected), Ok(root));
    }

    #[test]
    fn quotes_text_that_would_resolve_or_misparse() {
        // Plain only when unambiguous.
        assert_eq!(string("abc-1.0").to_string(), "abc-1.0\n");
        assert_eq!(string("0x1234").to_string(), "0x1234\n");

        // Words with core schema meaning, the empty string, and indicators get quotes.
        assert_eq!(string("true").to_string(), "\"true\"\n");
        assert_eq!(string("~").to_string(), "\"~\"\n");
        assert_eq!(string("").to_string(), "\"\"\n");
        assert_eq!(string("- a").to_string(), "\"- a\"\n");

        // Escapes for quotes, backslashes, breaks, and control bytes.
        assert_eq!(
            string("a\"b\\c\nd\u{1}").to_string(),
            "\"a\\\"b\\\\c\\nd\\x01\"\n"
        );
    }

    #[test]
    fn writes_nested_sequences_compactly() {
        // [[a, b], []] as a compact sequence of sequences.
        let value = Yaml::Sequence(vec![
            Yaml::Sequence(vec![string("a"), string("b")]),
            Yaml::Sequence(vec![]),
        ]);
        assert_eq!(value.to_string(), "- - a\n  - b\n- []\n");
    }

    /// Arbitrary nodes up to four levels deep.
    fn arb_yaml() -> impl Strategy<Value = Yaml> {
        let leaf = prop_oneof![
            Just(Yaml::Null),
            any::<bool>().prop_map(Yaml::Bool),
            any::<String>().prop_map(Yaml::String),
            "[a-z0-9 ._:#'\"-]{0,12}".prop_map(Yaml::String),
        ];
        leaf.prop_recursive(4, 64, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Yaml::Sequence),
                prop::collection::vec((any::<String>(), inner), 0..6).prop_map(|entries| {
                    let mut mapping = Mapping::new();
                    for (key, value) in entries {
                        mapping.insert(key, value);
                    }
                    Yaml::Mapping(mapping)
                }),
            ]
        })
    }

    proptest! {
        #[test]
        fn output_parses_back_to_the_same_node(value in arb_yaml()) {
            // Law: parse(display(v)) == v for every node.
            let text = value.to_string();
            prop_assert_eq!(Yaml::parse(&text), Ok(value), "text:\n{}", text);
        }
    }
}
