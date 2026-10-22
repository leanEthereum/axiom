//! Block and flow structure, built on the scanner's scalars.

use crate::{ErrorKind, Mapping, ParseError, Unsupported, Yaml, scanner::Scanner};

/// Deepest nesting of collections the parser accepts.
///
/// Recursion follows nesting, so the bound caps stack use on hostile input.
/// Consensus vectors nest fewer than 16 levels.
const MAX_DEPTH: usize = 128;

/// Indentation of the virtual block around the root node.
///
/// Every real line sits at column 0 or deeper, so all of them are inside it.
const ROOT: isize = -1;

/// A recursive-descent parser over one document.
#[derive(Debug)]
pub(crate) struct Parser<'a> {
    /// Position in the text.
    scanner: Scanner<'a>,
    /// Number of collections currently open.
    depth: usize,
}

impl<'a> Parser<'a> {
    /// A parser at the start of the text.
    pub(crate) fn new(text: &'a str) -> Self {
        Self {
            scanner: Scanner::new(text),
            depth: 0,
        }
    }

    /// Parses the single document of the text.
    ///
    /// ```text
    /// [comments]  [---]  [root node]  [...]  [comments]
    /// ```
    pub(crate) fn document(mut self) -> Result<Yaml, ParseError> {
        self.scanner.skip_trivia()?;

        // Directives such as %YAML would change how the rest is read.
        if self.scanner.peek() == Some(b'%') && self.scanner.indent() == 0 {
            return Err(self.unsupported(Unsupported::Directive));
        }

        let root = if self.scanner.at_document_marker() && !self.scanner.at_document_end() {
            // Explicit start "---": a root on the same line can only be a flow node or scalar.
            for _ in 0..3 {
                self.scanner.bump();
            }
            self.scanner.skip_blanks();
            if self.scanner.at_line_end() {
                self.scanner.skip_trivia()?;
                self.root()?
            } else {
                let value = self.inline(ROOT)?;
                self.scanner.end_line()?;
                value
            }
        } else {
            self.root()?
        };

        // Optional end marker "...", which only comments may follow.
        if self.scanner.at_document_end() {
            for _ in 0..3 {
                self.scanner.bump();
            }
            self.scanner.end_line()?;
            if !self.scanner.at_end() {
                return Err(self.unsupported(Unsupported::MultipleDocuments));
            }
        }

        // Anything left is either a second document or a line outside the root's block.
        if self.scanner.at_end() {
            Ok(root)
        } else if self.scanner.at_document_marker() {
            Err(self.unsupported(Unsupported::MultipleDocuments))
        } else {
            Err(self.scanner.error(ErrorKind::InvalidIndentation))
        }
    }

    /// The root node, or null for a document without one.
    fn root(&mut self) -> Result<Yaml, ParseError> {
        if self.scanner.at_end() || self.scanner.at_document_marker() {
            Ok(Yaml::Null)
        } else {
            self.node(ROOT)
        }
    }

    /// An error for a construct outside the supported subset, at the current position.
    fn unsupported(&self, feature: Unsupported) -> ParseError {
        self.scanner.error(ErrorKind::Unsupported(feature))
    }

    /// Opens one level of nesting, failing past the depth bound.
    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.scanner.error(ErrorKind::TooDeep { limit: MAX_DEPTH }));
        }
        Ok(())
    }

    /// Whether a block sequence entry, `-` then whitespace, starts here.
    fn at_block_entry(&self) -> bool {
        self.scanner.peek() == Some(b'-') && self.scanner.blank_or_end_at(1)
    }

    /// Whether the current line starts with an implicit key: a scalar, then `:` and whitespace.
    ///
    /// The check is pure lookahead on a copy of the scanner.
    fn at_implicit_key(&self) -> bool {
        let mut ahead = self.scanner;
        let parsed = match ahead.peek() {
            Some(b'\'') => ahead.single_quoted(ROOT).is_ok(),
            Some(b'"') => ahead.double_quoted(ROOT).is_ok(),
            _ if ahead.can_start_plain(false) => {
                ahead.plain_key(false);
                true
            }
            _ => false,
        };
        if !parsed {
            return false;
        }

        // A key fits on one line, so the colon must follow on the line it started.
        let mut start = self.scanner;
        start.skip_blanks();
        ahead.skip_blanks();
        ahead.at_value_colon(false) && start.line() == ahead.line()
    }

    /// A node in block context whose first character is at the current position.
    ///
    /// # Arguments
    ///
    /// - `parent`: indentation of the enclosing block.
    ///
    /// The node's own column decides the indentation of a collection it opens.
    fn node(&mut self, parent: isize) -> Result<Yaml, ParseError> {
        let indent = self.scanner.indent();
        if self.at_block_entry() {
            self.block_sequence(indent)
        } else if self.at_implicit_key() {
            self.block_mapping(indent)
        } else {
            let value = self.inline(parent)?;
            self.scanner.end_line()?;
            Ok(value)
        }
    }

    /// A block sequence whose entries start at the given column.
    ///
    /// ```text
    /// - a          entry at column 0
    /// - k: v       compact mapping, its keys at column 2
    ///   j: w
    /// - - x        compact sequence, its entries at column 2
    ///   - y
    /// -            empty line after the indicator:
    ///   b          the entry is the deeper block below
    /// ```
    fn block_sequence(&mut self, indent: usize) -> Result<Yaml, ParseError> {
        self.enter()?;
        let mut items = Vec::new();
        loop {
            // Step over "-" and the whitespace after it.
            self.scanner.bump();
            self.scanner.skip_blanks();
            items.push(self.entry_value(indent, false)?);

            // The next entry must start at the same column with another "-".
            if !self.continues_block(indent)? || !self.at_block_entry() {
                break;
            }
        }
        self.depth -= 1;
        Ok(Yaml::Sequence(items))
    }

    /// A block mapping whose keys start at the given column.
    ///
    /// ```text
    /// a: 1         scalar on the key's line
    /// b:           nothing on the key's line:
    ///   c: 2       a deeper block is the value
    /// d:
    /// - 3          a sequence at the key's column is the value too
    /// e:           nothing at all: null
    /// ```
    fn block_mapping(&mut self, indent: usize) -> Result<Yaml, ParseError> {
        self.enter()?;
        let mut mapping = Mapping::new();
        loop {
            // Each line at the mapping's column must open with a key and a colon.
            if !self.at_implicit_key() {
                return Err(self.scanner.error(ErrorKind::ExpectedKey));
            }
            let key_at = self.scanner;
            let key = self.key(false)?;
            self.scanner.bump();
            self.scanner.skip_blanks();
            let value = self.entry_value(indent, true)?;
            if mapping.insert(key.clone(), value).is_some() {
                return Err(key_at.error(ErrorKind::DuplicateKey(key)));
            }

            // Stop at a shallower line, the end, or a document marker.
            if !self.continues_block(indent)? {
                break;
            }
        }
        self.depth -= 1;
        Ok(Yaml::Mapping(mapping))
    }

    /// Decides, after an entry, whether the next line continues the same block.
    ///
    /// A deeper line is an error, since no entry is open to take it.
    fn continues_block(&self, indent: usize) -> Result<bool, ParseError> {
        if self.scanner.at_end() || self.scanner.at_document_marker() {
            return Ok(false);
        }
        let column = self.scanner.indent();
        if column > indent {
            return Err(self.scanner.error(ErrorKind::InvalidIndentation));
        }
        Ok(column == indent)
    }

    /// The value after a mapping's colon or a sequence's dash.
    ///
    /// # Arguments
    ///
    /// - `indent`: column of the key or dash.
    /// - `in_mapping`: whether a sequence at the key's own column may be the value.
    fn entry_value(&mut self, indent: usize, in_mapping: bool) -> Result<Yaml, ParseError> {
        let parent = indent.cast_signed();
        if !self.scanner.at_line_end() {
            // Content on the same line.
            return if in_mapping {
                self.same_line_value(parent)
            } else {
                // After a dash, a sequence or a mapping may start compactly on the same line.
                self.node(parent)
            };
        }

        // Nothing on this line: the value is the next block, if one is deep enough.
        self.scanner.skip_trivia()?;
        if self.scanner.at_end() || self.scanner.at_document_marker() {
            return Ok(Yaml::Null);
        }
        let column = self.scanner.indent();
        if column > indent {
            self.node(parent)
        } else if in_mapping && column == indent && self.at_block_entry() {
            // YAML lets a mapping's sequence value sit at the key's own column.
            //
            //     branch:
            //     - 0xab
            //     - 0xcd
            self.block_sequence(indent)
        } else {
            Ok(Yaml::Null)
        }
    }

    /// A mapping value that starts on the line of its key.
    ///
    /// Only a scalar or a flow collection may start there.
    fn same_line_value(&mut self, parent: isize) -> Result<Yaml, ParseError> {
        if self.at_block_entry() {
            return Err(self.scanner.error(ErrorKind::UnexpectedBlockEntry));
        }
        if self.at_implicit_key() {
            // A key on the key's line, as in "a: b: c".
            let mut colon = self.scanner;
            colon.plain_key(false);
            colon.skip_blanks();
            return Err(colon.error(ErrorKind::UnexpectedMappingValue));
        }
        let value = self.inline(parent)?;
        self.scanner.end_line()?;
        Ok(value)
    }

    /// A key: a quoted scalar or a single-line plain scalar, without its colon.
    fn key(&mut self, flow: bool) -> Result<String, ParseError> {
        let key = match self.scanner.peek() {
            Some(b'\'') => self.scanner.single_quoted(ROOT)?,
            Some(b'"') => self.scanner.double_quoted(ROOT)?,
            Some(b'[' | b'{') => return Err(self.unsupported(Unsupported::CollectionKey)),
            Some(b'?') if self.scanner.blank_or_end_at(1) => {
                return Err(self.unsupported(Unsupported::ComplexKey));
            }
            _ if self.scanner.can_start_plain(flow) => self.scanner.plain_key(flow).to_owned(),
            _ => return Err(self.indicator_error(flow)),
        };
        self.scanner.skip_blanks();
        Ok(key)
    }

    /// A scalar or flow collection, which may span lines deeper than the parent block.
    fn inline(&mut self, parent: isize) -> Result<Yaml, ParseError> {
        match self.scanner.peek() {
            Some(b'[') => self.flow_sequence(parent),
            Some(b'{') => self.flow_mapping(parent),
            Some(b'\'') => self.scanner.single_quoted(parent).map(Yaml::String),
            Some(b'"') => self.scanner.double_quoted(parent).map(Yaml::String),
            _ if self.scanner.can_start_plain(false) => {
                let value = self.scanner.plain(parent, false)?;
                // A colon after a value turns it into a key, which is not allowed here.
                self.scanner.skip_blanks();
                if self.scanner.at_value_colon(false) {
                    return Err(self.scanner.error(ErrorKind::UnexpectedMappingValue));
                }
                Ok(Yaml::from_plain(value))
            }
            _ => Err(self.indicator_error(false)),
        }
    }

    /// The error for a character that starts no supported node.
    fn indicator_error(&self, flow: bool) -> ParseError {
        let blank_after = self.scanner.blank_or_end_at(1);
        match self.scanner.peek() {
            Some(b'&') => self.unsupported(Unsupported::Anchor),
            Some(b'*') => self.unsupported(Unsupported::Alias),
            Some(b'!') => self.unsupported(Unsupported::Tag),
            Some(b'|' | b'>') => self.unsupported(Unsupported::BlockScalar),
            Some(b'%') => self.unsupported(Unsupported::Directive),
            Some(b'?') if blank_after => self.unsupported(Unsupported::ComplexKey),
            Some(b'-') if blank_after && !flow => {
                self.scanner.error(ErrorKind::UnexpectedBlockEntry)
            }
            _ => self.scanner.unexpected_char(),
        }
    }

    /// A flow node: a nested flow collection or a scalar.
    fn flow_node(&mut self, parent: isize) -> Result<Yaml, ParseError> {
        match self.scanner.peek() {
            Some(b'[') => self.flow_sequence(parent),
            Some(b'{') => self.flow_mapping(parent),
            Some(b'\'') => self.scanner.single_quoted(parent).map(Yaml::String),
            Some(b'"') => self.scanner.double_quoted(parent).map(Yaml::String),
            _ if self.scanner.can_start_plain(true) => {
                self.scanner.plain(parent, true).map(Yaml::from_plain)
            }
            _ => Err(self.indicator_error(true)),
        }
    }

    /// A flow sequence such as `[1, 'a', [b]]`, with an optional trailing comma.
    fn flow_sequence(&mut self, parent: isize) -> Result<Yaml, ParseError> {
        self.enter()?;
        let open = self.scanner;
        self.scanner.bump();
        let mut items = Vec::new();
        loop {
            self.scanner.skip_flow_trivia(parent)?;
            match self.scanner.peek() {
                None => return Err(open.error(ErrorKind::UnterminatedFlow)),
                Some(b']') => break,
                Some(_) => {}
            }
            items.push(self.flow_node(parent)?);

            // After an item: a comma, the closing bracket, or an error.
            self.scanner.skip_flow_trivia(parent)?;
            match self.scanner.peek() {
                None => return Err(open.error(ErrorKind::UnterminatedFlow)),
                Some(b',') => self.scanner.bump(),
                Some(b']') => break,
                Some(b':') => return Err(self.unsupported(Unsupported::FlowPair)),
                Some(_) => return Err(self.scanner.unexpected_char()),
            }
        }
        // Step over "]".
        self.scanner.bump();
        self.depth -= 1;
        Ok(Yaml::Sequence(items))
    }

    /// A flow mapping such as `{a: 1, b: [2]}`, where a missing value is null.
    fn flow_mapping(&mut self, parent: isize) -> Result<Yaml, ParseError> {
        self.enter()?;
        let open = self.scanner;
        self.scanner.bump();
        let mut mapping = Mapping::new();
        loop {
            self.scanner.skip_flow_trivia(parent)?;
            match self.scanner.peek() {
                None => return Err(open.error(ErrorKind::UnterminatedFlow)),
                Some(b'}') => break,
                Some(_) => {}
            }

            // Key, then an optional ":" and value.
            //
            //     {a: 1}   ->  a = "1"
            //     {a:, b}  ->  a = null, b = null
            let key_at = self.scanner;
            let key = self.key(true)?;
            self.scanner.skip_flow_trivia(parent)?;
            let value = if self.scanner.peek() == Some(b':') {
                self.scanner.bump();
                self.scanner.skip_flow_trivia(parent)?;
                match self.scanner.peek() {
                    Some(b',' | b'}') => Yaml::Null,
                    _ => self.flow_node(parent)?,
                }
            } else {
                Yaml::Null
            };
            if mapping.insert(key.clone(), value).is_some() {
                return Err(key_at.error(ErrorKind::DuplicateKey(key)));
            }

            self.scanner.skip_flow_trivia(parent)?;
            match self.scanner.peek() {
                None => return Err(open.error(ErrorKind::UnterminatedFlow)),
                Some(b',') => self.scanner.bump(),
                Some(b'}') => break,
                Some(_) => return Err(self.scanner.unexpected_char()),
            }
        }
        // Step over "}".
        self.scanner.bump();
        self.depth -= 1;
        Ok(Yaml::Mapping(mapping))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use crate::{ErrorKind, Mapping, Unsupported, Yaml};

    /// A string node.
    pub(crate) fn s(text: &str) -> Yaml {
        Yaml::String(text.into())
    }

    /// A sequence node.
    pub(crate) const fn seq(items: Vec<Yaml>) -> Yaml {
        Yaml::Sequence(items)
    }

    /// A mapping node, entries in the given order.
    pub(crate) fn map(entries: Vec<(&str, Yaml)>) -> Yaml {
        let mut mapping = Mapping::new();
        for (key, value) in entries {
            mapping.insert(key, value);
        }
        Yaml::Mapping(mapping)
    }

    /// Parses text that must be valid.
    pub(crate) fn parse(text: &str) -> Yaml {
        Yaml::parse(text).expect("text is valid YAML")
    }

    /// Parses text that must fail and returns its kind, line, and column.
    pub(crate) fn fail(text: &str) -> (ErrorKind, usize, usize) {
        let err = Yaml::parse(text).expect_err("text is invalid YAML");
        (err.kind().clone(), err.line(), err.column())
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
    fn unterminated_flow_points_at_the_opening_bracket() {
        assert_eq!(fail("a: [1, 2\n"), (ErrorKind::UnterminatedFlow, 1, 4));
        assert_eq!(fail("{a: 1"), (ErrorKind::UnterminatedFlow, 1, 1));
    }

    #[test]
    fn nesting_beyond_the_depth_bound() {
        // 200 open brackets: the 129th crosses the bound of 128.
        let text = "[".repeat(200);
        assert_eq!(fail(&text), (ErrorKind::TooDeep { limit: 128 }, 1, 129));
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
    }
}
