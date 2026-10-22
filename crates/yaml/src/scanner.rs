//! Character-level reading of YAML text: positions, whitespace, comments, and scalars.

use std::iter;

use crate::{ErrorKind, ParseError, char_class::CharClass};

/// A position in the text, with the bookkeeping to report lines and columns.
///
/// It is `Copy`, so lookahead is a copy that is dropped or kept.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Scanner<'a> {
    /// The whole text.
    src: &'a str,
    /// Byte offset of the next unread character.
    pos: usize,
    /// Zero-based number of the current line.
    line: usize,
    /// Byte offset where the current line starts.
    line_start: usize,
}

impl<'a> Scanner<'a> {
    /// A scanner at the start of the text, past a leading byte order mark.
    pub(crate) fn new(src: &'a str) -> Self {
        // The byte order mark is three bytes in UTF-8 and is not content.
        let pos = if src.starts_with('\u{feff}') { 3 } else { 0 };
        Self {
            src,
            pos,
            line: 0,
            line_start: pos,
        }
    }

    /// The next byte, if any.
    pub(crate) fn peek(&self) -> Option<u8> {
        self.src.as_bytes().get(self.pos).copied()
    }

    /// The byte a given distance past the next one, if any.
    pub(crate) fn peek_at(&self, distance: usize) -> Option<u8> {
        self.src.as_bytes().get(self.pos + distance).copied()
    }

    /// Zero-based number of the current line.
    pub(crate) const fn line(&self) -> usize {
        self.line
    }

    /// Whether the whole text has been read.
    pub(crate) const fn at_end(&self) -> bool {
        self.pos >= self.src.len()
    }

    /// Whether the next byte is whitespace, a line break, or the end, after a given distance.
    pub(crate) fn blank_or_end_at(&self, distance: usize) -> bool {
        self.peek_at(distance)
            .is_none_or(|byte| CharClass::of(byte).is_space())
    }

    /// Whether the next bytes end the line, possibly after a comment.
    pub(crate) fn at_line_end(&self) -> bool {
        match self.peek() {
            Some(b'#') => self.preceded_by_blank(),
            Some(byte) => CharClass::of(byte).is_break(),
            None => true,
        }
    }

    /// Whether the next byte opens the line or follows whitespace.
    ///
    /// A `#` starts a comment only in that position.
    const fn preceded_by_blank(&self) -> bool {
        self.pos == self.line_start || CharClass::of(self.src.as_bytes()[self.pos - 1]).is_white()
    }

    /// Byte distance from the start of the line, which is the indentation at a line's content.
    ///
    /// Structural characters are ASCII, so bytes and characters agree wherever it matters.
    pub(crate) const fn indent(&self) -> usize {
        self.pos - self.line_start
    }

    /// Steps over one non-break ASCII byte.
    pub(crate) const fn bump(&mut self) {
        self.pos += 1;
    }

    /// Steps over one non-break character and returns it.
    fn bump_char(&mut self) -> Option<char> {
        let c = self.src[self.pos..].chars().next()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    /// An error of the given kind at the current position.
    pub(crate) fn error(&self, kind: ErrorKind) -> ParseError {
        // Columns count characters, so multi-byte text reports what an editor shows.
        let column = self.src[self.line_start..self.pos].chars().count() + 1;
        ParseError {
            line: self.line + 1,
            column,
            kind,
        }
    }

    /// An error naming the character at the current position.
    pub(crate) fn unexpected_char(&self) -> ParseError {
        // The scanner never stops inside a character, so the slice is valid.
        match self.src[self.pos..].chars().next() {
            Some(c) => self.error(ErrorKind::UnexpectedChar(c)),
            None => self.error(ErrorKind::TrailingContent),
        }
    }

    /// Consumes one line break, treating `\r\n` as one, and reports whether there was one.
    fn consume_break(&mut self) -> bool {
        match self.peek() {
            Some(b'\r') => {
                self.pos += 1;
                if self.peek() == Some(b'\n') {
                    self.pos += 1;
                }
            }
            Some(b'\n') => self.pos += 1,
            _ => return false,
        }
        self.line += 1;
        self.line_start = self.pos;
        true
    }

    /// Skips spaces and tabs within the line.
    pub(crate) fn skip_blanks(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| CharClass::of(byte).is_white())
        {
            self.pos += 1;
        }
    }

    /// Whether a document marker, `---` or `...`, starts at the current position.
    ///
    /// A marker sits at column 0 and is followed by whitespace or the end.
    pub(crate) fn at_document_marker(&self) -> bool {
        let rest = &self.src.as_bytes()[self.pos..];
        self.pos == self.line_start
            && (rest.starts_with(b"---") || rest.starts_with(b"..."))
            && self.blank_or_end_at(3)
    }

    /// Whether the end marker `...` starts at the current position.
    pub(crate) fn at_document_end(&self) -> bool {
        self.at_document_marker() && self.peek() == Some(b'.')
    }

    /// Skips whitespace, comments, and line breaks up to the next content or the end.
    ///
    /// Indentation must be spaces.
    /// A tab before the first content of a line is an error.
    pub(crate) fn skip_trivia(&mut self) -> Result<(), ParseError> {
        loop {
            self.skip_blanks();
            match self.peek() {
                None => return Ok(()),
                Some(b'#') if self.preceded_by_blank() => self.skip_comment(),
                Some(byte) if CharClass::of(byte).is_break() => {
                    self.consume_break();
                }
                Some(_) => {
                    // Content reached: its indentation, if any, must hold no tab.
                    //
                    //     "  \tkey: 1"  ->  tab inside the indentation  ->  error
                    //     "- \tvalue"   ->  tab after an indicator      ->  fine
                    let prefix = &self.src.as_bytes()[self.line_start..self.pos];
                    if let Some(tab) = prefix.iter().position(|&b| b == b'\t')
                        && prefix.iter().all(|&b| CharClass::of(b).is_white())
                    {
                        let mut at_tab = *self;
                        at_tab.pos = self.line_start + tab;
                        return Err(at_tab.error(ErrorKind::TabIndentation));
                    }
                    return Ok(());
                }
            }
        }
    }

    /// Skips a comment up to, not including, the line break.
    fn skip_comment(&mut self) {
        while self.peek().is_some_and(|b| !CharClass::of(b).is_break()) {
            self.pos += 1;
        }
    }

    /// Finishes the line of a complete value, then moves to the next content.
    ///
    /// Only whitespace and a comment may follow the value on its line.
    pub(crate) fn end_line(&mut self) -> Result<(), ParseError> {
        self.skip_blanks();
        if !self.at_line_end() {
            return Err(self.error(ErrorKind::TrailingContent));
        }
        self.skip_trivia()
    }

    /// Whether a plain scalar may start at the current position.
    ///
    /// Indicator characters cannot start one.
    /// The exceptions are `-`, `?`, and `:` followed by a non-blank character.
    pub(crate) fn can_start_plain(&self, flow: bool) -> bool {
        match self.peek() {
            None => false,
            Some(b'-' | b'?' | b':') => match self.peek_at(1) {
                None => false,
                Some(next) => {
                    let class = CharClass::of(next);
                    !(class.is_space() || (flow && class.is_flow_indicator()))
                }
            },
            Some(byte) => {
                !CharClass::of(byte).is_space()
                    && !matches!(
                        byte,
                        b',' | b'['
                            | b']'
                            | b'{'
                            | b'}'
                            | b'#'
                            | b'&'
                            | b'*'
                            | b'!'
                            | b'|'
                            | b'>'
                            | b'\''
                            | b'"'
                            | b'%'
                            | b'@'
                            | b'`'
                    )
            }
        }
    }

    /// Whether a colon at the current position separates a key from its value.
    ///
    /// In block context the colon needs whitespace after it.
    /// In flow context a flow indicator after it also counts.
    pub(crate) fn at_value_colon(&self, flow: bool) -> bool {
        self.peek() == Some(b':')
            && (self.blank_or_end_at(1)
                || (flow
                    && self
                        .peek_at(1)
                        .is_some_and(|byte| CharClass::of(byte).is_flow_indicator())))
    }

    /// Reads the part of a plain scalar that lies on the current line.
    ///
    /// The scanner stops right after the last content character, before trailing whitespace.
    fn plain_line(&mut self, flow: bool) -> &'a str {
        let start = self.pos;
        let mut end = start;
        loop {
            match self.peek() {
                None => break,
                Some(byte) if CharClass::of(byte).is_break() => break,
                Some(byte) if CharClass::of(byte).is_white() => {
                    // Whitespace belongs to the scalar only when content follows it.
                    //
                    //     "a b"     ->  "a b"
                    //     "a  # c"  ->  "a"    (comment)
                    //     "a   \n"  ->  "a"    (trailing)
                    self.skip_blanks();
                    if self.at_line_end() {
                        break;
                    }
                }
                Some(b':') if self.at_value_colon(flow) => break,
                Some(byte) if flow && CharClass::of(byte).is_flow_indicator() => break,
                Some(_) => {
                    self.bump_char();
                    end = self.pos;
                }
            }
        }
        self.pos = end;
        &self.src[start..end]
    }

    /// Reads a single-line plain scalar, the form of every plain key.
    pub(crate) fn plain_key(&mut self, flow: bool) -> &'a str {
        self.plain_line(flow)
    }

    /// Reads a plain scalar that may continue on more indented lines.
    ///
    /// # Arguments
    ///
    /// - `parent`: indentation of the enclosing block, or -1 at the top level.
    /// - `flow`: whether the scalar sits inside a flow collection.
    ///
    /// Lines fold as in YAML: one line break becomes a space.
    /// Each further empty line becomes one newline.
    pub(crate) fn plain(&mut self, parent: isize, flow: bool) -> Result<String, ParseError> {
        let mut out = String::from(self.plain_line(flow));
        loop {
            // Lookahead: keep the position after the last content in case the scalar ends.
            let end = *self;
            self.skip_blanks();
            if !self
                .peek()
                .is_some_and(|byte| CharClass::of(byte).is_break())
            {
                *self = end;
                return Ok(out);
            }

            // Count the line breaks up to the next non-empty line.
            //
            //     "a\n  b"      ->  1 break   ->  "a b"
            //     "a\n\n  b"    ->  2 breaks  ->  "a\nb"
            let mut breaks = 0_usize;
            while self.consume_break() {
                breaks += 1;
                self.skip_blanks();
            }

            // A continuation line must be indented past the parent and hold content.
            let ends_scalar = self.at_end()
                || self.at_line_end()
                || self.at_document_marker()
                || (self.indent().cast_signed() <= parent)
                || (flow
                    && self
                        .peek()
                        .is_some_and(|byte| CharClass::of(byte).is_flow_indicator()))
                || self.at_value_colon(flow);
            if ends_scalar {
                *self = end;
                return Ok(out);
            }

            // Fold the breaks, then append the next line's content.
            if breaks == 1 {
                out.push(' ');
            } else {
                out.extend(iter::repeat_n('\n', breaks - 1));
            }
            out.push_str(self.plain_line(flow));

            // Invariant: an implicit key cannot span lines.
            //
            //     "a: b\n  c: d"  ->  "b c" would be a key  ->  error
            if !flow && self.at_value_colon(false) {
                return Err(self.error(ErrorKind::UnexpectedMappingValue));
            }
        }
    }

    /// Reads a single-quoted scalar, where `''` stands for one quote.
    pub(crate) fn single_quoted(&mut self, parent: isize) -> Result<String, ParseError> {
        let open = *self;
        self.bump();
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(open.error(ErrorKind::UnterminatedQuote)),
                Some(b'\'') if self.peek_at(1) == Some(b'\'') => {
                    // A doubled quote is the only escape in this style.
                    out.push('\'');
                    self.pos += 2;
                }
                Some(b'\'') => {
                    self.bump();
                    return Ok(out);
                }
                Some(byte) if CharClass::of(byte).is_break() => {
                    self.fold_quoted(&mut out, 0, parent, open)?;
                }
                Some(_) => out.extend(self.bump_char()),
            }
        }
    }

    /// Reads a double-quoted scalar, decoding backslash escapes.
    pub(crate) fn double_quoted(&mut self, parent: isize) -> Result<String, ParseError> {
        let open = *self;
        self.bump();
        let mut out = String::new();
        // Length of the prefix that folding must not trim.
        //
        // Escaped whitespace, as in "a\t", is content even at the end of a line.
        let mut kept = 0;
        loop {
            match self.peek() {
                None => return Err(open.error(ErrorKind::UnterminatedQuote)),
                Some(b'"') => {
                    self.bump();
                    return Ok(out);
                }
                Some(b'\\')
                    if self
                        .peek_at(1)
                        .is_some_and(|byte| CharClass::of(byte).is_break()) =>
                {
                    // An escaped line break joins the lines with nothing between them.
                    //
                    //     "ab\        ->  "abcd"
                    //       cd"
                    self.bump();
                    self.consume_break();
                    self.skip_continuation_prefix(parent)?;
                    kept = out.len();
                }
                Some(b'\\') => {
                    self.escape(&mut out)?;
                    kept = out.len();
                }
                Some(byte) if CharClass::of(byte).is_break() => {
                    self.fold_quoted(&mut out, kept, parent, open)?;
                }
                Some(_) => out.extend(self.bump_char()),
            }
        }
    }

    /// Decodes one backslash escape into the output.
    fn escape(&mut self, out: &mut String) -> Result<(), ParseError> {
        let backslash = *self;
        self.bump();
        let Some(letter) = self.bump_char() else {
            return Err(backslash.error(ErrorKind::UnterminatedQuote));
        };
        let c = match letter {
            '0' => '\0',
            'a' => '\u{7}',
            'b' => '\u{8}',
            't' | '\t' => '\t',
            'n' => '\n',
            'v' => '\u{b}',
            'f' => '\u{c}',
            'r' => '\r',
            'e' => '\u{1b}',
            ' ' => ' ',
            '"' => '"',
            '/' => '/',
            '\\' => '\\',
            'N' => '\u{85}',
            '_' => '\u{a0}',
            'L' => '\u{2028}',
            'P' => '\u{2029}',
            'x' => self.hex_escape(2, backslash, letter)?,
            'u' => self.hex_escape(4, backslash, letter)?,
            'U' => self.hex_escape(8, backslash, letter)?,
            other => return Err(backslash.error(ErrorKind::InvalidEscape(other))),
        };
        out.push(c);
        Ok(())
    }

    /// Reads the hex digits of a `\x`, `\u`, or `\U` escape and returns the character.
    fn hex_escape(
        &mut self,
        digits: usize,
        backslash: Self,
        letter: char,
    ) -> Result<char, ParseError> {
        let mut value = 0_u32;
        for _ in 0..digits {
            let digit = self
                .peek()
                .and_then(|b| char::from(b).to_digit(16))
                .ok_or_else(|| backslash.error(ErrorKind::InvalidEscape(letter)))?;
            // At most 8 digits, so the value fits in 32 bits.
            value = (value << 4) | digit;
            self.bump();
        }
        // Surrogates and values past U+10FFFF are not characters.
        char::from_u32(value).ok_or_else(|| backslash.error(ErrorKind::InvalidCodePoint(value)))
    }

    /// Folds a line break inside a quoted scalar.
    ///
    /// Trailing whitespace before the break and leading whitespace after it are dropped.
    /// One break becomes a space, and each further empty line becomes a newline.
    fn fold_quoted(
        &mut self,
        out: &mut String,
        kept: usize,
        parent: isize,
        open: Self,
    ) -> Result<(), ParseError> {
        // Drop the unescaped whitespace that ends the line.
        let trimmed = out[kept..].trim_end_matches([' ', '\t']).len();
        out.truncate(kept + trimmed);

        self.consume_break();
        let empty_lines = self.skip_continuation_prefix(parent)?;
        if self.at_end() {
            return Err(open.error(ErrorKind::UnterminatedQuote));
        }
        if empty_lines == 0 {
            out.push(' ');
        } else {
            out.extend(iter::repeat_n('\n', empty_lines));
        }
        Ok(())
    }

    /// Skips empty lines and the indentation of a quoted scalar's next content line.
    ///
    /// Returns the number of empty lines skipped.
    /// The content line must sit deeper than the enclosing block.
    fn skip_continuation_prefix(&mut self, parent: isize) -> Result<usize, ParseError> {
        let mut empty_lines = 0;
        loop {
            self.skip_blanks();
            if !self.consume_break() {
                break;
            }
            empty_lines += 1;
        }
        if self.at_end() {
            return Ok(empty_lines);
        }

        // Rewind to the line start so a marker or shallow indent is caught at column 0.
        let mut line = *self;
        line.pos = line.line_start;
        if line.at_document_marker() {
            return Err(line.error(ErrorKind::UnexpectedDocumentMarker));
        }

        // Invariant: continuation lines sit deeper than the enclosing block.
        //
        //     key: 'a       parent block at column 0
        //       b'          column 2 > 0  ->  fine
        //     c'            column 0 <= 0 ->  error
        if self.indent().cast_signed() <= parent {
            return Err(self.error(ErrorKind::InvalidIndentation));
        }
        Ok(empty_lines)
    }

    /// Skips whitespace, comments, and line breaks inside a flow collection.
    ///
    /// Lines inside a flow collection must still sit deeper than the enclosing block.
    pub(crate) fn skip_flow_trivia(&mut self, parent: isize) -> Result<(), ParseError> {
        let line = self.line;
        loop {
            self.skip_blanks();
            match self.peek() {
                Some(b'#') if self.preceded_by_blank() => self.skip_comment(),
                Some(byte) if CharClass::of(byte).is_break() => {
                    self.consume_break();
                }
                _ => break,
            }
        }
        if self.line != line && !self.at_end() {
            // A new line was entered: check where its content starts.
            let mut start = *self;
            start.pos = start.line_start;
            if start.at_document_marker() {
                return Err(start.error(ErrorKind::UnexpectedDocumentMarker));
            }
            if self.indent().cast_signed() <= parent {
                return Err(self.error(ErrorKind::InvalidIndentation));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::{
        ErrorKind, Yaml,
        parser::tests::{fail, map, parse, s, seq},
    };

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

    #[test]
    fn tab_in_indentation() {
        // The tab sits where the nested key's indentation should be.
        //
        //     a:
        //     \tb: 1
        //
        // The tab sits at line 2, column 1.
        assert_eq!(fail("a:\n\tb: 1\n"), (ErrorKind::TabIndentation, 2, 1));
    }

    #[test]
    fn unterminated_quotes_point_at_the_opening_quote() {
        assert_eq!(fail("a: 'abc\n"), (ErrorKind::UnterminatedQuote, 1, 4));
        assert_eq!(fail("a: \"abc"), (ErrorKind::UnterminatedQuote, 1, 4));
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20_000))]

        #[test]
        fn arbitrary_unicode_never_panics(text in any::<String>()) {
            // Law: multi-byte characters never split a slice inside the scanner.
            let _ = Yaml::parse(&text);
        }
    }
}
