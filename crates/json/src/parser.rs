//! The RFC 8259 parser.
//!
//! The parser walks the bytes once, left to right, with an explicit stack of open containers.
//! Recursion depth on the thread's stack stays constant whatever the input nests.

use std::str;

use crate::{
    ErrorKind, Json, Number, Object, ParseError,
    frame::{Frame, OpenObject},
};

/// Bounds on the input a parse accepts.
///
/// Both bounds protect a reader of untrusted input.
/// The size bound caps memory and time.
/// The depth bound caps the parser's stack of open containers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Most arrays and objects that may be open at once.
    pub max_depth: usize,

    /// Most bytes the text may hold.
    pub max_bytes: usize,
}

impl Limits {
    /// Limits that suit RPC messages.
    ///
    /// - Engine and beacon API messages nest fewer than ten levels, so 128 leaves ample room.
    /// - A block with blobs, hex encoded, stays well below 16 MiB.
    pub const DEFAULT: Self = Self {
        max_depth: 128,
        max_bytes: 16 << 20,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A cursor over the bytes of one document.
pub(crate) struct Parser<'a> {
    /// The whole text.
    bytes: &'a [u8],
    /// Offset of the next unread byte.
    at: usize,
    /// Bounds on the text.
    limits: Limits,
}

impl<'a> Parser<'a> {
    /// A cursor at the start of a text.
    pub(crate) const fn new(bytes: &'a [u8], limits: Limits) -> Self {
        Self {
            bytes,
            at: 0,
            limits,
        }
    }

    /// Reads exactly one value surrounded by optional whitespace.
    ///
    /// # Algorithm
    ///
    /// The loop alternates between two phases.
    ///
    /// ```text
    ///     read a value ----> scalar or empty container -> attach to the open container
    ///          ^         \-> "[" or "{" with content   -> push a frame, read again
    ///          |
    ///     attach: "," -> read the next value
    ///             "]" or "}" -> pop the frame, attach it to its parent in turn
    ///             no open container -> the document is done
    /// ```
    pub(crate) fn document(mut self) -> Result<Json, ParseError> {
        // Size bound first, so no work is spent on an oversized text.
        if self.bytes.len() > self.limits.max_bytes {
            return Err(ParseError {
                offset: self.limits.max_bytes,
                kind: ErrorKind::TooLarge,
            });
        }

        let mut stack: Vec<Frame> = Vec::new();

        'value: loop {
            // Phase 1: read one value, or open a container and come back for its first item.
            let Some(mut value) = self.value_or_open(&mut stack)? else {
                continue 'value;
            };

            // Phase 2: attach the value to the innermost open container, closing as many as end here.
            loop {
                let Some(frame) = stack.last_mut() else {
                    // No open container: the value is the document, and only whitespace may follow.
                    self.skip_whitespace();
                    if self.at != self.bytes.len() {
                        return Err(self.error(ErrorKind::TrailingCharacters));
                    }
                    return Ok(value);
                };

                frame.push(value);

                // After an item: a comma for another, or the closing bracket.
                self.skip_whitespace();
                match self.peek() {
                    Some(b',') => {
                        self.at += 1;
                        // An object's next member starts with its name.
                        if let Frame::Object(object) = frame {
                            self.skip_whitespace();
                            let (next, offset) = self.member_name()?;
                            object.next_name(next, offset);
                        }
                        continue 'value;
                    }
                    Some(byte) if byte == frame.closer() => {
                        self.at += 1;
                        // The container is complete; it becomes the value to attach next.
                        match stack.pop() {
                            Some(closed) => value = closed.close()?,
                            None => return Err(self.error(ErrorKind::UnexpectedByte(byte))),
                        }
                    }
                    Some(byte) => return Err(self.error(ErrorKind::UnexpectedByte(byte))),
                    None => return Err(self.error(ErrorKind::UnexpectedEnd)),
                }
            }
        }
    }

    /// Reads a complete value, or opens a non-empty container.
    ///
    /// # Returns
    ///
    /// The value, or nothing when a container was opened and its first item is next.
    fn value_or_open(&mut self, stack: &mut Vec<Frame>) -> Result<Option<Json>, ParseError> {
        self.skip_whitespace();
        let value = match self.peek() {
            None => return Err(self.error(ErrorKind::UnexpectedEnd)),
            Some(b'[') => {
                self.check_depth(stack.len())?;
                self.at += 1;
                self.skip_whitespace();
                // "[]" closes at once; anything else is a first item.
                if self.peek() != Some(b']') {
                    stack.push(Frame::Array(Vec::new()));
                    return Ok(None);
                }
                self.at += 1;
                Json::Array(Vec::new())
            }
            Some(b'{') => {
                self.check_depth(stack.len())?;
                self.at += 1;
                self.skip_whitespace();
                // "{}" closes at once; anything else must be a first member name.
                if self.peek() != Some(b'}') {
                    let (name, offset) = self.member_name()?;
                    stack.push(Frame::Object(OpenObject::new(name, offset)));
                    return Ok(None);
                }
                self.at += 1;
                Json::Object(Object::new())
            }
            Some(b'"') => Json::String(self.string()?),
            Some(b't') => {
                self.literal(b"true")?;
                Json::Bool(true)
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Json::Bool(false)
            }
            Some(b'n') => {
                self.literal(b"null")?;
                Json::Null
            }
            Some(b'-' | b'0'..=b'9') => Json::Number(self.number()?),
            Some(byte) => return Err(self.error(ErrorKind::UnexpectedByte(byte))),
        };
        Ok(Some(value))
    }

    /// Fails when opening one more container would pass the depth limit.
    const fn check_depth(&self, open: usize) -> Result<(), ParseError> {
        // The container about to open makes the depth one more than those already open.
        if open >= self.limits.max_depth {
            return Err(self.error(ErrorKind::TooDeep));
        }
        Ok(())
    }

    /// Reads a member name and the colon after it.
    ///
    /// # Returns
    ///
    /// The decoded name and the offset of its opening quote.
    fn member_name(&mut self) -> Result<(String, usize), ParseError> {
        let offset = self.at;
        // Names are strings; RFC 8259 allows nothing else, not even bare words.
        match self.peek() {
            Some(b'"') => {}
            Some(byte) => return Err(self.error(ErrorKind::UnexpectedByte(byte))),
            None => return Err(self.error(ErrorKind::UnexpectedEnd)),
        }
        let name = self.string()?;

        // The name separator, with optional whitespace on either side.
        self.skip_whitespace();
        match self.peek() {
            Some(b':') => self.at += 1,
            Some(byte) => return Err(self.error(ErrorKind::UnexpectedByte(byte))),
            None => return Err(self.error(ErrorKind::UnexpectedEnd)),
        }
        Ok((name, offset))
    }

    /// Reads one of the three literal names.
    fn literal(&mut self, word: &[u8]) -> Result<(), ParseError> {
        // Compare byte by byte so the error points at the first wrong byte.
        for &expected in word {
            match self.peek() {
                Some(byte) if byte == expected => self.at += 1,
                Some(byte) => return Err(self.error(ErrorKind::UnexpectedByte(byte))),
                None => return Err(self.error(ErrorKind::UnexpectedEnd)),
            }
        }
        Ok(())
    }

    /// Reads a number.
    fn number(&mut self) -> Result<Number, ParseError> {
        let start = self.at;
        match Number::scan(self.bytes, start) {
            Ok(end) => {
                self.at = end;
                // The grammar admits only ASCII, so each byte is one character.
                let text = self.bytes[start..end]
                    .iter()
                    .copied()
                    .map(char::from)
                    .collect();
                Ok(Number::from_validated(text))
            }
            Err(offset) => Err(ParseError {
                offset,
                kind: ErrorKind::InvalidNumber,
            }),
        }
    }

    /// Reads a string, decoding escapes.
    ///
    /// ```text
    ///     " plain run \ escape plain run \ escape ... "
    ///       ^ copied    ^ decoded
    /// ```
    ///
    /// Plain runs are copied whole after one UTF-8 check each.
    /// A run never splits a character, because every byte that ends a run is ASCII.
    fn string(&mut self) -> Result<String, ParseError> {
        // Skip the opening quote.
        self.at += 1;
        let mut out = String::new();

        loop {
            // Fast scan to the next byte that needs attention.
            let run_start = self.at;
            while let Some(&byte) = self.bytes.get(self.at) {
                if byte == b'"' || byte == b'\\' || byte < 0x20 {
                    break;
                }
                self.at += 1;
            }

            // Copy the run, checking it is UTF-8.
            match str::from_utf8(&self.bytes[run_start..self.at]) {
                Ok(run) => out.push_str(run),
                Err(error) => {
                    return Err(ParseError {
                        offset: run_start + error.valid_up_to(),
                        kind: ErrorKind::InvalidUtf8,
                    });
                }
            }

            // Decide what the stopping byte means.
            match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => self.escape(&mut out)?,
                Some(byte) => return Err(self.error(ErrorKind::ControlCharacter(byte))),
                None => return Err(self.error(ErrorKind::UnexpectedEnd)),
            }
        }
    }

    /// Decodes one escape sequence starting at a backslash.
    fn escape(&mut self, out: &mut String) -> Result<(), ParseError> {
        let start = self.at;
        // Skip the backslash and read the escape letter.
        self.at += 1;
        let Some(letter) = self.peek() else {
            return Err(self.error(ErrorKind::UnexpectedEnd));
        };
        // The eight short escapes of RFC 8259 section 7.
        let short = match letter {
            b'"' => Some('"'),
            b'\\' => Some('\\'),
            b'/' => Some('/'),
            b'b' => Some('\u{8}'),
            b'f' => Some('\u{c}'),
            b'n' => Some('\n'),
            b'r' => Some('\r'),
            b't' => Some('\t'),
            b'u' => None,
            other => return Err(self.error(ErrorKind::InvalidEscape(other))),
        };
        self.at += 1;
        if let Some(decoded) = short {
            out.push(decoded);
            return Ok(());
        }

        // A unicode escape is one UTF-16 code unit in four hex digits.
        let unit = self.hex4()?;
        let code = match unit {
            // A high surrogate needs a low surrogate escape right after it.
            //
            //     😀  ->  0x10000 + (0x3d << 10) + 0x200 = U+1F600
            0xd800..=0xdbff => {
                let low = if self.bytes.get(self.at..self.at + 2) == Some(b"\\u") {
                    self.at += 2;
                    self.hex4()?
                } else {
                    0
                };
                if !(0xdc00..=0xdfff).contains(&low) {
                    return Err(ParseError {
                        offset: start,
                        kind: ErrorKind::LoneSurrogate(unit),
                    });
                }
                0x1_0000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00)
            }
            // A low surrogate with no high surrogate before it.
            0xdc00..=0xdfff => {
                return Err(ParseError {
                    offset: start,
                    kind: ErrorKind::LoneSurrogate(unit),
                });
            }
            // Any other unit is a character of the basic multilingual plane.
            _ => u32::from(unit),
        };

        // Every value built above is a scalar value, so the conversion cannot fail.
        // The error arm keeps the code free of a panic path all the same.
        match char::from_u32(code) {
            Some(decoded) => {
                out.push(decoded);
                Ok(())
            }
            None => Err(ParseError {
                offset: start,
                kind: ErrorKind::LoneSurrogate(unit),
            }),
        }
    }

    /// Reads four hex digits as a UTF-16 code unit.
    fn hex4(&mut self) -> Result<u16, ParseError> {
        let mut unit = 0_u16;
        for _ in 0..4 {
            // Each digit shifts in four more bits, most significant first.
            let digit = match self.peek() {
                Some(byte @ b'0'..=b'9') => byte - b'0',
                Some(byte @ b'a'..=b'f') => byte - b'a' + 10,
                Some(byte @ b'A'..=b'F') => byte - b'A' + 10,
                Some(_) => return Err(self.error(ErrorKind::InvalidUnicodeEscape)),
                None => return Err(self.error(ErrorKind::UnexpectedEnd)),
            };
            unit = (unit << 4) | u16::from(digit);
            self.at += 1;
        }
        Ok(unit)
    }

    /// Skips the four whitespace bytes of RFC 8259: space, tab, line feed, carriage return.
    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    /// The next unread byte, if any.
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    /// An error at the current offset.
    const fn error(&self, kind: ErrorKind) -> ParseError {
        ParseError {
            offset: self.at,
            kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Any number the grammar allows, built from its four optional parts.
    fn number() -> impl Strategy<Value = Number> {
        (
            any::<bool>(),
            prop_oneof![Just("0".to_owned()), "[1-9][0-9]{0,30}"],
            proptest::option::of("[0-9]{1,10}"),
            proptest::option::of(("[eE]", "[+-]?", "[0-9]{1,4}")),
        )
            .prop_map(|(negative, int, frac, exp)| {
                // Assemble sign, integer, fraction, and exponent in grammar order.
                let mut text = String::new();
                if negative {
                    text.push('-');
                }
                text.push_str(&int);
                if let Some(frac) = frac {
                    text.push('.');
                    text.push_str(&frac);
                }
                if let Some((e, sign, digits)) = exp {
                    text.push_str(&e);
                    text.push_str(&sign);
                    text.push_str(&digits);
                }
                text.parse().expect("assembled from the grammar")
            })
    }

    /// Any value up to a few levels deep, including every control character and astral planes.
    fn json() -> impl Strategy<Value = Json> {
        let leaf = prop_oneof![
            Just(Json::Null),
            any::<bool>().prop_map(Json::Bool),
            number().prop_map(Json::Number),
            any::<String>().prop_map(Json::String),
        ];
        leaf.prop_recursive(4, 64, 8, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..8).prop_map(Json::Array),
                // Names may collide in the generator; collecting keeps them unique.
                proptest::collection::vec((any::<String>(), inner), 0..8)
                    .prop_map(|members| Json::Object(members.into_iter().collect::<Object>())),
            ]
        })
    }

    /// Inserts whitespace between every token of a compact text.
    ///
    /// Whitespace inside strings must stay put, so the walk tracks whether it is inside one.
    fn spread(compact: &str, pad: &str) -> String {
        let mut out = String::new();
        let mut in_string = false;
        let mut escaped = false;
        for c in compact.chars() {
            out.push(c);
            if in_string {
                // Track escapes so an escaped quote does not end the string.
                match (escaped, c) {
                    (true, _) => escaped = false,
                    (false, '\\') => escaped = true,
                    (false, '"') => in_string = false,
                    _ => {}
                }
            } else if c == '"' {
                in_string = true;
            } else if matches!(c, '[' | ']' | '{' | '}' | ',' | ':') {
                out.push_str(pad);
            }
        }
        out
    }

    proptest! {
        #[test]
        fn serialize_then_parse_is_identity(value in json()) {
            // Writing a value and reading it back yields the same value.
            let text = value.to_string();
            prop_assert_eq!(Json::parse(&text), Ok(value));
        }

        #[test]
        fn parse_then_serialize_is_idempotent(value in json(), pad in "[ \t\n\r]{0,3}") {
            // A padded text parses to the same value, and writes back to the compact form.
            let compact = value.to_string();
            let padded = format!("{pad}{}{pad}", spread(&compact, &pad));
            let parsed = Json::parse(&padded).unwrap();
            prop_assert_eq!(parsed.to_string(), compact);
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            // Any outcome is fine; an error must point inside the input or at its end.
            if let Err(error) = Json::parse(&bytes) {
                prop_assert!(error.offset() <= bytes.len());
            }
        }

        #[test]
        fn json_alphabet_never_panics(text in "[\\[\\]{}\",:0-9eE.+\\-a-z\\\\ ]{0,64}") {
            // Bytes drawn from the JSON alphabet reach far deeper into the grammar than noise.
            let limits = Limits { max_depth: 4, max_bytes: 64 };
            if let Err(error) = Json::parse_with(&text, limits) {
                prop_assert!(error.offset() <= text.len());
            }
        }

        #[test]
        fn truncation_is_always_rejected(value in json(), cut in any::<prop::sample::Index>()) {
            // Cutting a container's compact text short always fails.
            // A scalar may survive, as "12" cut to "1" is still a number.
            let text = value.to_string();
            if matches!(value, Json::Array(_) | Json::Object(_)) {
                let end = cut.index(text.len());
                if text.is_char_boundary(end) {
                    prop_assert!(Json::parse(&text[..end]).is_err());
                }
            }
        }
    }
}
