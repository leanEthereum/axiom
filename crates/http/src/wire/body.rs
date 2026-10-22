//! Body framing and the chunked transfer coding.
//!
//! A chunked body is a run of sized chunks ended by a zero-sized one.
//!
//! ```text
//!     5\r\n            size in hex, optional ";ext" ignored
//!     hello\r\n        five bytes of data, then CRLF
//!     6;x=y\r\n
//!      world\r\n
//!     0\r\n            last chunk
//!     trailer: v\r\n   optional trailer fields, ignored
//!     \r\n             end of body
//! ```
//!
//! The grammar is RFC 9112 section 7.1.

use crate::ProtocolError;

/// How a message's body is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyLength {
    /// The message has no body.
    Empty,

    /// The body is exactly this many bytes.
    Fixed(u64),

    /// The body uses the chunked transfer coding.
    Chunked,

    /// The body runs until the sender closes the connection.
    ///
    /// Only responses may be framed this way.
    UntilClose,
}

/// Longest chunk size line or trailer line accepted.
///
/// A size line holds at most 16 hex digits; the rest is room for ignored extensions.
const MAX_LINE: usize = 4096;

/// Most trailer bytes accepted after the last chunk.
///
/// Trailers are discarded, so this only bounds the work of skipping them.
const MAX_TRAILER: usize = 16 << 10;

/// Where the decoder is within a chunked body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Reading a chunk size line.
    Size,
    /// Copying chunk data, with this many bytes left.
    Data(u64),
    /// Expecting the CRLF after chunk data.
    DataEnd,
    /// Reading trailer lines after the last chunk.
    Trailer,
    /// The body is complete.
    Done,
}

/// An incremental decoder for the chunked transfer coding.
///
/// It accepts input in pieces of any size, so a socket read may end anywhere.
/// The decoder never reads past the body, leaving the next message's bytes to the caller.
#[derive(Clone, Debug)]
pub struct ChunkedDecoder {
    /// Position in the body grammar.
    state: State,
    /// The partial line being read, CRLF included once complete.
    line: Vec<u8>,
    /// Most decoded bytes allowed.
    max_body: usize,
    /// Decoded bytes so far.
    decoded: usize,
    /// Trailer bytes seen so far.
    trailer: usize,
}

impl ChunkedDecoder {
    /// A decoder at the start of a body, refusing more than a bound of decoded bytes.
    #[must_use]
    pub const fn new(max_body: usize) -> Self {
        Self {
            state: State::Size,
            line: Vec::new(),
            max_body,
            decoded: 0,
            trailer: 0,
        }
    }

    /// Whether the whole body, trailers included, has been read.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Decodes as much of the input as belongs to the body.
    ///
    /// # Returns
    ///
    /// The input bytes consumed.
    /// Fewer than all are consumed only when the body ends inside the input.
    ///
    /// # Errors
    ///
    /// Fails on a malformed size line or delimiter, and on a body over the bound.
    pub fn decode(&mut self, input: &[u8], body: &mut Vec<u8>) -> Result<usize, ProtocolError> {
        let mut at = 0;
        while at < input.len() {
            match self.state {
                State::Size => {
                    // Gather the line; stop for more input when it is still open.
                    if !self.take_line(input, &mut at)? {
                        break;
                    }
                    self.state = self.size_line()?;
                    self.line.clear();
                }
                State::Data(left) => {
                    // Copy as much of the chunk as this input holds.
                    let available = input.len() - at;
                    let take = usize::try_from(left).map_or(available, |left| left.min(available));
                    body.extend_from_slice(&input[at..at + take]);
                    at += take;
                    let left = left - take as u64;
                    self.state = if left == 0 {
                        State::DataEnd
                    } else {
                        State::Data(left)
                    };
                }
                State::DataEnd => {
                    // Exactly CRLF must follow the data, possibly split across inputs.
                    // Checking the prefix at once rejects "helloXX" without waiting for a line feed.
                    let complete = self.take_line(input, &mut at)?;
                    if !b"\r\n".starts_with(&self.line) {
                        return Err(ProtocolError::InvalidChunk);
                    }
                    if !complete {
                        break;
                    }
                    self.line.clear();
                    self.state = State::Size;
                }
                State::Trailer => {
                    if !self.take_line(input, &mut at)? {
                        break;
                    }
                    // The empty line ends the body; any other line is a trailer field, skipped.
                    if self.line == b"\r\n" {
                        self.state = State::Done;
                    } else {
                        self.trailer += self.line.len();
                        if self.trailer > MAX_TRAILER {
                            return Err(ProtocolError::HeadTooLarge { limit: MAX_TRAILER });
                        }
                    }
                    self.line.clear();
                }
                State::Done => break,
            }
        }
        Ok(at)
    }

    /// Moves input bytes into the line buffer up to and including a line feed.
    ///
    /// # Returns
    ///
    /// Whether the line is complete.
    fn take_line(&mut self, input: &[u8], at: &mut usize) -> Result<bool, ProtocolError> {
        // Copy up to the next line feed, or all the input when there is none yet.
        let rest = &input[*at..];
        let (piece, complete) = match rest.iter().position(|&byte| byte == b'\n') {
            Some(end) => (&rest[..=end], true),
            None => (rest, false),
        };
        self.line.extend_from_slice(piece);
        *at += piece.len();

        // A line that never ends would grow without bound.
        if self.line.len() > MAX_LINE {
            return Err(ProtocolError::InvalidChunk);
        }
        // A bare LF is not a line ending here; CR must precede it.
        if complete && !self.line.ends_with(b"\r\n") {
            return Err(ProtocolError::InvalidChunk);
        }
        Ok(complete)
    }

    /// Reads the size from a complete size line and picks the next state.
    fn size_line(&mut self) -> Result<State, ProtocolError> {
        // Drop the CRLF, then any extensions after a semicolon, then optional whitespace.
        //
        //     "1a ; name=value\r\n"  ->  "1a"  ->  26
        let line = &self.line[..self.line.len() - 2];
        let size = line
            .split(|&byte| byte == b';')
            .next()
            .unwrap_or_default()
            .trim_ascii_end();

        // One to sixteen hex digits: sixteen fill a 64-bit size.
        if size.is_empty() || size.len() > 16 {
            return Err(ProtocolError::InvalidChunk);
        }
        let mut value = 0_u64;
        for &byte in size {
            let digit = char::from(byte)
                .to_digit(16)
                .ok_or(ProtocolError::InvalidChunk)?;
            value = (value << 4) | u64::from(digit);
        }

        // The last chunk has size zero and leads into the trailer section.
        if value == 0 {
            return Ok(State::Trailer);
        }

        // Refuse a chunk that would push the body past its bound before copying any of it.
        let budget = (self.max_body - self.decoded) as u64;
        if value > budget {
            return Err(ProtocolError::BodyTooLarge {
                size: (self.decoded as u64).saturating_add(value),
                limit: self.max_body,
            });
        }
        self.decoded += value as usize;
        Ok(State::Data(value))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Decodes a complete body in one piece.
    fn decode(input: &[u8], max_body: usize) -> Result<(Vec<u8>, usize), ProtocolError> {
        let mut decoder = ChunkedDecoder::new(max_body);
        let mut body = Vec::new();
        let consumed = decoder.decode(input, &mut body)?;
        assert!(decoder.is_done(), "body is incomplete");
        Ok((body, consumed))
    }

    #[test]
    fn extensions_and_trailers_are_skipped() {
        // Two chunks, one with an extension, then a trailer field, then the next message.
        let input = b"5\r\nhello\r\n6;x=y\r\n world\r\n0\r\nT: v\r\n\r\nNEXT";
        let (body, consumed) = decode(input, 100).unwrap();

        // Eleven decoded bytes; the decoder stops right before "NEXT".
        assert_eq!(body, b"hello world");
        assert_eq!(&input[consumed..], b"NEXT");
    }

    #[test]
    fn rfc9112_grammar_cases() {
        // RFC 9112 section 7.1 gives the grammar but no sample body, so each case exercises one rule.
        let cases: [(&[u8], &[u8]); 6] = [
            // HEXDIG is case-insensitive, per RFC 5234 section 2.3: "A" is ten.
            (b"A\r\n0123456789\r\n0\r\n\r\n", b"0123456789"),
            // The size is 1*HEXDIG, so leading zeros are allowed: "000a" is ten too.
            (b"000a\r\n0123456789\r\n0\r\n\r\n", b"0123456789"),
            // Section 7.1.1 allows bad whitespace around the semicolon and the equals sign.
            (b"5 ; a = b\r\nhello\r\n0\r\n\r\n", b"hello"),
            // Several extensions, one a quoted string holding a semicolon.
            (b"5;a;b=c;d=\"x;y\"\r\nhello\r\n0\r\n\r\n", b"hello"),
            // The last chunk is 1*"0" and may carry its own extension.
            (b"5\r\nhello\r\n000;end=1\r\n\r\n", b"hello"),
            // Section 7.1.2 trailer fields, two of them, are read and dropped.
            (b"5\r\nhello\r\n0\r\nA: 1\r\nB: 2\r\n\r\n", b"hello"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                decode(input, 100),
                Ok((expected.to_vec(), input.len())),
                "{input:?}"
            );
        }
    }

    #[test]
    fn rejections() {
        // Each malformed body maps to one error.
        //
        //     "g\r\n..."           non-hex size
        //     "\r\n..."            empty size
        //     "5\r\nhelloXX..."    data not followed by CRLF
        //     "5\nhello..."        bare LF after the size
        //     17 hex digits        past 64 bits
        let cases: [&[u8]; 5] = [
            b"g\r\n",
            b"\r\n",
            b"5\r\nhelloXX",
            b"5\nhello",
            b"10000000000000000\r\n",
        ];
        for input in cases {
            let mut decoder = ChunkedDecoder::new(100);
            assert_eq!(
                decoder.decode(input, &mut Vec::new()),
                Err(ProtocolError::InvalidChunk),
                "{input:?}"
            );
        }
    }

    #[test]
    fn bound_applies_before_copying() {
        // A 0x10 = 16 byte chunk against a 15-byte bound fails on the size line alone.
        assert_eq!(
            decode(b"10\r\n", 15),
            Err(ProtocolError::BodyTooLarge {
                size: 16,
                limit: 15
            })
        );

        // Two chunks of 8 against the same bound: the second one brings the body to 16.
        let mut decoder = ChunkedDecoder::new(15);
        let input = b"8\r\n12345678\r\n8\r\n";
        assert_eq!(
            decoder.decode(input, &mut Vec::new()),
            Err(ProtocolError::BodyTooLarge {
                size: 16,
                limit: 15
            })
        );
    }

    /// Encodes a body with the chunked coding, cutting it at the given sizes.
    ///
    /// ```text
    ///     body "hello", sizes [2, 9]  ->  "2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n"
    /// ```
    fn chunked(body: &[u8], sizes: &[usize]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = body;
        let mut sizes = sizes.iter().cycle();
        while !rest.is_empty() {
            // Sizes cycle; zero would end the body early, so it becomes one.
            let size = sizes.next().copied().unwrap_or(1).clamp(1, rest.len());
            out.extend_from_slice(format!("{size:x}\r\n").as_bytes());
            out.extend_from_slice(&rest[..size]);
            out.extend_from_slice(b"\r\n");
            rest = &rest[size..];
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    }

    proptest! {
        #[test]
        fn chunked_decode_any_split(
            body in proptest::collection::vec(any::<u8>(), 0..2000),
            sizes in proptest::collection::vec(1_usize..300, 1..10),
            cuts in proptest::collection::vec(1_usize..64, 1..20),
            next in proptest::collection::vec(any::<u8>(), 0..20),
        ) {
            // A chunked body followed by the start of another message.
            let mut stream = chunked(&body, &sizes);
            let end = stream.len();
            stream.extend_from_slice(&next);

            // Feed it in pieces of arbitrary sizes, as socket reads would arrive.
            let mut decoder = ChunkedDecoder::new(body.len());
            let mut decoded = Vec::new();
            let mut at = 0;
            let mut cuts = cuts.iter().cycle();
            while !decoder.is_done() && at < stream.len() {
                let piece = (*cuts.next().unwrap()).min(stream.len() - at);
                let used = decoder.decode(&stream[at..at + piece], &mut decoded).unwrap();
                at += used;
                // The decoder consumes the whole piece unless the body ended inside it.
                if used < piece {
                    prop_assert!(decoder.is_done());
                }
            }

            // The whole body comes back, and the next message's bytes are untouched.
            prop_assert!(decoder.is_done());
            prop_assert_eq!(decoded, body);
            prop_assert_eq!(at, end);
        }

        #[test]
        fn chunked_bound_is_exact(body in proptest::collection::vec(any::<u8>(), 1..500)) {
            // A bound one byte short of the body rejects it.
            // Every chunk before the last fits, so the last one reports the whole body size.
            let stream = chunked(&body, &[7]);
            let mut decoder = ChunkedDecoder::new(body.len() - 1);
            prop_assert_eq!(
                decoder.decode(&stream, &mut Vec::new()),
                Err(ProtocolError::BodyTooLarge {
                    size: body.len() as u64,
                    limit: body.len() - 1
                })
            );
        }
    }
}
