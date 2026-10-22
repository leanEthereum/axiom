//! A streaming deflate encoder emitting fixed Huffman blocks.
//!
//! Source: RFC 1951.

use std::io::{self, Write};

use crate::logging::gzip::{
    bits::BitWriter,
    matcher::{Matcher, Token},
    tables::{Code, DISTANCES, END_OF_BLOCK, FIRST_LENGTH_SYMBOL, LENGTHS},
};

/// The block type of fixed Huffman codes, in its two-bit header field.
///
/// Source: RFC 1951 section 3.2.3.
const FIXED_HUFFMAN: u32 = 0b01;

/// Compresses a byte stream into a deflate stream on a sink.
///
/// # Overview
///
/// The stream is one open block of fixed Huffman codes, closed by an empty final block.
/// The final flag precedes a block's data, so a stream of unknown length cannot set it early.
///
/// Fixed codes need no code table in the stream and no buffering of a whole block.
/// Log text is mostly repeated words, which LZ77 matches already shrink.
#[derive(Debug)]
pub(super) struct Deflater<W> {
    /// The LZ77 stage.
    matcher: Matcher,

    /// The bit packer.
    bits: BitWriter,

    /// Where the compressed bytes go.
    sink: W,
}

impl<W: Write> Deflater<W> {
    /// Starts a stream on a sink.
    pub(super) fn new(sink: W) -> Self {
        let mut bits = BitWriter::default();
        // The open block is not final, then its two-bit type.
        bits.put(0, 1);
        bits.put(FIXED_HUFFMAN, 2);
        Self {
            matcher: Matcher::default(),
            bits,
            sink,
        }
    }

    /// Compresses more input.
    pub(super) fn write(&mut self, mut input: &[u8]) -> io::Result<()> {
        while !input.is_empty() {
            let taken = self.matcher.fill(input);
            input = &input[taken..];
            self.encode(false);
            self.bits.spill(&mut self.sink)?;
        }
        Ok(())
    }

    /// Ends the stream and returns the sink.
    pub(super) fn finish(mut self) -> io::Result<W> {
        // Phase 1: the remaining input, without waiting for a full lookahead.
        self.encode(true);
        // Phase 2: close the open block, then an empty block marked final.
        self.bits.put_code(Code::literal_length(END_OF_BLOCK));
        self.bits.put(1, 1);
        self.bits.put(FIXED_HUFFMAN, 2);
        self.bits.put_code(Code::literal_length(END_OF_BLOCK));
        // Phase 3: pad to a byte, and hand everything over.
        self.bits.finish(&mut self.sink)?;
        Ok(self.sink)
    }

    /// Codes every token the matcher can produce now.
    fn encode(&mut self, ended: bool) {
        while let Some(token) = self.matcher.next_token(ended) {
            match token {
                Token::Literal(byte) => {
                    self.bits.put_code(Code::literal_length(u16::from(byte)));
                }
                Token::Match { length, distance } => {
                    // A length symbol, its extra bits, a distance symbol, then its extra bits.
                    // Source: RFC 1951 section 3.2.5.
                    let length = LENGTHS.classify(length);
                    let symbol = FIRST_LENGTH_SYMBOL + length.index as u16;
                    self.bits.put_code(Code::literal_length(symbol));
                    self.bits.put(length.offset, length.width);
                    let distance = DISTANCES.classify(distance);
                    self.bits.put_code(Code::distance(distance.index as u16));
                    self.bits.put(distance.offset, distance.width);
                }
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::logging::gzip::matcher::WINDOW;

    /// Reads fields packed least significant bit first.
    struct BitReader<'a> {
        bytes: &'a [u8],
        position: usize,
    }

    impl BitReader<'_> {
        /// The next field of a given width, least significant bit first.
        fn take(&mut self, width: u32) -> u32 {
            let mut value = 0;
            for shift in 0..width {
                let byte = self.bytes[self.position / 8];
                let bit = u32::from(byte >> (self.position % 8)) & 1;
                value |= bit << shift;
                self.position += 1;
            }
            value
        }

        /// The next Huffman code bit, which accumulates most significant bit first.
        fn code(&mut self, code: u32) -> u32 {
            (code << 1) | self.take(1)
        }

        /// The next literal or length symbol of the fixed code.
        fn literal_length(&mut self) -> u16 {
            // Seven bits: symbols 256 to 279 are the codes 0 to 23.
            let mut code = 0;
            for _ in 0..7 {
                code = self.code(code);
            }
            if code <= 23 {
                return 256 + code as u16;
            }
            // Eight bits: literals 0 to 143, then symbols 280 to 287.
            code = self.code(code);
            match code {
                0x30..=0xbf => return (code - 0x30) as u16,
                0xc0..=0xc7 => return (code - 0xc0 + 280) as u16,
                _ => {}
            }
            // Nine bits: literals 144 to 255.
            code = self.code(code);
            (code - 0x190 + 144) as u16
        }

        /// A match length from its symbol and extra bits.
        ///
        /// The ranges follow the rule of RFC 1951 section 3.2.5, independent of the encoder's table.
        fn length(&mut self, symbol: u16) -> usize {
            // Symbol 285 is exactly 258, with no extra bits.
            if symbol == 285 {
                return 258;
            }
            // Eight symbols with no extra bits, then one more bit every four symbols.
            let extra = |symbol: u16| u32::from(symbol.saturating_sub(261) / 4);
            let base: usize = 3 + (257..symbol).map(|s| 1_usize << extra(s)).sum::<usize>();
            base + self.take(extra(symbol)) as usize
        }

        /// A match distance from its symbol and extra bits.
        ///
        /// The ranges follow the rule of RFC 1951 section 3.2.5, independent of the encoder's table.
        fn distance(&mut self, symbol: u32) -> usize {
            // Four symbols with no extra bits, then one more bit every two symbols.
            let extra = |symbol: u32| (symbol / 2).saturating_sub(1);
            let base: usize = 1 + (0..symbol).map(|s| 1_usize << extra(s)).sum::<usize>();
            base + self.take(extra(symbol)) as usize
        }
    }

    /// Decodes a deflate stream of fixed Huffman blocks, returning the bytes and the bytes read.
    pub(in crate::logging::gzip) fn inflate(stream: &[u8]) -> (Vec<u8>, usize) {
        let mut reader = BitReader {
            bytes: stream,
            position: 0,
        };
        let mut out: Vec<u8> = Vec::new();
        loop {
            let last = reader.take(1) == 1;
            assert_eq!(reader.take(2), FIXED_HUFFMAN, "only fixed blocks");
            loop {
                let symbol = reader.literal_length();
                match symbol {
                    0..=255 => out.push(symbol as u8),
                    256 => break,
                    _ => {
                        let length = reader.length(symbol);
                        let mut code = 0;
                        for _ in 0..5 {
                            code = reader.code(code);
                        }
                        let distance = reader.distance(code);
                        // Byte by byte, so an overlapping copy repeats what it just wrote.
                        let from = out.len() - distance;
                        for offset in 0..length {
                            out.push(out[from + offset]);
                        }
                    }
                }
            }
            if last {
                return (out, reader.position.div_ceil(8));
            }
        }
    }

    /// Compresses an input split into writes of a given size.
    fn deflate(input: &[u8], chunk: usize) -> Vec<u8> {
        let mut deflater = Deflater::new(Vec::new());
        for piece in input.chunks(chunk) {
            deflater.write(piece).unwrap();
        }
        deflater.finish().unwrap()
    }

    /// Bytes from a seeded xorshift generator, cheap enough for inputs of hundreds of KiB.
    fn noise(seed: u64, length: usize) -> Vec<u8> {
        // Xorshift needs a nonzero state.
        let mut state = seed | 1;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    /// A random pattern repeated to a length, with about one byte in 1000 replaced.
    ///
    /// The edits cut matches to every length, at every alignment.
    fn repeated(seed: u64, period: usize, length: usize) -> Vec<u8> {
        let pattern = noise(seed, period);
        let edits = noise(!seed, length);
        pattern
            .iter()
            .cycle()
            .zip(&edits)
            .enumerate()
            .map(|(index, (&byte, &edit))| {
                // A cheap index hash picks the edited positions.
                let pick = (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 54;
                if pick == 0 { edit } else { byte }
            })
            .collect()
    }

    #[test]
    fn empty_input_is_two_empty_blocks() {
        // Two empty blocks, the second final.
        //
        //     open block:  0, type 01, end code 0000000  -> 10 bits
        //     final block: 1, type 01, end code 0000000  -> 10 bits
        //
        // Twenty bits pad to three bytes.
        let stream = deflate(b"", 1);
        assert_eq!(stream, [0x02, 0x0c, 0x00]);
        assert_eq!(inflate(&stream), (Vec::new(), 3));
    }

    #[test]
    fn repetitive_logs_shrink() {
        // 1000 copies of one 38-byte line make 38000 bytes.
        let line = b"INFO axiom: imported block slot=12345\n";
        let input = line.repeat(1000);
        let stream = deflate(&input, input.len());
        // A 258-byte copy costs at most 26 bits, so 148 copies fit well under 1 KiB.
        assert!(stream.len() < 1024, "{}", stream.len());
        assert_eq!(inflate(&stream).0, input);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn random_bytes_round_trip(
            seed in any::<u64>(),
            length in 0usize..200_000,
            chunk in 1usize..100_000,
        ) {
            // Incompressible input, longer than one 64 KiB buffer, in arbitrary writes.
            let input = noise(seed, length);
            let stream = deflate(&input, chunk);
            prop_assert_eq!(inflate(&stream), (input, stream.len()));
        }

        #[test]
        fn repetitive_bytes_round_trip(
            seed in any::<u64>(),
            period in 1usize..300,
            length in 0usize..200_000,
            chunk in 1usize..100_000,
        ) {
            // A short random pattern repeated: long overlapping matches across buffer slides.
            let input = repeated(seed, period, length);
            let stream = deflate(&input, chunk);
            prop_assert_eq!(inflate(&stream), (input, stream.len()));
        }

        #[test]
        fn window_edge_repeats_round_trip(
            seed in any::<u64>(),
            period in (WINDOW - 300)..(WINDOW + 300),
            chunk in 1usize..100_000,
        ) {
            // A block near one window long, three times over.
            // Its repeats sit just inside or just beyond the farthest legal distance.
            let block = noise(seed, period);
            let input = block.repeat(3);
            let stream = deflate(&input, chunk);
            prop_assert_eq!(inflate(&stream), (input, stream.len()));
        }

        #[test]
        fn output_ignores_write_boundaries(
            seed in any::<u64>(),
            period in prop_oneof![1usize..3, 3usize..300],
            length in 0usize..150_000,
            chunk in 1usize..2_000,
        ) {
            // Tokens wait for a full lookahead, so the stream depends on the bytes alone.
            // Periods of one or two bytes put a candidate at every position.
            // A position left out of the index then shows in the next copy's distance.
            let input = repeated(seed, period, length);
            prop_assert_eq!(deflate(&input, chunk), deflate(&input, input.len().max(1)));
        }
    }
}
