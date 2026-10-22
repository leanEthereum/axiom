//! A reader that decodes a framed stream on the fly.

use std::io::{self, Read};

use super::{ChunkDecoder, ChunkHeader, chunk::ChunkType};
use crate::SnappyError;

/// Decompresses a framed stream read from an inner reader.
///
/// # Overview
///
/// It reads one chunk at a time and never reads past the chunk that ends the data asked for.
/// A req/resp payload followed by more stream data can therefore be read exactly.
///
/// Errors come back as I/O errors that carry the precise decoding error inside.
/// A truncated stream reports an unexpected end of file.
/// Every other decoding error reports invalid data.
#[derive(Debug)]
pub struct FrameDecoder<R: Read> {
    /// Source of the framed stream.
    inner: R,
    /// Decoding state across chunks, with the bound on the total.
    chunks: ChunkDecoder,
    /// Decompressed bytes of the current chunk.
    chunk: Vec<u8>,
    /// Bytes of the current chunk already handed to the caller.
    position: usize,
    /// Scratch space for one chunk body.
    body: Vec<u8>,
}

impl<R: Read> FrameDecoder<R> {
    /// A decoder reading from the given source, producing at most the given number of bytes.
    pub const fn new(inner: R, max_len: usize) -> Self {
        Self {
            inner,
            chunks: ChunkDecoder::new(max_len),
            chunk: Vec::new(),
            position: 0,
            body: Vec::new(),
        }
    }

    /// The source.
    pub const fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Returns the source, dropping any decoded bytes not yet read.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Reads and decodes the next chunk.
    ///
    /// Returns false at a clean end of stream, between chunks.
    fn next_chunk(&mut self) -> io::Result<bool> {
        let mut header = [0; ChunkHeader::LEN];
        match Self::read_full(&mut self.inner, &mut header)? {
            // End of stream between chunks: clean, once the identifier was seen.
            0 if self.chunks.started() => return Ok(false),
            0 => return Err(SnappyError::MissingStreamIdentifier.into()),
            ChunkHeader::LEN => {}
            read => {
                return Err(SnappyError::UnexpectedEnd {
                    needed: ChunkHeader::LEN,
                    available: read,
                }
                .into());
            }
        }
        let header = self.chunks.header(header)?;
        let len = header.len;

        // Skippable chunks are streamed past, never buffered, whatever their length.
        if header.chunk_type == ChunkType::Skippable {
            let skipped = io::copy(&mut (&mut self.inner).take(len as u64), &mut io::sink())?;
            if skipped != len as u64 {
                // Invariant: the reader stops at len bytes, so the count fits a usize.
                return Err(SnappyError::UnexpectedEnd {
                    needed: len,
                    available: skipped as usize,
                }
                .into());
            }
            return Ok(true);
        }

        // Data and identifier bodies are bounded by the header check above.
        self.body.resize(len, 0);
        let read = Self::read_full(&mut self.inner, &mut self.body)?;
        if read != len {
            return Err(SnappyError::UnexpectedEnd {
                needed: len,
                available: read,
            }
            .into());
        }
        self.chunk.clear();
        self.position = 0;
        self.chunks.body(header, &self.body, &mut self.chunk)?;
        Ok(true)
    }

    /// Reads until the buffer is full or the source ends, and returns the count read.
    ///
    /// Unlike the standard exact read, a short count is not an error.
    /// The caller then tells a clean end between chunks from a cut inside one.
    fn read_full(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            match reader.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(err),
            }
        }
        Ok(filled)
    }
}

impl<R: Read> Read for FrameDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Refill until a chunk with data arrives or the stream ends.
        while self.position == self.chunk.len() {
            if !self.next_chunk()? {
                return Ok(0);
            }
        }
        let available = &self.chunk[self.position..];
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.position += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::frame::{FrameEncoder, compress};

    /// The decoding error inside an I/O error.
    fn inner_error(err: &io::Error) -> Option<&SnappyError> {
        err.get_ref()?.downcast_ref()
    }

    #[test]
    fn writer_and_reader_round_trip_across_chunk_boundaries() {
        // 150000 bytes written in odd-sized pieces: three chunks, the last partial.
        let data: Vec<u8> = (0..150_000_u32)
            .map(|i| (i * 7 / 13).to_le_bytes()[0])
            .collect();
        let mut encoder = FrameEncoder::new(Vec::new());
        for piece in data.chunks(1_234) {
            encoder.write_all(piece).unwrap();
        }
        let framed = encoder.finish().unwrap();

        // The writer and the one-shot function produce the same stream.
        assert_eq!(framed, compress(&data));

        let mut decoded = Vec::new();
        FrameDecoder::new(&framed[..], data.len())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn reader_stops_at_the_end_of_the_requested_bytes() {
        // Two framed payloads back to back on one stream, as req/resp sends them.
        let mut wire = compress(b"first");
        let second = compress(b"second");
        wire.extend_from_slice(&second);

        // Reading exactly 5 bytes consumes exactly the first payload's chunks.
        let mut source = &wire[..];
        let mut first = [0; 5];
        FrameDecoder::new(&mut source, 5)
            .read_exact(&mut first)
            .unwrap();
        assert_eq!(&first, b"first");
        assert_eq!(source, &second[..]);
    }

    #[test]
    fn empty_stream_with_identifier_reads_nothing() {
        let framed = compress(b"");
        let mut decoded = Vec::new();
        let n = FrameDecoder::new(&framed[..], 0)
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn errors_carry_the_decoding_error() {
        // Truncation is an unexpected end of file.
        let framed = compress(b"abc");
        let err = FrameDecoder::new(&framed[..framed.len() - 1], 10)
            .read_to_end(&mut Vec::new())
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(
            inner_error(&err),
            Some(&SnappyError::UnexpectedEnd {
                needed: 7,
                available: 6
            })
        );

        // The total bound is invalid data.
        let err = FrameDecoder::new(&framed[..], 2)
            .read_to_end(&mut Vec::new())
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            inner_error(&err),
            Some(&SnappyError::TooLarge { len: 3, max: 2 })
        );

        // A missing identifier, including on an empty source.
        let err = FrameDecoder::new(&[][..], 10)
            .read_to_end(&mut Vec::new())
            .unwrap_err();
        assert_eq!(
            inner_error(&err),
            Some(&SnappyError::MissingStreamIdentifier)
        );
    }

    #[test]
    fn huge_skippable_chunk_is_streamed_past() {
        // A skippable chunk of 2^24 - 1 bytes, the largest a header can declare.
        let mut framed = compress(b"");
        framed.extend_from_slice(&[0x80, 0xff, 0xff, 0xff]);
        framed.resize(framed.len() + 0xff_ffff, 0);
        framed.extend_from_slice(&compress(b"x")[10..]);

        let mut decoded = Vec::new();
        FrameDecoder::new(&framed[..], 1)
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, b"x");
    }
}
