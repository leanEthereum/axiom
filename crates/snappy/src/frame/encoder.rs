//! A writer that frames everything written through it.

use std::io::{self, Write};

use super::{MAX_CHUNK_DATA_LEN, STREAM_IDENTIFIER, encode_chunk};

/// Compresses bytes written to it into a framed stream on an inner writer.
///
/// Input is buffered up to one full chunk of 64 KiB.
/// Flushing emits the buffered bytes as a shorter chunk.
/// Buffered bytes are lost unless a flush or the finishing call runs.
#[derive(Debug)]
pub struct FrameEncoder<W: Write> {
    /// Destination of the framed stream.
    inner: W,
    /// Uncompressed bytes waiting to fill a chunk.
    pending: Vec<u8>,
    /// Scratch space for one encoded chunk.
    chunk: Vec<u8>,
    /// Whether the stream identifier went out already.
    started: bool,
}

impl<W: Write> FrameEncoder<W> {
    /// An encoder writing to the given destination.
    pub const fn new(inner: W) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            chunk: Vec::new(),
            started: false,
        }
    }

    /// The destination.
    pub const fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Emits everything buffered and returns the destination.
    ///
    /// A stream with no data still gets its identifier.
    pub fn finish(mut self) -> io::Result<W> {
        self.emit_pending()?;
        self.start()?;
        Ok(self.inner)
    }

    /// Writes the stream identifier, once.
    fn start(&mut self) -> io::Result<()> {
        if !self.started {
            self.inner.write_all(&STREAM_IDENTIFIER)?;
            self.started = true;
        }
        Ok(())
    }

    /// Encodes the buffered bytes as one chunk, if there are any.
    fn emit_pending(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.start()?;
        self.chunk.clear();
        encode_chunk(&self.pending, &mut self.chunk);
        self.inner.write_all(&self.chunk)?;
        self.pending.clear();
        Ok(())
    }
}

impl<W: Write> Write for FrameEncoder<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Take as much as fits in the current chunk.
        let room = MAX_CHUNK_DATA_LEN - self.pending.len();
        let taken = buf.len().min(room);
        self.pending.extend_from_slice(&buf[..taken]);

        // A full chunk goes out right away, so the buffer never exceeds 64 KiB.
        if self.pending.len() == MAX_CHUNK_DATA_LEN {
            self.emit_pending()?;
        }
        Ok(taken)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit_pending()?;
        self.inner.flush()
    }
}
