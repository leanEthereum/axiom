//! The gzip member: a fixed header, a deflate stream, and a checksum trailer.
//!
//! Source: RFC 1952 section 2.3.

use std::io::{self, Write};

use crate::logging::gzip::{crc32::Crc32, deflate::Deflater};

/// The member header, with no optional fields.
///
/// Source: RFC 1952 section 2.3.1.
///
/// ```text
///     ID1 ID2   0x1f 0x8b   the gzip magic
///     CM        8           deflate
///     FLG       0           no name, comment, extra field, or header checksum
///     MTIME     0           no timestamp, so equal input gives equal output
///     XFL       0           no claim about the compression level
///     OS        255         unknown operating system
/// ```
const HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];

/// Compresses a byte stream into one gzip member on a sink.
#[derive(Debug)]
pub(crate) struct GzipWriter<W> {
    /// The deflate stage, which owns the sink.
    deflater: Deflater<W>,

    /// The checksum of the uncompressed bytes.
    crc: Crc32,

    /// The uncompressed length, modulo 2^32 as the trailer stores it.
    size: u32,
}

impl<W: Write> GzipWriter<W> {
    /// Writes the header and starts the member.
    pub(crate) fn new(mut sink: W) -> io::Result<Self> {
        sink.write_all(&HEADER)?;
        Ok(Self {
            deflater: Deflater::new(sink),
            crc: Crc32::default(),
            size: 0,
        })
    }

    /// Ends the member with its trailer and returns the sink.
    pub(crate) fn finish(self) -> io::Result<W> {
        let mut sink = self.deflater.finish()?;
        // The trailer: the checksum, then the length, both little-endian.
        sink.write_all(&self.crc.value().to_le_bytes())?;
        sink.write_all(&self.size.to_le_bytes())?;
        Ok(sink)
    }
}

impl<W: Write> Write for GzipWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.deflater.write(bytes)?;
        self.crc.update(bytes);
        // The trailer keeps the length modulo 2^32, so the truncation is the format.
        self.size = self.size.wrapping_add(bytes.len() as u32);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Compressed bytes reach the sink in large batches, and all of them at the end.
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::logging::gzip::deflate::tests::inflate;

    /// Decodes one gzip member, checking its header, checksum, and length.
    pub(in crate::logging) fn gunzip(member: &[u8]) -> Vec<u8> {
        assert_eq!(member[..10], HEADER);
        let (bytes, read) = inflate(&member[10..]);
        let trailer = &member[10 + read..];
        let mut crc = Crc32::default();
        crc.update(&bytes);
        let mut expected = crc.value().to_le_bytes().to_vec();
        expected.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        assert_eq!(trailer, expected);
        bytes
    }

    /// One member holding the given bytes.
    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut writer = GzipWriter::new(Vec::new()).unwrap();
        writer.write_all(bytes).unwrap();
        writer.finish().unwrap()
    }

    #[test]
    fn empty_member_is_the_header_two_empty_blocks_and_a_zero_trailer() {
        // 10 header bytes, 3 deflate bytes, then CRC 0 and length 0.
        let mut expected = HEADER.to_vec();
        expected.extend_from_slice(&[0x02, 0x0c, 0x00]);
        expected.extend_from_slice(&[0; 8]);
        assert_eq!(gzip(b""), expected);
    }

    #[test]
    fn member_round_trips_with_its_trailer() {
        // The nine digits: CRC 0xcbf43926 and length 9 close the member.
        let member = gzip(b"123456789");
        assert_eq!(
            member[member.len() - 8..],
            [0x26, 0x39, 0xf4, 0xcb, 9, 0, 0, 0]
        );
        assert_eq!(gunzip(&member), b"123456789");
    }
}
