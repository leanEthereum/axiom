//! Byte layouts of segment files, batch frames and entries.
//!
//! # Overview
//!
//! A segment file is a fixed header followed by frames.
//! A frame is one committed batch: a header, then its entries back to back.
//!
//! ```text
//!     segment file
//!     +-------------+---------+---------+-----+---------+
//!     | file header | frame 0 | frame 1 | ... | frame n |
//!     |  16 bytes   |         |         |     |         |
//!     +-------------+---------+---------+-----+---------+
//!
//!     file header
//!     +-------------------+-------------+-------------+
//!     | magic "AXIOMSEG"  | version u32 | segment u32 |
//!     |  8                |  4          |  4          |
//!     +-------------------+-------------+-------------+
//!
//!     frame
//!     +-----------+------------+--------------+---------+-----+---------+
//!     | crc32c    | length u64 | count u32    | entry 0 | ... | entry k |
//!     |  4        |  8         |  4           |         |     |         |
//!     +-----------+------------+--------------+---------+-----+---------+
//!       crc covers length and count; length counts the entry bytes only
//!
//!     entry
//!     +--------+------+-------+-------------+---------------+-----+-------+
//!     | crc32c | kind | table | key len u16 | value len u32 | key | value |
//!     |  4     |  1   |  1    |  2          |  4            |     |       |
//!     +--------+------+-------+-------------+---------------+-----+-------+
//!       crc covers every byte after itself, key and value included
//! ```
//!
//! Integers are little-endian.
//!
//! The frame checksum makes the length trustworthy before any entry is read.
//! A torn frame is then recognized by its length alone, without parsing garbage.
//!
//! Each entry carries its own checksum, so a read verifies one value without its frame.
//! Compaction also copies entries verbatim into new frames, checksum included.

use crate::crc::Crc32c;

/// Bytes of the header at the start of every segment and hint file.
pub(crate) const FILE_HEADER_LEN: u64 = 16;

/// Bytes of the header in front of every frame.
pub(crate) const FRAME_HEADER_LEN: usize = 16;

/// Bytes of the header in front of every entry's key and value.
pub(crate) const ENTRY_HEADER_LEN: usize = 12;

/// Version of the layout, bumped on any incompatible change.
const FORMAT_VERSION: u32 = 1;

/// What an entry does to its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Bind the key to the value that follows.
    Put,
    /// Remove the key; the entry carries an empty value and is called a tombstone.
    Delete,
}

impl Kind {
    /// Returns the byte stored on disk.
    ///
    /// Zero is never used, so a zero-filled region never parses as an entry.
    pub(crate) const fn to_byte(self) -> u8 {
        match self {
            Self::Put => 1,
            Self::Delete => 2,
        }
    }

    /// Parses a stored byte, rejecting every unassigned value.
    pub(crate) const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Put),
            2 => Some(Self::Delete),
            _ => None,
        }
    }
}

/// The header identifying a segment or hint file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileHeader {
    /// Eight bytes naming the file type.
    pub(crate) magic: [u8; 8],
    /// Segment the file belongs to, repeated from its name to catch misplaced files.
    pub(crate) segment: u32,
}

impl FileHeader {
    /// Magic of a segment file.
    pub(crate) const SEGMENT_MAGIC: [u8; 8] = *b"AXIOMSEG";

    /// Magic of a hint file.
    pub(crate) const HINT_MAGIC: [u8; 8] = *b"AXIOMHNT";

    /// Serializes the header.
    pub(crate) fn encode(self) -> [u8; FILE_HEADER_LEN as usize] {
        let mut out = [0; FILE_HEADER_LEN as usize];
        out[..8].copy_from_slice(&self.magic);
        out[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        out[12..].copy_from_slice(&self.segment.to_le_bytes());
        out
    }

    /// Parses a header, rejecting unknown versions.
    pub(crate) fn decode(bytes: [u8; FILE_HEADER_LEN as usize]) -> Option<Self> {
        let (magic, rest) = bytes.split_first_chunk::<8>()?;
        let (version, segment) = rest.split_first_chunk::<4>()?;
        let segment = segment.first_chunk::<4>()?;
        (u32::from_le_bytes(*version) == FORMAT_VERSION).then_some(Self {
            magic: *magic,
            segment: u32::from_le_bytes(*segment),
        })
    }
}

/// The header of one frame, the on-disk form of one batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FrameHeader {
    /// Bytes of entries following the header.
    pub(crate) len: u64,
    /// Number of entries following the header.
    pub(crate) count: u32,
}

impl FrameHeader {
    /// Serializes the header with its checksum.
    pub(crate) fn encode(self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0; FRAME_HEADER_LEN];
        out[4..12].copy_from_slice(&self.len.to_le_bytes());
        out[12..].copy_from_slice(&self.count.to_le_bytes());
        // The checksum goes in front and covers the twelve bytes after it.
        let crc = Crc32c::checksum(&out[4..]);
        out[..4].copy_from_slice(&crc.to_le_bytes());
        out
    }

    /// Parses a header, returning nothing when the checksum fails or the frame is empty.
    pub(crate) fn decode(bytes: [u8; FRAME_HEADER_LEN]) -> Option<Self> {
        let (crc, body) = bytes.split_first_chunk::<4>()?;
        if Crc32c::checksum(body) != u32::from_le_bytes(*crc) {
            return None;
        }
        let (len, count) = body.split_first_chunk::<8>()?;
        let count = u32::from_le_bytes(*count.first_chunk::<4>()?);
        // Batches are never committed empty, so a zero count marks garbage.
        (count > 0).then_some(Self {
            len: u64::from_le_bytes(*len),
            count,
        })
    }
}

/// The header of one entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EntryHeader {
    /// Checksum of every byte after it: the rest of the header, the key and the value.
    pub(crate) crc: u32,
    /// What the entry does to its key.
    pub(crate) kind: Kind,
    /// Identifier of the table the key belongs to.
    pub(crate) table: u8,
    /// Bytes of key.
    pub(crate) key_len: u16,
    /// Bytes of value, zero for a tombstone.
    pub(crate) value_len: u32,
}

impl EntryHeader {
    /// Serializes the header.
    pub(crate) fn encode(self) -> [u8; ENTRY_HEADER_LEN] {
        let mut out = [0; ENTRY_HEADER_LEN];
        out[..4].copy_from_slice(&self.crc.to_le_bytes());
        out[4..].copy_from_slice(&self.checked_part());
        out
    }

    /// Returns the eight header bytes the checksum covers.
    pub(crate) fn checked_part(self) -> [u8; 8] {
        let mut out = [0; 8];
        out[0] = self.kind.to_byte();
        out[1] = self.table;
        out[2..4].copy_from_slice(&self.key_len.to_le_bytes());
        out[4..].copy_from_slice(&self.value_len.to_le_bytes());
        out
    }

    /// Parses a header, rejecting unassigned kinds.
    ///
    /// The checksum is not verified here: it also covers the key and value, read separately.
    pub(crate) fn decode(bytes: [u8; ENTRY_HEADER_LEN]) -> Option<Self> {
        let (crc, rest) = bytes.split_first_chunk::<4>()?;
        let (&[kind, table], rest) = rest.split_first_chunk::<2>()?;
        let (key_len, value_len) = rest.split_first_chunk::<2>()?;
        Some(Self {
            crc: u32::from_le_bytes(*crc),
            kind: Kind::from_byte(kind)?,
            table,
            key_len: u16::from_le_bytes(*key_len),
            value_len: u32::from_le_bytes(*value_len.first_chunk::<4>()?),
        })
    }

    /// Returns the bytes the whole entry occupies on disk.
    pub(crate) const fn entry_len(self) -> u64 {
        entry_len(self.key_len as usize, self.value_len)
    }
}

/// Returns the bytes an entry with the given key and value lengths occupies on disk.
pub(crate) const fn entry_len(key_len: usize, value_len: u32) -> u64 {
    ENTRY_HEADER_LEN as u64 + key_len as u64 + value_len as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_header_round_trips_and_rejects_other_versions() {
        // Segment 7 of a segment file.
        let header = FileHeader {
            magic: FileHeader::SEGMENT_MAGIC,
            segment: 7,
        };
        let bytes = header.encode();
        assert_eq!(&bytes[..8], b"AXIOMSEG");
        assert_eq!(FileHeader::decode(bytes), Some(header));

        // Mutation: version 1 becomes version 2, a layout this code does not know.
        let mut future = bytes;
        future[8] = 2;
        assert_eq!(FileHeader::decode(future), None);
    }

    #[test]
    fn frame_header_round_trips_and_detects_damage() {
        // A frame of 3 entries holding 100 bytes.
        let header = FrameHeader { len: 100, count: 3 };
        let bytes = header.encode();
        assert_eq!(FrameHeader::decode(bytes), Some(header));

        // Mutation: flip a bit of the length, as a torn sector would.
        //
        //     length 100 -> 101, checksum unchanged -> rejected
        let mut torn = bytes;
        torn[4] ^= 1;
        assert_eq!(FrameHeader::decode(torn), None);

        // Sixteen zero bytes, the content of a preallocated tail, never parse.
        assert_eq!(FrameHeader::decode([0; FRAME_HEADER_LEN]), None);
    }

    #[test]
    fn entry_header_round_trips_and_rejects_unknown_kinds() {
        // A put of a 32-byte key and a 1 KiB value into table 3.
        let header = EntryHeader {
            crc: 0xdead_beef,
            kind: Kind::Put,
            table: 3,
            key_len: 32,
            value_len: 1024,
        };
        let bytes = header.encode();
        assert_eq!(EntryHeader::decode(bytes), Some(header));
        assert_eq!(header.entry_len(), 12 + 32 + 1024);

        // Mutation: kind byte 1 becomes 0, the value of zeroed space.
        let mut zeroed = bytes;
        zeroed[4] = 0;
        assert_eq!(EntryHeader::decode(zeroed), None);
    }
}
