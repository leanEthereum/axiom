//! Hint files: a sealed segment's index, so recovery need not read its values.
//!
//! # Overview
//!
//! Rebuilding the index from segments alone means reading every byte ever written.
//! A store holding a few hundred beacon states would read tens of gigabytes at each start.
//! Bitcask's answer is a hint file per sealed segment: the entry metadata, without values.
//!
//! ```text
//!     hint file
//!     +-------------+----------+-----+----------+--------+
//!     | file header | record 0 | ... | record n | crc32c |
//!     |  16         |          |     |          |  4     |
//!     +-------------+----------+-----+----------+--------+
//!       magic "AXIOMHNT"           crc covers every byte before it
//!
//!     record
//!     +------+-------+-------------+---------------+------------+-----+
//!     | kind | table | key len u16 | value len u32 | offset u64 | key |
//!     |  1   |  1    |  2          |  4            |  8         |     |
//!     +------+-------+-------------+---------------+------------+-----+
//! ```
//!
//! A hint is written under a temporary name, synced, then renamed into place.
//! Rename is atomic, so a hint either exists whole or not at all.
//! A missing or damaged hint is never an error: recovery scans the segment and rewrites it.

use std::{
    fs::{self, File},
    io::{self, ErrorKind, Write},
};

use axiom_snappy::Crc32c;

use crate::{
    directory::Directory,
    format::{FILE_HEADER_LEN, FileHeader, Kind},
    record::Record,
};

/// Bytes of a record before its key.
const RECORD_HEADER_LEN: usize = 16;

/// Bytes of the trailing checksum.
const CHECKSUM_LEN: usize = 4;

/// Reader and writer of hint files.
#[derive(Debug)]
pub(crate) struct Hint;

impl Hint {
    /// Writes the hint of a sealed segment, atomically and durably.
    pub(crate) fn write(directory: &Directory, segment: u32, records: &[Record]) -> io::Result<()> {
        let bytes = Self::encode(segment, records);
        let temporary = directory.hint_temporary_path(segment);
        let mut file = File::create(&temporary)?;
        file.write_all(&bytes)?;
        // The content must be durable before the rename can publish it.
        file.sync_all()?;
        fs::rename(&temporary, directory.hint_path(segment))?;
        directory.sync()
    }

    /// Reads the hint of a segment, or nothing when it is missing or damaged.
    pub(crate) fn read(directory: &Directory, segment: u32) -> io::Result<Option<Vec<Record>>> {
        match fs::read(directory.hint_path(segment)) {
            Ok(bytes) => Ok(Self::decode(segment, &bytes)),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Deletes the hint of a segment, if any.
    pub(crate) fn remove(directory: &Directory, segment: u32) -> io::Result<()> {
        match fs::remove_file(directory.hint_path(segment)) {
            Err(err) if err.kind() != ErrorKind::NotFound => Err(err),
            _ => Ok(()),
        }
    }

    /// Serializes a hint.
    fn encode(segment: u32, records: &[Record]) -> Vec<u8> {
        let header = FileHeader {
            magic: FileHeader::HINT_MAGIC,
            segment,
        };
        let mut bytes = header.encode().to_vec();
        for record in records {
            bytes.push(record.kind.to_byte());
            bytes.push(record.table);
            // Invariant: keys come from entries whose own length field is 16 bits.
            bytes.extend_from_slice(&(record.key.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&record.value_len.to_le_bytes());
            bytes.extend_from_slice(&record.offset.to_le_bytes());
            bytes.extend_from_slice(&record.key);
        }
        let crc = Crc32c::checksum(&bytes);
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes
    }

    /// Parses a hint, rejecting any damage.
    fn decode(segment: u32, bytes: &[u8]) -> Option<Vec<Record>> {
        // The trailing checksum vouches for everything else, so check it first.
        let (body, crc) = bytes.split_last_chunk::<CHECKSUM_LEN>()?;
        if Crc32c::checksum(body) != u32::from_le_bytes(*crc) {
            return None;
        }
        let (header, mut rest) = body.split_first_chunk::<{ FILE_HEADER_LEN as usize }>()?;
        let expected = FileHeader {
            magic: FileHeader::HINT_MAGIC,
            segment,
        };
        if FileHeader::decode(*header)? != expected {
            return None;
        }

        let mut records = Vec::new();
        while !rest.is_empty() {
            //     | kind | table | key len | value len | offset | key ... |
            //       0      1       2..4      4..8        8..16    16..
            let (fixed, tail) = rest.split_first_chunk::<RECORD_HEADER_LEN>()?;
            let key_len = usize::from(u16::from_le_bytes([fixed[2], fixed[3]]));
            let (key, tail) = tail.split_at_checked(key_len)?;
            records.push(Record {
                kind: Kind::from_byte(fixed[0])?,
                table: fixed[1],
                key: key.into(),
                value_len: u32::from_le_bytes(*fixed[4..8].first_chunk()?),
                offset: u64::from_le_bytes(*fixed[8..].first_chunk()?),
            });
            rest = tail;
        }
        Some(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records() -> Vec<Record> {
        // Fixture state: a put of "alpha" with a 4 KiB value, then a tombstone for "beta".
        vec![
            Record {
                kind: Kind::Put,
                table: 1,
                key: b"alpha".to_vec().into_boxed_slice(),
                value_len: 4096,
                offset: 32,
            },
            Record {
                kind: Kind::Delete,
                table: 2,
                key: b"beta".to_vec().into_boxed_slice(),
                value_len: 0,
                offset: 4157,
            },
        ]
    }

    #[test]
    fn hint_round_trips() {
        let bytes = Hint::encode(9, &records());
        // 16 header + (16 + 5) + (16 + 4) + 4 checksum = 61 bytes.
        assert_eq!(bytes.len(), 61);
        assert_eq!(Hint::decode(9, &bytes), Some(records()));
    }

    #[test]
    fn every_damage_is_rejected() {
        let bytes = Hint::encode(9, &records());

        // A hint filed under the wrong segment.
        assert_eq!(Hint::decode(10, &bytes), None);

        // Every single-byte flip and every truncation fails the checksum.
        for position in 0..bytes.len() {
            let mut flipped = bytes.clone();
            flipped[position] ^= 0x40;
            assert_eq!(Hint::decode(9, &flipped), None, "flip at {position}");
            assert_eq!(
                Hint::decode(9, &bytes[..position]),
                None,
                "cut at {position}"
            );
        }
    }
}
