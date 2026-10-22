//! Write batches, the unit of atomicity.

use axiom_snappy::Crc32c;

use crate::{
    Error, Table,
    format::{ENTRY_HEADER_LEN, EntryHeader, FRAME_HEADER_LEN, FrameHeader, Kind},
};

/// A group of writes, across any tables, that commits all at once or not at all.
///
/// The batch encodes each operation straight into its on-disk frame.
/// Committing it is then one positional write of a contiguous buffer.
///
/// Operations apply in insertion order, so a later write to a key wins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    /// The encoded frame: a valid header followed by every entry so far.
    frame: Vec<u8>,
    /// Number of entries in the frame.
    count: u32,
}

impl Batch {
    /// Creates an empty batch.
    #[must_use]
    pub fn new() -> Self {
        let mut batch = Self {
            frame: Vec::new(),
            count: 0,
        };
        batch.clear();
        batch
    }

    /// Binds a key to a value in a table.
    ///
    /// # Errors
    ///
    /// Fails when the key exceeds 65535 bytes or the value exceeds 4294967295 bytes.
    pub fn put(&mut self, table: Table, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.push(Kind::Put, table, key, value)
    }

    /// Removes a key from a table, whether or not it is present.
    ///
    /// # Errors
    ///
    /// Fails when the key exceeds 65535 bytes.
    pub fn delete(&mut self, table: Table, key: &[u8]) -> Result<(), Error> {
        self.push(Kind::Delete, table, key, &[])
    }

    /// Returns the number of operations in the batch.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    /// Returns whether the batch holds no operation.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Removes every operation, keeping the allocation for reuse.
    pub fn clear(&mut self) {
        self.frame.clear();
        self.count = 0;
        // Reserve the frame header up front, so the frame never needs a second buffer.
        self.frame.extend_from_slice(&[0; FRAME_HEADER_LEN]);
        self.seal_header();
    }

    /// Returns the frame exactly as it goes to disk.
    pub(crate) fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// Iterates the operations in commit order.
    pub(crate) fn entries(&self) -> Entries<'_> {
        Entries {
            frame: &self.frame,
            position: FRAME_HEADER_LEN,
        }
    }

    /// Checks that every operation targets a table identifier below a count.
    pub(crate) fn tables_within(&self, table_count: usize) -> Result<(), Error> {
        for entry in self.entries() {
            // Identifier zero is the catalog, reachable only through table creation.
            if usize::from(entry.table.id()) >= table_count {
                return Err(Error::UnknownTable(entry.table));
            }
        }
        Ok(())
    }

    /// Appends one encoded entry.
    fn push(&mut self, kind: Kind, table: Table, key: &[u8], value: &[u8]) -> Result<(), Error> {
        // Validate every length before touching the buffer, so a failure leaves it unchanged.
        let key_len = u16::try_from(key.len()).map_err(|_| Error::KeyTooLong(key.len()))?;
        let value_len = u32::try_from(value.len()).map_err(|_| Error::ValueTooLong(value.len()))?;
        let count = self.count.checked_add(1).ok_or(Error::BatchTooLarge)?;

        // The checksum covers the header bytes after it, then the key, then the value.
        let mut header = EntryHeader {
            crc: 0,
            kind,
            table: table.id(),
            key_len,
            value_len,
        };
        let mut crc = Crc32c::new();
        crc.update(&header.checked_part());
        crc.update(key);
        crc.update(value);
        header.crc = crc.finish();

        // One reservation, then three copies: header, key, value.
        self.frame
            .reserve(ENTRY_HEADER_LEN + key.len() + value.len());
        self.frame.extend_from_slice(&header.encode());
        self.frame.extend_from_slice(key);
        self.frame.extend_from_slice(value);
        self.count = count;
        self.seal_header();
        Ok(())
    }

    /// Rewrites the frame header so the buffer is always ready to commit.
    fn seal_header(&mut self) {
        let header = FrameHeader {
            len: (self.frame.len() - FRAME_HEADER_LEN) as u64,
            count: self.count,
        };
        self.frame[..FRAME_HEADER_LEN].copy_from_slice(&header.encode());
    }
}

impl Default for Batch {
    fn default() -> Self {
        Self::new()
    }
}

/// One operation of a batch, borrowed from its frame.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BatchEntry<'a> {
    /// What the operation does.
    pub(crate) kind: Kind,
    /// Table the key belongs to.
    pub(crate) table: Table,
    /// The key.
    pub(crate) key: &'a [u8],
    /// The value, empty for a delete.
    pub(crate) value: &'a [u8],
    /// Offset of the entry from the start of the frame, frame header included.
    pub(crate) position: u64,
}

/// Iterator over the operations of a batch.
#[derive(Clone, Debug)]
pub(crate) struct Entries<'a> {
    /// The encoded frame.
    frame: &'a [u8],
    /// Offset of the next entry.
    position: usize,
}

impl<'a> Iterator for Entries<'a> {
    type Item = BatchEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Invariant: the frame was encoded by this module, so every header parses.
        let start = self.position;
        let header = EntryHeader::decode(*self.frame.get(start..)?.first_chunk()?)?;

        //     | header 12 | key key_len | value value_len |
        //     ^start      ^key_start    ^value_start      ^end
        let key_start = start + ENTRY_HEADER_LEN;
        let value_start = key_start + usize::from(header.key_len);
        let end = value_start + header.value_len as usize;
        self.position = end;
        Some(BatchEntry {
            kind: header.kind,
            table: Table::from_id(header.table),
            key: self.frame.get(key_start..value_start)?,
            value: self.frame.get(value_start..end)?,
            position: start as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_batch_is_a_valid_empty_frame() {
        // An empty batch still carries a 16-byte header claiming 0 bytes and 0 entries.
        let batch = Batch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.frame().len(), FRAME_HEADER_LEN);
        assert_eq!(batch.entries().count(), 0);
    }

    #[test]
    fn entries_decode_in_insertion_order_with_positions() {
        // Fixture state: put 3-byte value under "a", then delete "bc", both in table 1.
        let table = Table::from_id(1);
        let mut batch = Batch::new();
        batch.put(table, b"a", b"xyz").unwrap();
        batch.delete(table, b"bc").unwrap();
        assert_eq!(batch.len(), 2);

        //     frame header 16 | put: 12 + 1 + 3 = 16 | delete: 12 + 2 + 0 = 14
        //     positions:        16                     32
        let entries: Vec<_> = batch.entries().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            (
                entries[0].kind,
                entries[0].key,
                entries[0].value,
                entries[0].position
            ),
            (Kind::Put, &b"a"[..], &b"xyz"[..], 16)
        );
        assert_eq!(
            (
                entries[1].kind,
                entries[1].key,
                entries[1].value,
                entries[1].position
            ),
            (Kind::Delete, &b"bc"[..], &b""[..], 32)
        );

        // The header always describes the current content: 30 entry bytes, 2 entries.
        let header = FrameHeader::decode(*batch.frame().first_chunk().unwrap()).unwrap();
        assert_eq!(header, FrameHeader { len: 30, count: 2 });
    }

    #[test]
    fn oversized_key_is_rejected_without_changing_the_batch() {
        // 65536 bytes overflow the 16-bit key length field by one.
        let mut batch = Batch::new();
        let key = vec![0; 65_536];
        assert!(matches!(
            batch.put(Table::from_id(1), &key, b""),
            Err(Error::KeyTooLong(65_536))
        ));
        assert_eq!(batch, Batch::new());

        // 65535 bytes is the largest key that fits.
        batch.put(Table::from_id(1), &key[1..], b"").unwrap();
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn clear_resets_to_an_empty_frame() {
        let mut batch = Batch::new();
        batch.put(Table::from_id(1), b"k", b"v").unwrap();
        batch.clear();
        assert_eq!(batch, Batch::new());
    }

    #[test]
    fn unknown_tables_are_reported() {
        // A store with tables 0 and 1 cannot accept a write into table 2.
        let mut batch = Batch::new();
        batch.put(Table::from_id(1), b"k", b"v").unwrap();
        batch.put(Table::from_id(2), b"k", b"v").unwrap();
        assert!(matches!(
            batch.tables_within(2),
            Err(Error::UnknownTable(table)) if table == Table::from_id(2)
        ));
        assert!(batch.tables_within(3).is_ok());
    }
}
