//! One segment file: an append-only run of frames.

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::unix::fs::FileExt,
};

use axiom_snappy::Crc32c;

use crate::{
    Error,
    directory::Directory,
    format::{ENTRY_HEADER_LEN, EntryHeader, FILE_HEADER_LEN, FileHeader, Kind},
    slot::Location,
};

/// An open segment file.
///
/// Reads use positional I/O, so any number of threads read one segment without a shared cursor.
/// Snapshots hold segments by reference count.
/// A segment deleted by compaction stays readable until the last snapshot drops it.
#[derive(Debug)]
pub(crate) struct Segment {
    /// Identifier, also the file name and the replay order.
    id: u32,
    /// The open file.
    file: File,
}

impl Segment {
    /// Creates a new segment file holding only its header, durably.
    pub(crate) fn create(directory: &Directory, id: u32) -> io::Result<Self> {
        // Refuse to reuse a name: an existing file would mean the identifier counter is wrong.
        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(directory.segment_path(id))?;
        let segment = Self { id, file };
        segment.write_header()?;
        directory.sync()?;
        Ok(segment)
    }

    /// Opens an existing segment file.
    pub(crate) fn open(directory: &Directory, id: u32) -> io::Result<Self> {
        let file = File::options()
            .read(true)
            .write(true)
            .open(directory.segment_path(id))?;
        Ok(Self { id, file })
    }

    /// Returns the identifier.
    pub(crate) const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the open file, for sequential scans.
    pub(crate) const fn file(&self) -> &File {
        &self.file
    }

    /// Returns the current length of the file.
    pub(crate) fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    /// Writes the file header and makes it durable.
    pub(crate) fn write_header(&self) -> io::Result<()> {
        let header = FileHeader {
            magic: FileHeader::SEGMENT_MAGIC,
            segment: self.id,
        };
        self.file.write_all_at(&header.encode(), 0)?;
        self.file.sync_all()
    }

    /// Returns whether the file starts with this segment's header.
    pub(crate) fn has_valid_header(&self) -> io::Result<bool> {
        let mut bytes = [0; FILE_HEADER_LEN as usize];
        self.file.read_exact_at(&mut bytes, 0)?;
        Ok(FileHeader::decode(bytes)
            == Some(FileHeader {
                magic: FileHeader::SEGMENT_MAGIC,
                segment: self.id,
            }))
    }

    /// Writes bytes at an offset.
    pub(crate) fn write_at(&self, bytes: &[u8], offset: u64) -> io::Result<()> {
        self.file.write_all_at(bytes, offset)
    }

    /// Flushes written data to stable storage.
    ///
    /// Data sync skips metadata such as timestamps, but includes the file length.
    pub(crate) fn sync(&self) -> io::Result<()> {
        self.file.sync_data()
    }

    /// Cuts the file at a length and makes the cut durable.
    pub(crate) fn truncate(&self, len: u64) -> io::Result<()> {
        self.file.set_len(len)?;
        self.file.sync_all()
    }

    /// Copies a byte range of another segment into this one.
    ///
    /// On Linux the standard library turns this into copy_file_range.
    /// The bytes then move inside the kernel, or are shared as extents on copy-on-write filesystems.
    pub(crate) fn copy_from(
        &self,
        source: &Self,
        source_offset: u64,
        offset: u64,
        len: u64,
    ) -> io::Result<()> {
        // Positioning both cursors is safe: only the single writer ever moves them.
        let mut reader = &source.file;
        reader.seek(SeekFrom::Start(source_offset))?;
        let mut writer = &self.file;
        writer.seek(SeekFrom::Start(offset))?;
        let copied = io::copy(&mut reader.take(len), &mut writer)?;
        if copied == len {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "source segment ended inside a live entry",
            ))
        }
    }

    /// Reads and verifies the value of a put entry.
    ///
    /// # Algorithm
    ///
    /// ```text
    ///     read 1:  | header 12 | key |             small, checked against the index
    ///     read 2:                    | value ... | straight into the returned buffer
    ///     crc32c(header[4..] || key || value) must equal header[..4]
    /// ```
    ///
    /// Two reads avoid moving a large value after the fact.
    pub(crate) fn read_value(
        &self,
        table: u8,
        key: &[u8],
        location: Location,
    ) -> Result<Vec<u8>, Error> {
        let corrupt = |reason| Error::Corruption {
            segment: self.id,
            offset: location.offset,
            reason,
        };
        let short_read = |err: io::Error| {
            if err.kind() == io::ErrorKind::UnexpectedEof {
                corrupt("entry extends past the end of the segment")
            } else {
                Error::Io(err)
            }
        };

        // Read 1: the header and the key.
        let mut head = vec![0; ENTRY_HEADER_LEN + key.len()];
        self.file
            .read_exact_at(&mut head, location.offset)
            .map_err(short_read)?;
        let header = head
            .first_chunk::<ENTRY_HEADER_LEN>()
            .copied()
            .and_then(EntryHeader::decode)
            .ok_or_else(|| corrupt("unknown entry kind"))?;

        // The entry must be the one the index describes, field by field.
        let matches = header.kind == Kind::Put
            && header.table == table
            && usize::from(header.key_len) == key.len()
            && header.value_len == location.value_len
            && head[ENTRY_HEADER_LEN..] == *key;
        if !matches {
            return Err(corrupt("entry does not match the index"));
        }

        // Read 2: the value, into a buffer of its exact size.
        let mut value = vec![0; location.value_len as usize];
        let value_offset = location.offset + head.len() as u64;
        self.file
            .read_exact_at(&mut value, value_offset)
            .map_err(short_read)?;

        // The checksum skips its own four bytes and covers everything else.
        let mut crc = Crc32c::new();
        crc.update(&head[4..]);
        crc.update(&value);
        if crc.finish() != header.crc {
            return Err(corrupt("entry checksum mismatch"));
        }
        Ok(value)
    }
}
