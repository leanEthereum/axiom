//! Sequential verification of a segment, the core of crash recovery.

use std::io::{self, BufRead, BufReader, Seek, SeekFrom};

use axiom_snappy::Crc32c;

use crate::{
    format::{ENTRY_HEADER_LEN, EntryHeader, FILE_HEADER_LEN, FRAME_HEADER_LEN, FrameHeader},
    record::Record,
    segment::Segment,
};

/// Read buffer of a scan.
///
/// One mebibyte amortizes system calls while bounding memory, whatever the value sizes.
const SCAN_BUFFER: usize = 1 << 20;

/// The outcome of reading a segment from its header to its end.
#[derive(Debug)]
pub(crate) struct Scan {
    /// Metadata of every entry in every whole, verified frame, in log order.
    pub(crate) records: Vec<Record>,
    /// Length of the verified prefix: the file header plus every whole frame.
    pub(crate) valid_len: u64,
    /// The first rule broken after the verified prefix, if the file does not end there.
    pub(crate) damage: Option<&'static str>,
}

impl Scan {
    /// Verifies every frame of a segment and collects its records.
    ///
    /// # Algorithm
    ///
    /// ```text
    ///     | file header | frame 0 ok | frame 1 ok | frame 2 torn ......|
    /// ```
    ///
    /// The valid length ends where the torn frame starts, short of the file end.
    ///
    /// A frame counts only if all four checks pass:
    ///
    /// - its header checksum holds,
    /// - its length fits in the file,
    /// - every entry checksum holds,
    /// - its entries fill its length exactly.
    ///
    /// The scan stops at the first frame that fails.
    ///
    /// # Performance
    ///
    /// Values stream through the checksum from the read buffer and are never held whole.
    pub(crate) fn run(segment: &Segment) -> io::Result<Self> {
        let file_len = segment.len()?;
        let mut reader = BufReader::with_capacity(SCAN_BUFFER, segment.file());
        reader.seek(SeekFrom::Start(FILE_HEADER_LEN))?;

        let mut records = Vec::new();
        let mut position = FILE_HEADER_LEN;
        let damage = loop {
            // A clean end: the file stops exactly after a whole frame.
            if position == file_len {
                break None;
            }
            match Self::frame(&mut reader, position, file_len)? {
                Ok((frame_records, frame_end)) => {
                    records.extend(frame_records);
                    position = frame_end;
                }
                Err(reason) => break Some(reason),
            }
        };
        Ok(Self {
            records,
            valid_len: position,
            damage,
        })
    }

    /// Verifies one frame starting at a position, returning its records and its end.
    ///
    /// The outer result carries read failures, the inner one the rule a frame broke.
    fn frame<R: BufRead>(
        reader: &mut R,
        start: u64,
        file_len: u64,
    ) -> io::Result<Result<(Vec<Record>, u64), &'static str>> {
        // Phase 1: the frame header, trusted only once its checksum holds.
        let remaining = file_len - start;
        if remaining < FRAME_HEADER_LEN as u64 {
            return Ok(Err("torn frame header"));
        }
        let mut header = [0; FRAME_HEADER_LEN];
        reader.read_exact(&mut header)?;
        let Some(frame) = FrameHeader::decode(header) else {
            return Ok(Err("frame header checksum mismatch"));
        };
        let body_start = start + FRAME_HEADER_LEN as u64;
        if frame.len > file_len - body_start {
            // The header made it to disk but part of the body did not.
            return Ok(Err("torn frame body"));
        }
        let end = body_start + frame.len;

        // Phase 2: every entry, each checked against its own checksum.
        // Each entry takes at least 12 bytes, which caps the reservation whatever the count says.
        let capacity = (frame.count as usize).min((frame.len / ENTRY_HEADER_LEN as u64) as usize);
        let mut records = Vec::with_capacity(capacity);
        let mut offset = body_start;
        for _ in 0..frame.count {
            if end - offset < ENTRY_HEADER_LEN as u64 {
                return Ok(Err("entry header overruns its frame"));
            }
            let mut bytes = [0; ENTRY_HEADER_LEN];
            reader.read_exact(&mut bytes)?;
            let Some(entry) = EntryHeader::decode(bytes) else {
                return Ok(Err("unknown entry kind"));
            };
            if entry.entry_len() > end - offset {
                return Ok(Err("entry overruns its frame"));
            }

            let mut key = vec![0; usize::from(entry.key_len)];
            reader.read_exact(&mut key)?;
            let mut crc = Crc32c::new();
            crc.update(&entry.checked_part());
            crc.update(&key);
            Self::absorb(reader, &mut crc, u64::from(entry.value_len))?;
            if crc.finish() != entry.crc {
                return Ok(Err("entry checksum mismatch"));
            }

            records.push(Record {
                kind: entry.kind,
                table: entry.table,
                key: key.into_boxed_slice(),
                value_len: entry.value_len,
                offset,
            });
            offset += entry.entry_len();
        }

        // Phase 3: the entries must fill the frame exactly, no slack and no overlap.
        if offset != end {
            return Ok(Err("frame length disagrees with its entries"));
        }
        Ok(Ok((records, end)))
    }

    /// Feeds a run of bytes from the reader into a checksum without collecting them.
    fn absorb<R: BufRead>(reader: &mut R, crc: &mut Crc32c, mut len: u64) -> io::Result<()> {
        while len > 0 {
            let chunk = reader.fill_buf()?;
            if chunk.is_empty() {
                // The length checks above rule this out unless the file shrinks under us.
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "segment shrank during scan",
                ));
            }
            let take = chunk.len().min(usize::try_from(len).unwrap_or(usize::MAX));
            crc.update(&chunk[..take]);
            reader.consume(take);
            len -= take as u64;
        }
        Ok(())
    }
}
