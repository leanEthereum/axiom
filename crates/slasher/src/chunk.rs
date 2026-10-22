//! Fixed-width cells stored together as one compressed database value.

use axiom_snappy::raw;

use crate::SlasherError;

/// A fixed-width unsigned cell, stored little-endian.
pub(crate) trait Cell: Copy + Eq {
    /// Bytes per cell.
    const WIDTH: usize;

    /// The cell from its little-endian bytes, exactly the cell's width.
    fn read(bytes: &[u8]) -> Self;

    /// Appends the cell's little-endian bytes.
    fn write(self, out: &mut Vec<u8>);
}

impl Cell for u16 {
    const WIDTH: usize = 2;

    fn read(bytes: &[u8]) -> Self {
        Self::from_le_bytes([bytes[0], bytes[1]])
    }

    fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }
}

impl Cell for u32 {
    const WIDTH: usize = 4;

    fn read(bytes: &[u8]) -> Self {
        Self::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_le_bytes());
    }
}

/// A block of cells that loads, changes, and stores as one value.
///
/// Snappy compresses it: most cells hold the empty value, or repeat their neighbours.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Chunk<T> {
    /// The cells.
    cells: Vec<T>,
    /// Whether a cell changed since the chunk was loaded.
    dirty: bool,
}

impl<T: Cell> Chunk<T> {
    /// A chunk of cells that all hold one value, not yet stored.
    pub(crate) fn filled(len: usize, value: T) -> Self {
        Self {
            cells: vec![value; len],
            dirty: true,
        }
    }

    /// A stored chunk, which must hold exactly a number of cells.
    ///
    /// # Errors
    ///
    /// Fails when the bytes do not decompress, or hold another number of cells.
    pub(crate) fn decode(
        bytes: &[u8],
        len: usize,
        table: &'static str,
    ) -> Result<Self, SlasherError> {
        let expected = len * T::WIDTH;
        let raw = raw::decompress(bytes, expected)
            .map_err(|source| SlasherError::Compression { table, source })?;
        if raw.len() != expected {
            return Err(SlasherError::Corrupt {
                table,
                len: raw.len(),
                reason: "wrong number of cells",
            });
        }
        Ok(Self {
            cells: raw.chunks_exact(T::WIDTH).map(T::read).collect(),
            dirty: false,
        })
    }

    /// The compressed bytes of the chunk.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(self.cells.len() * T::WIDTH);
        for cell in &self.cells {
            cell.write(&mut raw);
        }
        raw::compress(&raw)
    }

    /// The value of a cell.
    pub(crate) fn get(&self, cell: usize) -> T {
        self.cells[cell]
    }

    /// Changes a cell, marking the chunk for storing if the value differs.
    pub(crate) fn set(&mut self, cell: usize, value: T) {
        if self.cells[cell] != value {
            self.cells[cell] = value;
            self.dirty = true;
        }
    }

    /// Whether a cell changed since the chunk was loaded.
    pub(crate) const fn is_dirty(&self) -> bool {
        self.dirty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chunk_round_trips_through_its_compressed_form() {
        // 64 two-byte cells, two of them set.
        let mut chunk = Chunk::filled(64, u16::MAX);
        chunk.set(3, 7);
        chunk.set(63, 0);
        let decoded = Chunk::<u16>::decode(&chunk.encode(), 64, "spans").expect("decodes");
        assert_eq!(decoded.cells, chunk.cells);
        assert!(!decoded.is_dirty());
    }

    #[test]
    fn a_chunk_of_another_size_is_corrupt() {
        // 64 cells stored, 32 expected: the decompressor's bound refuses it first.
        let chunk = Chunk::filled(64, 0_u32);
        assert!(matches!(
            Chunk::<u32>::decode(&chunk.encode(), 32, "records"),
            Err(SlasherError::Compression {
                table: "records",
                ..
            })
        ));
        // 16 cells stored, 32 expected: the cell count is wrong.
        let short = Chunk::filled(16, 0_u32);
        assert!(matches!(
            Chunk::<u32>::decode(&short.encode(), 32, "records"),
            Err(SlasherError::Corrupt {
                table: "records",
                len: 64,
                reason: "wrong number of cells"
            })
        ));
    }

    #[test]
    fn setting_an_unchanged_value_leaves_the_chunk_clean() {
        let encoded = Chunk::filled(8, 5_u16).encode();
        let mut chunk = Chunk::<u16>::decode(&encoded, 8, "spans").expect("decodes");
        chunk.set(2, 5);
        assert!(!chunk.is_dirty());
        chunk.set(2, 6);
        assert!(chunk.is_dirty());
    }
}
