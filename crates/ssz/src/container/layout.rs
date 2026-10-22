//! The declared shape of a container: one fixed size or none per field.

use crate::{BYTES_PER_LENGTH_OFFSET, Ssz};

/// The fixed size of each field in order, empty for a variable-size field.
///
/// A fixed field occupies its size in the fixed part, and a variable field one offset.
#[derive(Clone, Copy, Debug)]
pub(super) struct Layout(&'static [Option<usize>]);

impl Layout {
    /// The layout a container declares.
    pub(super) const fn new(fields: &'static [Option<usize>]) -> Self {
        Self(fields)
    }

    /// Number of fields.
    pub(super) const fn len(self) -> usize {
        self.0.len()
    }

    /// Bytes a field takes in the fixed part.
    const fn slot(size: Option<usize>) -> usize {
        match size {
            Some(size) => size,
            None => BYTES_PER_LENGTH_OFFSET,
        }
    }

    /// Total size of the fixed part: fixed fields in full, variable fields as offsets.
    pub(super) const fn fixed_part_len(self) -> usize {
        self.position_of(self.0.len())
    }

    /// Fixed size of the container, when every field is fixed-size.
    pub(super) const fn fixed_size(self) -> Option<usize> {
        match self.next_variable(0) {
            Some(_) => None,
            None => Some(self.fixed_part_len()),
        }
    }

    /// Position of a field within the fixed part.
    pub(super) const fn position_of(self, field: usize) -> usize {
        let mut total = 0;
        let mut index = 0;
        while index < field {
            total += Self::slot(self.0[index]);
            index += 1;
        }
        total
    }

    /// First variable-size field at or after the given index.
    pub(super) const fn next_variable(self, from: usize) -> Option<usize> {
        let mut index = from;
        while index < self.0.len() {
            if self.0[index].is_none() {
                return Some(index);
            }
            index += 1;
        }
        None
    }

    /// Checks a visited or decoded field against its declared size, in debug builds.
    pub(super) fn check<T: Ssz>(self, index: usize) {
        debug_assert!(
            index < self.0.len(),
            "container visits more fields than it declares"
        );
        debug_assert_eq!(
            self.0[index],
            T::FIXED_SIZE,
            "field {index} does not match its declared size"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_part_counts_variable_fields_as_offsets() {
        // A u64, a variable field, and a 32-byte root: 8 + 4 + 32 = 44 bytes.
        let layout = Layout::new(&[Some(8), None, Some(32)]);
        assert_eq!(layout.fixed_part_len(), 44);
        assert_eq!(layout.fixed_size(), None);

        // The root starts after the u64 and the offset, at byte 12.
        assert_eq!(layout.position_of(2), 12);
        assert_eq!(layout.next_variable(0), Some(1));
        assert_eq!(layout.next_variable(2), None);

        // Two fixed fields alone make a fixed-size container of 40 bytes.
        assert_eq!(Layout::new(&[Some(8), Some(32)]).fixed_size(), Some(40));
    }
}
