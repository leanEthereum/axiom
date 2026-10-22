//! How much one table of the chain database holds.

/// Entries and bytes one table holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableUsage {
    /// The table's name.
    pub name: &'static str,
    /// Entries in the table.
    pub entries: u64,
    /// Bytes of every key together.
    pub key_bytes: u64,
    /// Bytes of every value together.
    pub value_bytes: u64,
}

impl TableUsage {
    /// A table holding nothing yet.
    pub(super) const fn empty(name: &'static str) -> Self {
        Self {
            name,
            entries: 0,
            key_bytes: 0,
            value_bytes: 0,
        }
    }

    /// Counts one entry.
    pub(super) const fn add(&mut self, key_len: usize, value_len: usize) {
        self.entries += 1;
        self.key_bytes += key_len as u64;
        self.value_bytes += value_len as u64;
    }
}
