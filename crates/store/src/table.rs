//! Handles to named tables, the store's column families.

/// A handle to one named table of a store.
///
/// Each table is an independent ordered map from byte keys to byte values.
/// Keys of different tables never collide, so callers need no key prefixes.
///
/// A handle is a one-byte identifier, obtained by name from the store that owns the table.
/// The identifier is persisted, so a name maps to the same handle across reopens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Table(u8);

impl Table {
    /// The internal table that maps table names to identifiers.
    ///
    /// Identifier zero is reserved for it, so user tables number 1 to 255.
    pub(crate) const CATALOG: Self = Self(0);

    /// Wraps a raw identifier read from disk or allocated by the catalog.
    pub(crate) const fn from_id(id: u8) -> Self {
        Self(id)
    }

    /// Returns the raw identifier written into every record of this table.
    pub(crate) const fn id(self) -> u8 {
        self.0
    }
}
