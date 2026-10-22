//! How each fork makes its blob data available.

/// The form a fork's blob data travels in, and what it gates.
///
/// Availability gates import: a node waits for the data before trusting what commits to it.
/// See `is_data_available` in the Deneb, Fulu, and Gloas fork choice specs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlobData {
    /// No blobs exist.
    None,
    /// Whole blobs, one sidecar per blob, all needed before the block imports.
    ///
    /// See EIP-4844.
    BlobSidecars,
    /// Columns of the extended blob matrix, sampled before the block imports.
    ///
    /// See EIP-7594.
    BlockColumns,
    /// Columns that name their block, sampled before the payload envelope imports.
    ///
    /// The block commits to the blobs through its bid, and the payload follows apart.
    /// See EIP-7732.
    PayloadColumns,
}

impl BlobData {
    /// Whether the data travels as columns.
    #[must_use]
    pub const fn is_columns(self) -> bool {
        matches!(self, Self::BlockColumns | Self::PayloadColumns)
    }
}
