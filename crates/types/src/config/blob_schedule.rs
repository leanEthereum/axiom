//! The blob schedule of Blob Parameter Only forks.

use crate::Epoch;

/// The blob limit in force from an epoch on.
///
/// See `BlobParameters` in the Fulu beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobParameters {
    /// Epoch the limit takes effect.
    pub epoch: Epoch,
    /// Blobs a block may carry.
    pub max_blobs_per_block: u64,
}

/// Blob limits that change at fixed epochs, without a full fork.
///
/// See EIP-7892.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobSchedule {
    /// Entries sorted by epoch, latest last.
    entries: Vec<BlobParameters>,
}

impl BlobSchedule {
    /// A schedule from entries in any order.
    #[must_use]
    pub fn new(mut entries: Vec<BlobParameters>) -> Self {
        entries.sort_by_key(|entry| entry.epoch);
        Self { entries }
    }

    /// The latest entry in force at an epoch, if any.
    #[must_use]
    pub fn at(&self, epoch: Epoch) -> Option<BlobParameters> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.epoch <= epoch)
            .copied()
    }

    /// The entries, sorted by epoch.
    #[must_use]
    pub fn entries(&self) -> &[BlobParameters] {
        &self.entries
    }
}
