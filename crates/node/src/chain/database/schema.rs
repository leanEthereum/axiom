//! Layout versions of the chain database, and the migrations between them.

use std::fmt;

use axiom_store::Batch;
use axiom_types::Preset;

use super::{ChainDatabase, HistoryStart};
use crate::ChainError;

/// Version of the chain database's table layout.
///
/// A database records the version it was last written in.
/// Opening it migrates it forward one step at a time, each step atomic with its version bump.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaVersion(pub u64);

impl SchemaVersion {
    /// The first layout, which recorded no version.
    ///
    /// It held blocks, the finalized anchor state, sidecars, envelopes, and the canonical index.
    pub const FIRST: Self = Self(1);

    /// The layout this build writes.
    ///
    /// Version 2 added state snapshots, the state root index, light client data, and the history start.
    /// Version 3 adds blinded blocks, whose payloads were pruned.
    pub const CURRENT: Self = Self(3);

    /// The record as stored: eight big-endian bytes.
    pub(super) const fn encode(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Reads a stored record, or nothing when it is not eight bytes.
    pub(super) fn decode(bytes: &[u8]) -> Option<Self> {
        Some(Self(u64::from_be_bytes(bytes.try_into().ok()?)))
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// One step from a layout version to the next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Migration {
    /// Version 1 to 2: record where the stored chain begins, for backfill to resume from.
    ///
    /// Version 1 kept no such record.
    /// Its canonical index began at the anchor, so the earliest indexed block is the start.
    HistoryStart,
    /// Version 2 to 3: blocks may sit blinded in their own table.
    ///
    /// Version 2 kept every payload, so the new table starts empty and nothing moves.
    BlindedBlocks,
}

impl Migration {
    /// The step that upgrades a version, if this build knows one.
    pub(super) const fn from(version: SchemaVersion) -> Option<Self> {
        match version.0 {
            1 => Some(Self::HistoryStart),
            2 => Some(Self::BlindedBlocks),
            _ => None,
        }
    }

    /// The version the step produces.
    pub(super) const fn target(self) -> SchemaVersion {
        match self {
            Self::HistoryStart => SchemaVersion(2),
            Self::BlindedBlocks => SchemaVersion(3),
        }
    }

    /// Adds the step's writes to a batch, which also records the target version.
    pub(super) fn stage<P: Preset>(
        self,
        database: &ChainDatabase<P>,
        batch: &mut Batch,
    ) -> Result<(), ChainError> {
        match self {
            Self::HistoryStart => {
                let Some(slot) = database.earliest_slot()? else {
                    return Ok(());
                };
                let root = database
                    .canonical_root(slot)?
                    .ok_or(ChainError::Missing("earliest canonical root"))?;
                let block = database
                    .block(root)?
                    .ok_or(ChainError::Missing("earliest canonical block"))?;
                database.stage_history_start(
                    batch,
                    HistoryStart {
                        slot,
                        parent_root: block.parent_root(),
                    },
                )
            }
            Self::BlindedBlocks => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_version_below_the_current_one_has_a_step_to_the_next() {
        // Walking the steps from the first version must land exactly on the current one.
        let mut version = SchemaVersion::FIRST;
        let mut steps = 0;
        while let Some(step) = Migration::from(version) {
            assert_eq!(step.target(), SchemaVersion(version.0 + 1));
            version = step.target();
            steps += 1;
        }
        assert_eq!(version, SchemaVersion::CURRENT);
        assert_eq!(steps, 2);
    }

    #[test]
    fn a_version_record_is_eight_big_endian_bytes() {
        assert_eq!(SchemaVersion(2).encode(), [0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(
            SchemaVersion::decode(&[0, 0, 0, 0, 0, 0, 1, 0]),
            Some(SchemaVersion(256))
        );
        assert_eq!(SchemaVersion::decode(&[2]), None);
    }
}
