//! Blocks waiting for their blob data, and the columns that release them.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};

use axiom_fork_choice::PayloadStatus;
use axiom_types::{ColumnIndex, DataColumnSidecar, Preset, Root, SignedBeaconBlock, Slot};

/// What became of a block handed to the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submission {
    /// The block was imported.
    Imported(Root),
    /// The block waits for custody columns.
    Waiting(Root),
}

impl Submission {
    /// The block's root, whatever became of it.
    #[must_use]
    pub const fn root(self) -> Root {
        match self {
            Self::Imported(root) | Self::Waiting(root) => root,
        }
    }
}

/// A block ready for import, with the engine's verdict on its payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadyBlock<P: Preset> {
    /// The block.
    pub block: Arc<SignedBeaconBlock<P>>,
    /// The engine's verdict.
    pub payload: PayloadStatus,
}

/// Holds blocks until the columns this node samples have all arrived.
///
/// # Overview
///
/// A block with blobs is available once every custody column of the node verified.
/// Blocks and columns arrive in any order, so whichever comes last releases the block.
///
/// ```text
///     custody: {3, 40, 77, 101}
///
///     block B   ──> waiting: has {3, 40}
///     column 77 ──> waiting: has {3, 40, 77}
///     column 101──> complete ──> released for import
/// ```
///
/// A block without blobs needs no column and passes straight through.
/// Only verified columns may be offered: the buffer trusts what it receives.
/// See `is_data_available` in the Fulu fork choice spec.
#[derive(Debug)]
pub(crate) struct AvailabilityBuffer<P: Preset> {
    /// Columns this node samples for every block.
    custody: BTreeSet<ColumnIndex>,
    /// Blocks waiting for columns, by root.
    blocks: HashMap<Root, ReadyBlock<P>>,
    /// Verified columns, by block root and column index.
    columns: HashMap<Root, BTreeMap<ColumnIndex, Arc<DataColumnSidecar<P>>>>,
}

impl<P: Preset> AvailabilityBuffer<P> {
    /// An empty buffer for a custody set.
    pub(crate) fn new(custody: impl IntoIterator<Item = ColumnIndex>) -> Self {
        Self {
            custody: custody.into_iter().collect(),
            blocks: HashMap::new(),
            columns: HashMap::new(),
        }
    }

    /// The columns this node samples.
    #[must_use]
    pub(crate) const fn custody(&self) -> &BTreeSet<ColumnIndex> {
        &self.custody
    }

    /// Offers a block, which comes back at once if its data is already complete.
    pub(crate) fn offer_block(
        &mut self,
        root: Root,
        ready: ReadyBlock<P>,
    ) -> Option<ReadyBlock<P>> {
        // No blob means no column to wait for.
        if ready.block.message.body.blob_kzg_commitments.is_empty() || self.is_complete(&root) {
            return Some(ready);
        }
        self.blocks.insert(root, ready);
        None
    }

    /// Offers a verified column, which may release the block it belongs to.
    ///
    /// Columns outside the custody set are not kept: the node neither samples nor serves them.
    pub(crate) fn offer_column(
        &mut self,
        root: Root,
        column: Arc<DataColumnSidecar<P>>,
    ) -> Option<ReadyBlock<P>> {
        if !self.custody.contains(&column.index) {
            return None;
        }
        self.columns
            .entry(root)
            .or_default()
            .insert(column.index, column);
        if self.blocks.contains_key(&root) && self.is_complete(&root) {
            return self.blocks.remove(&root);
        }
        None
    }

    /// Removes and returns the columns held for a block, once it is imported.
    pub(crate) fn take_columns(&mut self, root: &Root) -> Vec<Arc<DataColumnSidecar<P>>> {
        self.columns
            .remove(root)
            .map(|columns| columns.into_values().collect())
            .unwrap_or_default()
    }

    /// Forgets blocks and columns at or before a slot, which finality made irrelevant.
    pub(crate) fn prune(&mut self, finalized: Slot) {
        self.blocks
            .retain(|_, ready| ready.block.message.slot > finalized);
        self.columns.retain(|_, columns| {
            columns
                .values()
                .next()
                .is_some_and(|column| column.signed_block_header.message.slot > finalized)
        });
    }

    /// Whether every custody column of a block is held.
    fn is_complete(&self, root: &Root) -> bool {
        self.columns
            .get(root)
            .is_some_and(|columns| self.custody.iter().all(|index| columns.contains_key(index)))
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{KzgCommitment, Minimal};

    use super::*;

    type Buffer = AvailabilityBuffer<Minimal>;

    /// A block at a slot carrying one blob commitment, or none.
    fn block(slot: u64, blobs: bool) -> ReadyBlock<Minimal> {
        let mut block = SignedBeaconBlock::<Minimal>::default();
        block.message.slot = Slot(slot);
        if blobs {
            block
                .message
                .body
                .blob_kzg_commitments
                .push(KzgCommitment::ZERO)
                .unwrap();
        }
        ReadyBlock {
            block: Arc::new(block),
            payload: PayloadStatus::Valid,
        }
    }

    /// A column of a block at a slot.
    fn column(index: u64, slot: u64) -> Arc<DataColumnSidecar<Minimal>> {
        let mut column = DataColumnSidecar::<Minimal> {
            index: ColumnIndex(index),
            ..DataColumnSidecar::default()
        };
        column.signed_block_header.message.slot = Slot(slot);
        Arc::new(column)
    }

    #[test]
    fn a_block_without_blobs_passes_straight_through() {
        let mut buffer = Buffer::new([ColumnIndex(3)]);

        assert!(buffer.offer_block(Root::ZERO, block(1, false)).is_some());
        assert!(buffer.blocks.is_empty());
    }

    #[test]
    fn the_last_custody_column_releases_a_waiting_block() {
        // Fixture state: custody {3, 40}; the block arrives first, then both columns.
        let mut buffer = Buffer::new([ColumnIndex(3), ColumnIndex(40)]);
        let root = Root([1; 32]);

        assert_eq!(buffer.offer_block(root, block(1, true)), None);
        // A column outside custody is not kept and releases nothing.
        assert_eq!(buffer.offer_column(root, column(7, 1)), None);
        assert_eq!(buffer.offer_column(root, column(3, 1)), None);
        let released = buffer.offer_column(root, column(40, 1));

        assert_eq!(released, Some(block(1, true)));
        let indices: Vec<u64> = buffer
            .take_columns(&root)
            .iter()
            .map(|column| column.index.0)
            .collect();
        assert_eq!(indices, [3, 40]);
    }

    #[test]
    fn columns_first_then_the_block_is_ready_at_once() {
        let mut buffer = Buffer::new([ColumnIndex(3)]);
        let root = Root([2; 32]);

        assert_eq!(buffer.offer_column(root, column(3, 5)), None);

        assert_eq!(
            buffer.offer_block(root, block(5, true)),
            Some(block(5, true))
        );
    }

    #[test]
    fn finality_prunes_what_waits_at_or_before_it() {
        // Fixture state: a block waiting at slot 4, and a lone column at slot 9.
        let mut buffer = Buffer::new([ColumnIndex(3), ColumnIndex(40)]);
        buffer.offer_block(Root([4; 32]), block(4, true));
        buffer.offer_column(Root([9; 32]), column(3, 9));

        buffer.prune(Slot(8));

        assert!(!buffer.blocks.contains_key(&Root([4; 32])));
        assert_eq!(buffer.take_columns(&Root([9; 32])).len(), 1);
    }
}
