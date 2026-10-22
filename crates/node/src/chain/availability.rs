//! Blocks and payload envelopes waiting for their blob data, and the sidecars that release them.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};

use axiom_fork_choice::PayloadStatus;
use axiom_ssz::Ssz;
use axiom_types::{
    ColumnIndex, Preset, Root, Slot, combined, deneb::BlobSidecar,
    gloas::SignedExecutionPayloadEnvelope,
};

/// What became of a block or envelope handed to the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submission {
    /// It was imported.
    Imported(Root),
    /// It waits for blob data.
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
    pub block: Arc<combined::SignedBeaconBlock<P>>,
    /// The engine's verdict.
    pub payload: PayloadStatus,
}

/// A payload envelope ready for import, with the engine's verdict on its payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadyEnvelope<P: Preset> {
    /// The envelope.
    pub envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
    /// The engine's verdict.
    pub payload: PayloadStatus,
}

/// What can wait for blob data.
///
/// Before Gloas a block waits; from Gloas on the payload envelope does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Pending<P: Preset> {
    /// A block whose body commits to blobs.
    Block(ReadyBlock<P>),
    /// An envelope whose block's bid commits to blobs.
    Envelope(ReadyEnvelope<P>),
}

impl<P: Preset> Pending<P> {
    /// Slot of the block the item belongs to.
    fn slot(&self) -> Slot {
        match self {
            Self::Block(ready) => ready.block.slot(),
            Self::Envelope(ready) => Slot(ready.envelope.message.payload.slot_number),
        }
    }
}

/// One verified piece of blob data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Sidecar<P: Preset> {
    /// A whole blob, Deneb and Electra.
    Blob(Arc<BlobSidecar<P>>),
    /// A column of the extended matrix, from Fulu on.
    Column(Arc<combined::DataColumnSidecar<P>>),
}

impl<P: Preset> Sidecar<P> {
    /// Root of the block the sidecar belongs to.
    pub(crate) fn block_root(&self) -> Root {
        match self {
            Self::Blob(blob) => blob.signed_block_header.message.hash_tree_root(),
            Self::Column(column) => column.block_root(),
        }
    }

    /// The blob index or column index.
    fn index(&self) -> u64 {
        match self {
            Self::Blob(blob) => blob.index.0,
            Self::Column(column) => column.index().0,
        }
    }

    /// Slot of the block the sidecar belongs to.
    fn slot(&self) -> Slot {
        match self {
            Self::Blob(blob) => blob.signed_block_header.message.slot,
            Self::Column(column) => column.slot(),
        }
    }
}

/// The sidecars an item needs before its data counts as available.
///
/// See `is_data_available` in the Deneb, Fulu, and Gloas fork choice specs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Needed {
    /// No blob is committed to, or the data is past the retention window.
    Nothing,
    /// Every blob sidecar from index zero up to the count.
    Blobs(u64),
    /// Every column this node samples.
    Custody,
}

/// Holds blocks and envelopes until their blob data has arrived.
///
/// # Overview
///
/// Items and sidecars arrive in any order, so whichever comes last releases the item.
/// Take custody columns {3, 40}, with column 3 already verified:
///
/// 1. Block B arrives, needs custody, and waits with {3}.
/// 2. Column 40 arrives, the set is complete, and B is released for import.
///
/// Before Fulu, a block needs each of its blobs instead of the custody columns.
/// Only verified sidecars may be offered: the buffer trusts what it receives.
#[derive(Debug)]
pub(crate) struct AvailabilityBuffer<P: Preset> {
    /// Columns this node samples for every block.
    custody: BTreeSet<ColumnIndex>,
    /// Items waiting for sidecars, by block root.
    pending: HashMap<Root, (Pending<P>, Needed)>,
    /// Verified sidecars, by block root and index.
    sidecars: HashMap<Root, BTreeMap<u64, Sidecar<P>>>,
}

impl<P: Preset> AvailabilityBuffer<P> {
    /// An empty buffer for a custody set.
    pub(crate) fn new(custody: impl IntoIterator<Item = ColumnIndex>) -> Self {
        Self {
            custody: custody.into_iter().collect(),
            pending: HashMap::new(),
            sidecars: HashMap::new(),
        }
    }

    /// The columns this node samples.
    #[must_use]
    pub(crate) const fn custody(&self) -> &BTreeSet<ColumnIndex> {
        &self.custody
    }

    /// Offers an item, which comes back at once if its data is already complete.
    pub(crate) fn offer(
        &mut self,
        root: Root,
        item: Pending<P>,
        needed: Needed,
    ) -> Option<Pending<P>> {
        if self.is_complete(&root, needed) {
            return Some(item);
        }
        self.pending.insert(root, (item, needed));
        None
    }

    /// Offers a verified sidecar, which may release the item it belongs to.
    ///
    /// Columns outside the custody set are not kept: the node neither samples nor serves them.
    pub(crate) fn offer_sidecar(&mut self, sidecar: Sidecar<P>) -> Option<Pending<P>> {
        if let Sidecar::Column(column) = &sidecar
            && !self.custody.contains(&column.index())
        {
            return None;
        }
        let root = sidecar.block_root();
        self.sidecars
            .entry(root)
            .or_default()
            .insert(sidecar.index(), sidecar);
        let needed = self.pending.get(&root).map(|(_, needed)| *needed)?;
        if self.is_complete(&root, needed) {
            return self.pending.remove(&root).map(|(item, _)| item);
        }
        None
    }

    /// Removes and returns the sidecars held for a block, once its data is imported.
    pub(crate) fn take_sidecars(&mut self, root: &Root) -> Vec<Sidecar<P>> {
        self.sidecars
            .remove(root)
            .map(|sidecars| sidecars.into_values().collect())
            .unwrap_or_default()
    }

    /// Forgets items and sidecars at or before a slot, which finality made irrelevant.
    pub(crate) fn prune(&mut self, finalized: Slot) {
        self.pending.retain(|_, (item, _)| item.slot() > finalized);
        self.sidecars.retain(|_, sidecars| {
            sidecars
                .values()
                .next()
                .is_some_and(|sidecar| sidecar.slot() > finalized)
        });
    }

    /// Whether every sidecar an item needs is held.
    fn is_complete(&self, root: &Root, needed: Needed) -> bool {
        let held = self.sidecars.get(root);
        match needed {
            Needed::Nothing => true,
            Needed::Blobs(count) => {
                held.is_some_and(|held| (0..count).all(|index| held.contains_key(&index)))
            }
            Needed::Custody => held.is_some_and(|held| {
                self.custody
                    .iter()
                    .all(|column| held.contains_key(&column.0))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{BlobIndex, Minimal, fulu};

    use super::*;

    type Buffer = AvailabilityBuffer<Minimal>;

    /// A Fulu block at a slot.
    fn block(slot: u64) -> Pending<Minimal> {
        let mut block = fulu::SignedBeaconBlock::<Minimal>::default();
        block.message.slot = Slot(slot);
        Pending::Block(ReadyBlock {
            block: Arc::new(combined::SignedBeaconBlock::Fulu(block)),
            payload: PayloadStatus::Valid,
        })
    }

    /// A Fulu column of the block at a slot.
    fn column(index: u64, slot: u64) -> Sidecar<Minimal> {
        let mut column = fulu::DataColumnSidecar::<Minimal> {
            index: ColumnIndex(index),
            ..Default::default()
        };
        column.signed_block_header.message.slot = Slot(slot);
        Sidecar::Column(Arc::new(combined::DataColumnSidecar::Fulu(column)))
    }

    /// A blob sidecar at an index of the block at a slot.
    fn blob(index: u64, slot: u64) -> Sidecar<Minimal> {
        let mut blob = BlobSidecar::<Minimal> {
            index: BlobIndex(index),
            ..Default::default()
        };
        blob.signed_block_header.message.slot = Slot(slot);
        Sidecar::Blob(Arc::new(blob))
    }

    #[test]
    fn an_item_needing_nothing_passes_straight_through() {
        let mut buffer = Buffer::new([ColumnIndex(3)]);

        assert_eq!(
            buffer.offer(Root::ZERO, block(1), Needed::Nothing),
            Some(block(1))
        );
        assert!(buffer.pending.is_empty());
    }

    #[test]
    fn the_last_custody_column_releases_a_waiting_block() {
        // Fixture state: custody {3, 40}; the block arrives first, then the columns.
        let mut buffer = Buffer::new([ColumnIndex(3), ColumnIndex(40)]);
        let root = column(3, 1).block_root();

        assert_eq!(buffer.offer(root, block(1), Needed::Custody), None);
        // A column outside custody is not kept and releases nothing.
        assert_eq!(buffer.offer_sidecar(column(7, 1)), None);
        assert_eq!(buffer.offer_sidecar(column(3, 1)), None);
        let released = buffer.offer_sidecar(column(40, 1));

        assert_eq!(released, Some(block(1)));
        let indices: Vec<u64> = buffer
            .take_sidecars(&root)
            .iter()
            .map(Sidecar::index)
            .collect();
        assert_eq!(indices, [3, 40]);
    }

    #[test]
    fn every_blob_up_to_the_count_releases_a_block() {
        // Fixture state: a Deneb-style block committing to two blobs, which arrive first.
        let mut buffer = Buffer::new([]);
        let root = blob(0, 5).block_root();
        assert_eq!(buffer.offer_sidecar(blob(1, 5)), None);

        // Blob 0 is still missing, so the block waits.
        assert_eq!(buffer.offer(root, block(5), Needed::Blobs(2)), None);
        assert_eq!(buffer.offer_sidecar(blob(0, 5)), Some(block(5)));
    }

    #[test]
    fn finality_prunes_what_waits_at_or_before_it() {
        // Fixture state: blocks waiting at slots 7, 8, and 9, finality at slot 8.
        //
        //     slot 7  before finality     dropped
        //     slot 8  the finalized slot  dropped
        //     slot 9  after finality      kept
        let mut buffer = Buffer::new([ColumnIndex(3)]);
        for slot in [7_u8, 8, 9] {
            buffer.offer(Root([slot; 32]), block(u64::from(slot)), Needed::Custody);
            buffer.offer_sidecar(blob(0, u64::from(slot)));
        }

        buffer.prune(Slot(8));

        let waiting: Vec<Root> = buffer.pending.keys().copied().collect();
        assert_eq!(waiting, [Root([9; 32])]);
        let slots: Vec<Slot> = buffer
            .sidecars
            .values()
            .flat_map(|held| held.values().map(Sidecar::slot))
            .collect();
        assert_eq!(slots, [Slot(9)]);
    }
}
