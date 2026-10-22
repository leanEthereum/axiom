//! The chain's on-disk layout: every table and key format in one place.

use std::{marker::PhantomData, path::Path, sync::Arc};

use axiom_ssz::Ssz;
use axiom_store::{Batch, Options, Store, Table};
use axiom_types::{
    BeaconState, Checkpoint, ColumnIndex, DataColumnSidecar, Preset, Root, SignedBeaconBlock, Slot,
};

use crate::ChainError;

/// Key of the finalized checkpoint in the metadata table.
const FINALIZED_KEY: &[u8] = b"finalized";

/// The chain's persistent records, typed over the store's raw tables.
///
/// # Layout
///
/// ```text
///     table       key                    value
///     blocks      block root (32 bytes)  SSZ signed block
///     states      block root (32 bytes)  SSZ post-state, kept for finalized blocks only
///     columns     root (32) + index (8)  SSZ data column sidecar of a custody column
///     canonical   slot (8 bytes, BE)     root of the finalized chain's block at that slot
///     meta        "finalized"            SSZ checkpoint the node resumes from
/// ```
///
/// Big-endian slots sort in slot order, so a range scan walks the chain forward.
#[derive(Debug)]
pub struct ChainDatabase<P: Preset> {
    /// The key-value store.
    store: Store,
    /// Signed blocks by root.
    blocks: Table,
    /// Post-states by block root.
    states: Table,
    /// Custody columns by block root and index.
    columns: Table,
    /// Finalized block roots by slot.
    canonical: Table,
    /// Single named records.
    meta: Table,
    /// The preset the encoded records follow.
    preset: PhantomData<P>,
}

impl<P: Preset> ChainDatabase<P> {
    /// Opens or creates a database in a directory.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be opened, or another process holds it.
    pub fn open(directory: &Path) -> Result<Self, ChainError> {
        Self::with_store(Store::open(directory, Options::default())?)
    }

    /// A database that lives in memory and vanishes with the node.
    ///
    /// # Errors
    ///
    /// Fails only if the tables cannot be named, which cannot happen for these names.
    pub fn in_memory() -> Result<Self, ChainError> {
        Self::with_store(Store::in_memory())
    }

    /// Names the tables in an open store.
    fn with_store(store: Store) -> Result<Self, ChainError> {
        Ok(Self {
            blocks: store.table("blocks")?,
            states: store.table("states")?,
            columns: store.table("columns")?,
            canonical: store.table("canonical")?,
            meta: store.table("meta")?,
            store,
            preset: PhantomData,
        })
    }

    /// Stores a block under its root.
    ///
    /// # Errors
    ///
    /// Fails when the write fails.
    pub fn put_block(&self, root: Root, block: &SignedBeaconBlock<P>) -> Result<(), ChainError> {
        Ok(self.store.put(self.blocks, &root.0, &block.encode())?)
    }

    /// The block with a root, if stored.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the stored bytes do not decode.
    pub fn block(&self, root: Root) -> Result<Option<SignedBeaconBlock<P>>, ChainError> {
        self.read(self.blocks, &root.0, "block")
    }

    /// Stores the custody columns of an imported block in one atomic write.
    ///
    /// # Errors
    ///
    /// Fails when the write fails.
    pub fn put_columns(
        &self,
        root: Root,
        columns: &[Arc<DataColumnSidecar<P>>],
    ) -> Result<(), ChainError> {
        let mut batch = Batch::new();
        for column in columns {
            batch.put(
                self.columns,
                &Self::column_key(root, column.index),
                &column.encode(),
            )?;
        }
        Ok(self.store.write(&batch)?)
    }

    /// A stored column of a block, if this node custodies it.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the stored bytes do not decode.
    pub fn column(
        &self,
        root: Root,
        index: ColumnIndex,
    ) -> Result<Option<DataColumnSidecar<P>>, ChainError> {
        self.read(self.columns, &Self::column_key(root, index), "column")
    }

    /// The finalized checkpoint and its post-state, if the node ever finalized one.
    ///
    /// # Errors
    ///
    /// Fails when a read fails, a record does not decode, or the state is missing.
    pub fn finalized(&self) -> Result<Option<(Checkpoint, BeaconState<P>)>, ChainError> {
        let Some(checkpoint) = self.read::<Checkpoint>(self.meta, FINALIZED_KEY, "checkpoint")?
        else {
            return Ok(None);
        };
        // The state is written in the same batch as the checkpoint, so it must be there.
        let state = self
            .read(self.states, &checkpoint.root.0, "state")?
            .ok_or(ChainError::Missing("finalized state"))?;
        Ok(Some((checkpoint, state)))
    }

    /// The earliest slot whose canonical block the database holds.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the index holds a malformed key.
    pub fn earliest_slot(&self) -> Result<Option<Slot>, ChainError> {
        // Big-endian slot keys sort by slot, so the first key is the earliest.
        let Some(key) = self.store.snapshot().entries(self.canonical)?.keys().next() else {
            return Ok(None);
        };
        let bytes: [u8; 8] = key
            .try_into()
            .map_err(|_| ChainError::Missing("well-formed canonical index key"))?;
        Ok(Some(Slot(u64::from_be_bytes(bytes))))
    }

    /// Whether the database holds an anchor to resume from.
    ///
    /// # Errors
    ///
    /// Fails when the read fails.
    pub fn has_anchor(&self) -> Result<bool, ChainError> {
        Ok(self.store.contains_key(self.meta, FINALIZED_KEY)?)
    }

    /// The finalized chain's block root at a slot, if a block was proposed there.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the stored root is malformed.
    pub fn canonical_root(&self, slot: Slot) -> Result<Option<Root>, ChainError> {
        self.read(self.canonical, &slot.0.to_be_bytes(), "canonical root")
    }

    /// Records a new finality in one atomic write.
    ///
    /// # Arguments
    ///
    /// - `checkpoint`: the new finalized checkpoint.
    /// - `state`: the finalized block's post-state, the anchor to resume from.
    /// - `chain`: the newly finalized blocks as slot and root pairs.
    /// - `orphans`: roots of blocks that finality excluded, to forget.
    ///
    /// # Errors
    ///
    /// Fails when the write fails.
    pub fn finalize(
        &self,
        checkpoint: Checkpoint,
        state: &BeaconState<P>,
        chain: &[(Slot, Root)],
        orphans: &[Root],
    ) -> Result<(), ChainError> {
        let mut batch = Batch::new();

        // The previous anchor state is superseded, but older states stay as history.
        batch.put(self.states, &checkpoint.root.0, &state.encode())?;
        batch.put(self.meta, FINALIZED_KEY, &checkpoint.encode())?;

        // Index the finalized chain by slot, so a slot query never needs the fork choice.
        for (slot, root) in chain {
            batch.put(self.canonical, &slot.0.to_be_bytes(), &root.0)?;
        }

        // Blocks off the finalized chain can never become canonical again, nor their columns.
        let snapshot = self.store.snapshot();
        for root in orphans {
            batch.delete(self.blocks, &root.0)?;
            // Column keys start with the block root, so a prefix scan finds exactly the stored ones.
            for key in snapshot.prefix(self.columns, &root.0)?.keys() {
                batch.delete(self.columns, &key)?;
            }
        }
        Ok(self.store.write(&batch)?)
    }

    /// Bytes written to the store since it opened.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.store.metrics().bytes_written()
    }

    /// Key of a column: the block root, then the index in big-endian.
    fn column_key(root: Root, index: ColumnIndex) -> [u8; 40] {
        let mut key = [0; 40];
        key[..32].copy_from_slice(&root.0);
        key[32..].copy_from_slice(&index.0.to_be_bytes());
        key
    }

    /// Reads and decodes one record.
    fn read<T: Ssz>(
        &self,
        table: Table,
        key: &[u8],
        what: &'static str,
    ) -> Result<Option<T>, ChainError> {
        self.store
            .get(table, key)?
            .map(|bytes| T::decode(&bytes).map_err(|error| ChainError::Corrupt { what, error }))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Epoch, Minimal};

    use super::*;

    type Database = ChainDatabase<Minimal>;

    fn block_at(slot: u64) -> SignedBeaconBlock<Minimal> {
        let mut block = SignedBeaconBlock::<Minimal>::default();
        block.message.slot = Slot(slot);
        block
    }

    #[test]
    fn blocks_round_trip_by_root() {
        let database = Database::in_memory().unwrap();
        let block = block_at(7);
        let root = block.message.hash_tree_root();

        database.put_block(root, &block).unwrap();

        assert_eq!(database.block(root).unwrap(), Some(block));
        assert_eq!(database.block(Root::ZERO).unwrap(), None);
    }

    #[test]
    fn finality_records_anchor_index_and_forgets_orphans() {
        // Fixture state: finalized blocks at slots 1 and 3, and an orphan at slot 2.
        //
        //     1 -> 3      finalized chain
        //      \
        //       2         orphan, excluded by finality
        let database = Database::in_memory().unwrap();
        let (one, two, three) = (block_at(1), block_at(2), block_at(3));
        let roots = [
            one.message.hash_tree_root(),
            two.message.hash_tree_root(),
            three.message.hash_tree_root(),
        ];
        for (block, root) in [&one, &two, &three].into_iter().zip(roots) {
            database.put_block(root, block).unwrap();
        }
        let column = DataColumnSidecar::<Minimal> {
            index: ColumnIndex(3),
            ..DataColumnSidecar::default()
        };
        database.put_columns(roots[1], &[Arc::new(column)]).unwrap();
        let checkpoint = Checkpoint {
            epoch: Epoch(1),
            root: roots[2],
        };
        let state = BeaconState::<Minimal>::default();

        database
            .finalize(
                checkpoint,
                &state,
                &[(Slot(1), roots[0]), (Slot(3), roots[2])],
                &[roots[1]],
            )
            .unwrap();

        // The anchor reads back whole.
        assert_eq!(database.finalized().unwrap(), Some((checkpoint, state)));
        // Slot 1 is the earliest the index holds, and slot 2 was skipped.
        assert_eq!(database.earliest_slot().unwrap(), Some(Slot(1)));
        assert_eq!(database.canonical_root(Slot(1)).unwrap(), Some(roots[0]));
        assert_eq!(database.canonical_root(Slot(2)).unwrap(), None);
        // The orphan and its column are gone, the finalized blocks stay.
        assert_eq!(database.block(roots[1]).unwrap(), None);
        assert_eq!(database.column(roots[1], ColumnIndex(3)).unwrap(), None);
        assert_eq!(database.block(roots[2]).unwrap(), Some(three));
    }

    #[test]
    fn columns_round_trip_by_root_and_index() {
        let database = Database::in_memory().unwrap();
        let root = Root([5; 32]);
        let column = DataColumnSidecar::<Minimal> {
            index: ColumnIndex(77),
            ..DataColumnSidecar::default()
        };

        database
            .put_columns(root, &[Arc::new(column.clone())])
            .unwrap();

        assert_eq!(
            database.column(root, ColumnIndex(77)).unwrap(),
            Some(column)
        );
        assert_eq!(database.column(root, ColumnIndex(76)).unwrap(), None);
    }

    #[test]
    fn a_fresh_database_has_no_finality() {
        let database = Database::in_memory().unwrap();

        assert!(!database.has_anchor().unwrap());
        assert_eq!(database.finalized().unwrap(), None);
    }
}
