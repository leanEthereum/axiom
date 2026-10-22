//! The chain's on-disk layout: every table and key format in one place.

use std::{marker::PhantomData, path::Path};

use axiom_ssz::Ssz;
use axiom_store::{Batch, Options, Store, Table};
use axiom_types::{BeaconState, Checkpoint, Preset, Root, SignedBeaconBlock, Slot};

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

        // Blocks off the finalized chain can never become canonical again.
        for root in orphans {
            batch.delete(self.blocks, &root.0)?;
        }
        Ok(self.store.write(&batch)?)
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
        // Slot 2 was skipped on the finalized chain.
        assert_eq!(database.canonical_root(Slot(1)).unwrap(), Some(roots[0]));
        assert_eq!(database.canonical_root(Slot(2)).unwrap(), None);
        // The orphan is gone, the finalized blocks stay.
        assert_eq!(database.block(roots[1]).unwrap(), None);
        assert_eq!(database.block(roots[2]).unwrap(), Some(three));
    }

    #[test]
    fn a_fresh_database_has_no_finality() {
        assert_eq!(Database::in_memory().unwrap().finalized().unwrap(), None);
    }
}
