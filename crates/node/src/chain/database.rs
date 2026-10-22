//! The chain's on-disk layout: every table and key format in one place.

use std::{marker::PhantomData, path::Path};

use axiom_ssz::{DecodeError, Ssz};
use axiom_store::{Batch, Options, Store, Table};
use axiom_types::{
    BlobIndex, ChainConfig, ColumnIndex, ForkName, Preset, Root, Slot, combined,
    deneb::BlobSidecar, gloas::SignedExecutionPayloadEnvelope, phase0::Checkpoint,
};

use super::availability::Sidecar;
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
///     blobs       root (32) + index (8)  SSZ blob sidecar
///     columns     root (32) + index (8)  SSZ data column sidecar of a custody column
///     envelopes   block root (32 bytes)  SSZ signed payload envelope
///     canonical   slot (8 bytes, BE)     root of the finalized chain's block at that slot
///     meta        "finalized"            SSZ checkpoint the node resumes from
/// ```
///
/// Big-endian slots sort in slot order, so a range scan walks the chain forward.
///
/// # Forks
///
/// No record names its fork: the encodings are the spec's, byte for byte.
/// Blocks and states carry their slot at a fixed place, and the configuration maps it to a fork.
/// Columns change shape at Gloas, so their reader names the fork of the block they belong to.
#[derive(Debug)]
pub struct ChainDatabase<P: Preset> {
    /// The key-value store.
    store: Store,
    /// The fork schedule that decodes each record.
    config: ChainConfig,
    /// Signed blocks by root.
    blocks: Table,
    /// Post-states by block root.
    states: Table,
    /// Blob sidecars by block root and index.
    blobs: Table,
    /// Custody columns by block root and index.
    columns: Table,
    /// Payload envelopes by block root.
    envelopes: Table,
    /// Finalized block roots by slot.
    canonical: Table,
    /// Single named records.
    meta: Table,
    /// The preset the encoded records follow.
    preset: PhantomData<P>,
}

impl<P: Preset> ChainDatabase<P> {
    /// Opens or creates a database in a directory, for a chain's fork schedule.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be opened, or another process holds it.
    pub fn open(directory: &Path, config: ChainConfig) -> Result<Self, ChainError> {
        Self::with_store(Store::open(directory, Options::default())?, config)
    }

    /// A database that lives in memory and vanishes with the node.
    ///
    /// # Errors
    ///
    /// Fails only if the tables cannot be named, which cannot happen for these names.
    pub fn in_memory(config: ChainConfig) -> Result<Self, ChainError> {
        Self::with_store(Store::in_memory(), config)
    }

    /// Names the tables in an open store.
    fn with_store(store: Store, config: ChainConfig) -> Result<Self, ChainError> {
        Ok(Self {
            blocks: store.table("blocks")?,
            states: store.table("states")?,
            blobs: store.table("blobs")?,
            columns: store.table("columns")?,
            envelopes: store.table("envelopes")?,
            canonical: store.table("canonical")?,
            meta: store.table("meta")?,
            store,
            config,
            preset: PhantomData,
        })
    }

    /// Stores a block under its root.
    ///
    /// # Errors
    ///
    /// Fails when the write fails.
    pub fn put_block(
        &self,
        root: Root,
        block: &combined::SignedBeaconBlock<P>,
    ) -> Result<(), ChainError> {
        Ok(self.store.put(self.blocks, &root.0, &block.encode())?)
    }

    /// The block with a root, if stored, in the fork of its slot.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the stored bytes do not decode.
    pub fn block(&self, root: Root) -> Result<Option<combined::SignedBeaconBlock<P>>, ChainError> {
        self.read_with(self.blocks, &root.0, "block", |bytes| {
            combined::SignedBeaconBlock::decode_at(bytes, &self.config)
        })
    }

    /// Stores the verified sidecars of an imported block in one atomic write.
    ///
    /// # Errors
    ///
    /// Fails when the write fails.
    pub(crate) fn put_sidecars(
        &self,
        root: Root,
        sidecars: &[Sidecar<P>],
    ) -> Result<(), ChainError> {
        let mut batch = Batch::new();
        for sidecar in sidecars {
            match sidecar {
                Sidecar::Blob(blob) => {
                    batch.put(
                        self.blobs,
                        &Self::index_key(root, blob.index.0),
                        &blob.encode(),
                    )?;
                }
                Sidecar::Column(column) => batch.put(
                    self.columns,
                    &Self::index_key(root, column.index().0),
                    &column.encode(),
                )?,
            }
        }
        Ok(self.store.write(&batch)?)
    }

    /// A stored blob sidecar of a block.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the stored bytes do not decode.
    pub fn blob(&self, root: Root, index: BlobIndex) -> Result<Option<BlobSidecar<P>>, ChainError> {
        self.read_with(
            self.blobs,
            &Self::index_key(root, index.0),
            "blob",
            BlobSidecar::decode,
        )
    }

    /// A stored column of a block, if this node custodies it.
    ///
    /// # Arguments
    ///
    /// - `fork`: the fork of the block, which fixes the column's format.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the stored bytes do not decode.
    pub fn column(
        &self,
        root: Root,
        index: ColumnIndex,
        fork: ForkName,
    ) -> Result<Option<combined::DataColumnSidecar<P>>, ChainError> {
        self.read_with(
            self.columns,
            &Self::index_key(root, index.0),
            "column",
            |bytes| combined::DataColumnSidecar::decode(bytes, fork),
        )
    }

    /// Stores the payload envelope of a block.
    ///
    /// # Errors
    ///
    /// Fails when the write fails.
    pub fn put_envelope(
        &self,
        envelope: &SignedExecutionPayloadEnvelope<P>,
    ) -> Result<(), ChainError> {
        let root = envelope.message.beacon_block_root;
        Ok(self
            .store
            .put(self.envelopes, &root.0, &envelope.encode())?)
    }

    /// The payload envelope of a block, if stored.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the stored bytes do not decode.
    pub fn envelope(
        &self,
        root: Root,
    ) -> Result<Option<SignedExecutionPayloadEnvelope<P>>, ChainError> {
        self.read_with(self.envelopes, &root.0, "envelope", |bytes| {
            SignedExecutionPayloadEnvelope::decode(bytes)
        })
    }

    /// The finalized checkpoint and its post-state, if the node ever finalized one.
    ///
    /// # Errors
    ///
    /// Fails when a read fails, a record does not decode, or the state is missing.
    pub fn finalized(&self) -> Result<Option<(Checkpoint, combined::BeaconState<P>)>, ChainError> {
        let Some(checkpoint) =
            self.read_with(self.meta, FINALIZED_KEY, "checkpoint", Checkpoint::decode)?
        else {
            return Ok(None);
        };
        // The state is written in the same batch as the checkpoint, so it must be there.
        let state = self
            .read_with(self.states, &checkpoint.root.0, "state", |bytes| {
                combined::BeaconState::decode_at(bytes, &self.config)
            })?
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
        let actual = key.len();
        let bytes: [u8; 8] = key.try_into().map_err(|_| ChainError::Corrupt {
            what: "canonical index key",
            error: DecodeError::InvalidLength {
                expected: 8,
                actual,
            },
        })?;
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
        self.read_with(
            self.canonical,
            &slot.0.to_be_bytes(),
            "canonical root",
            Root::decode,
        )
    }

    /// Records a new finality in one atomic write.
    ///
    /// # Arguments
    ///
    /// - `previous`: the finalized checkpoint being superseded, whose state is no longer needed.
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
        previous: Checkpoint,
        checkpoint: Checkpoint,
        state: &combined::BeaconState<P>,
        chain: &[(Slot, Root)],
        orphans: &[Root],
    ) -> Result<(), ChainError> {
        let mut batch = Batch::new();

        // Only the newest anchor state is kept: a full state is hundreds of megabytes on mainnet.
        if previous.root != checkpoint.root {
            batch.delete(self.states, &previous.root.0)?;
        }
        batch.put(self.states, &checkpoint.root.0, &state.encode())?;
        batch.put(self.meta, FINALIZED_KEY, &checkpoint.encode())?;

        // Index the finalized chain by slot, so a slot query never needs the fork choice.
        for (slot, root) in chain {
            batch.put(self.canonical, &slot.0.to_be_bytes(), &root.0)?;
        }

        // Blocks off the finalized chain can never become canonical again, nor their data.
        let snapshot = self.store.snapshot();
        for root in orphans {
            batch.delete(self.blocks, &root.0)?;
            batch.delete(self.envelopes, &root.0)?;
            // Sidecar keys start with the block root.
            // So a prefix scan finds exactly the stored ones.
            for table in [self.blobs, self.columns] {
                for key in snapshot.prefix(table, &root.0)?.keys() {
                    batch.delete(table, &key)?;
                }
            }
        }
        Ok(self.store.write(&batch)?)
    }

    /// Bytes written to the store since it opened.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.store.metrics().bytes_written()
    }

    /// Key of a sidecar: the block root, then the index in big-endian.
    fn index_key(root: Root, index: u64) -> [u8; 40] {
        let mut key = [0; 40];
        key[..32].copy_from_slice(&root.0);
        key[32..].copy_from_slice(&index.to_be_bytes());
        key
    }

    /// Reads one record and decodes it.
    fn read_with<T>(
        &self,
        table: Table,
        key: &[u8],
        what: &'static str,
        decode: impl FnOnce(&[u8]) -> Result<T, DecodeError>,
    ) -> Result<Option<T>, ChainError> {
        self.store
            .get(table, key)?
            .map(|bytes| decode(&bytes).map_err(|error| ChainError::Corrupt { what, error }))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axiom_types::{Epoch, Minimal, altair, fulu, gloas, phase0};

    use super::*;

    type Database = ChainDatabase<Minimal>;

    /// Altair from epoch 1 and Gloas from epoch 2, so slot 8 is Altair and slot 16 is Gloas.
    fn config() -> ChainConfig {
        ChainConfig::minimal()
            .with_fork_epoch(ForkName::Altair, Epoch(1))
            .with_fork_epoch(ForkName::Bellatrix, Epoch(2))
            .with_fork_epoch(ForkName::Capella, Epoch(2))
            .with_fork_epoch(ForkName::Deneb, Epoch(2))
            .with_fork_epoch(ForkName::Electra, Epoch(2))
            .with_fork_epoch(ForkName::Fulu, Epoch(2))
            .with_fork_epoch(ForkName::Gloas, Epoch(2))
    }

    /// A phase0 block at a slot.
    fn block_at(slot: u64) -> combined::SignedBeaconBlock<Minimal> {
        let mut block = phase0::SignedBeaconBlock::<Minimal>::default();
        block.message.slot = Slot(slot);
        combined::SignedBeaconBlock::Phase0(block)
    }

    #[test]
    fn blocks_of_every_fork_round_trip_by_root() {
        // Fixture state: a phase0 block at slot 7, an Altair one at slot 8, a Gloas one at 16.
        let database = Database::in_memory(config()).unwrap();
        let mut altair = altair::SignedBeaconBlock::<Minimal>::default();
        altair.message.slot = Slot(8);
        let mut gloas = gloas::SignedBeaconBlock::<Minimal>::default();
        gloas.message.slot = Slot(16);
        let blocks = [
            block_at(7),
            combined::SignedBeaconBlock::Altair(altair),
            combined::SignedBeaconBlock::Gloas(gloas),
        ];

        for block in &blocks {
            database.put_block(block.block_root(), block).unwrap();
        }

        // Each block reads back in the fork its slot falls in.
        for block in blocks {
            assert_eq!(database.block(block.block_root()).unwrap(), Some(block));
        }
        assert_eq!(database.block(Root::ZERO).unwrap(), None);
    }

    #[test]
    fn finality_records_anchor_index_and_forgets_orphans() {
        // Fixture state: finalized blocks at slots 1 and 3, and an orphan at slot 2.
        //
        //     1 -> 3      finalized chain
        //     1 -> 2      orphan, excluded by finality
        let database = Database::in_memory(config()).unwrap();
        let (one, two, three) = (block_at(1), block_at(2), block_at(3));
        let roots = [one.block_root(), two.block_root(), three.block_root()];
        for (block, root) in [&one, &two, &three].into_iter().zip(roots) {
            database.put_block(root, block).unwrap();
        }
        let column = fulu::DataColumnSidecar::<Minimal> {
            index: ColumnIndex(3),
            ..Default::default()
        };
        let blob = BlobSidecar::<Minimal>::default();
        database
            .put_sidecars(
                roots[1],
                &[
                    Sidecar::Column(Arc::new(column.into())),
                    Sidecar::Blob(Arc::new(blob)),
                ],
            )
            .unwrap();
        let envelope = SignedExecutionPayloadEnvelope::<Minimal> {
            message: gloas::ExecutionPayloadEnvelope {
                beacon_block_root: roots[1],
                ..Default::default()
            },
            ..Default::default()
        };
        database.put_envelope(&envelope).unwrap();
        let checkpoint = Checkpoint {
            epoch: Epoch(1),
            root: roots[2],
        };
        let state = combined::BeaconState::<Minimal>::Phase0(phase0::BeaconState::default());

        // The first anchor at block 1, then finality moving on to block 3.
        let first = Checkpoint {
            epoch: Epoch(0),
            root: roots[0],
        };
        database
            .finalize(first, first, &state, &[(Slot(1), roots[0])], &[])
            .unwrap();
        database
            .finalize(
                first,
                checkpoint,
                &state,
                &[(Slot(3), roots[2])],
                &[roots[1]],
            )
            .unwrap();

        // The superseded anchor state is gone; only the newest is kept.
        assert!(
            !database
                .store
                .contains_key(database.states, &roots[0].0)
                .unwrap()
        );

        // The anchor reads back whole.
        assert_eq!(database.finalized().unwrap(), Some((checkpoint, state)));
        // Slot 1 is the earliest the index holds, and slot 2 was skipped.
        assert_eq!(database.earliest_slot().unwrap(), Some(Slot(1)));
        assert_eq!(database.canonical_root(Slot(1)).unwrap(), Some(roots[0]));
        assert_eq!(database.canonical_root(Slot(2)).unwrap(), None);
        // The orphan and all its data are gone, the finalized blocks stay.
        assert_eq!(database.block(roots[1]).unwrap(), None);
        assert_eq!(
            database
                .column(roots[1], ColumnIndex(3), ForkName::Fulu)
                .unwrap(),
            None
        );
        assert_eq!(database.blob(roots[1], BlobIndex(0)).unwrap(), None);
        assert_eq!(database.envelope(roots[1]).unwrap(), None);
        assert_eq!(database.block(roots[2]).unwrap(), Some(three));
    }

    #[test]
    fn sidecars_round_trip_in_their_fork() {
        // Fixture state: a Fulu column, a Gloas column, and a blob of one block root.
        let database = Database::in_memory(config()).unwrap();
        let root = Root([5; 32]);
        let fulu_column = combined::DataColumnSidecar::Fulu(fulu::DataColumnSidecar::<Minimal> {
            index: ColumnIndex(77),
            ..Default::default()
        });
        let gloas_column =
            combined::DataColumnSidecar::Gloas(gloas::DataColumnSidecar::<Minimal> {
                index: ColumnIndex(78),
                beacon_block_root: root,
                ..Default::default()
            });
        let blob = BlobSidecar::<Minimal> {
            index: BlobIndex(2),
            ..Default::default()
        };

        database
            .put_sidecars(
                root,
                &[
                    Sidecar::Column(Arc::new(fulu_column.clone())),
                    Sidecar::Column(Arc::new(gloas_column.clone())),
                    Sidecar::Blob(Arc::new(blob.clone())),
                ],
            )
            .unwrap();

        assert_eq!(
            database
                .column(root, ColumnIndex(77), ForkName::Fulu)
                .unwrap(),
            Some(fulu_column)
        );
        assert_eq!(
            database
                .column(root, ColumnIndex(78), ForkName::Gloas)
                .unwrap(),
            Some(gloas_column)
        );
        assert_eq!(
            database
                .column(root, ColumnIndex(76), ForkName::Fulu)
                .unwrap(),
            None
        );
        assert_eq!(database.blob(root, BlobIndex(2)).unwrap(), Some(blob));
    }

    #[test]
    fn a_fresh_database_has_no_finality() {
        let database = Database::in_memory(config()).unwrap();

        assert!(!database.has_anchor().unwrap());
        assert_eq!(database.finalized().unwrap(), None);
    }
}
