//! The chain's on-disk layout: every table and key format in one place.

mod archive;
mod blocks;
mod history;
mod light_client;
mod schema;
mod usage;

use std::{marker::PhantomData, path::Path};

pub use archive::{InvalidInterval, SnapshotInterval, StorageMode};
use axiom_light_client::LightClientServer;
use axiom_ssz::{DecodeError, Ssz};
use axiom_store::{Batch, Options, Snapshot, Store, Table};
use axiom_types::{
    BlobData, BlobIndex, ChainConfig, ColumnIndex, Epoch, ForkName, Preset, Root, Slot,
    accessors::CoreState, combined, deneb::BlobSidecar, gloas::SignedExecutionPayloadEnvelope,
    phase0::Checkpoint,
};
use blocks::BlockRecords;
pub use blocks::StoredBlock;
pub use history::{HistoryStart, ReconstructionCursor};
use light_client::LightClientRecords;
use schema::Migration;
pub use schema::SchemaVersion;
pub use usage::TableUsage;

use super::{VerifiedSegment, availability::Sidecar};
use crate::ChainError;

/// Key of the finalized checkpoint in the metadata table.
const FINALIZED_KEY: &[u8] = b"finalized";

/// Key of the layout version in the metadata table.
const SCHEMA_KEY: &[u8] = b"schema";

/// Key of where the stored chain begins in the metadata table.
const HISTORY_KEY: &[u8] = b"history";

/// Key of the first slot whose sidecars may still need pruning, in the metadata table.
const SIDECARS_PRUNED_KEY: &[u8] = b"sidecars pruned";

/// Key of how far past states are rebuilt, in the metadata table.
const RECONSTRUCTED_KEY: &[u8] = b"reconstructed";

/// Most canonical slots one pruning pass walks.
///
/// Pruning runs on the chain thread at each finality, so one pass stays short.
/// An epoch of mainnet finality adds 32 slots, so the pass keeps up with ample margin.
const PRUNE_SLOTS_PER_PASS: usize = 1024;

/// The chain's persistent records, typed over the store's raw tables.
///
/// # Layout
///
/// ```text
///     table         key                    value
///     blocks        block root (32 bytes)  SSZ signed block
///     blinded_blocks block root (32 bytes) SSZ signed blinded block, once its payload is pruned
///     states        block root (32 bytes)  SSZ post-state, kept for the finalized anchor only
///     blobs         root (32) + index (8)  SSZ blob sidecar
///     columns       root (32) + index (8)  SSZ data column sidecar of a custody column
///     envelopes     block root (32 bytes)  SSZ signed payload envelope
///     canonical     slot (8 bytes, BE)     root of the finalized chain's block at that slot
///     snapshots     slot (8 bytes, BE)     SSZ state at that slot, in archive mode
///     state_roots   state root (32 bytes)  slot (8 bytes, BE) of a finalized state
///     light_client  tag + key              settled light client updates and bootstraps
///     meta          name                   single records: version, anchor, history, cursors
/// ```
///
/// Big-endian slots sort in slot order, so a range scan walks the chain forward.
///
/// # Forks
///
/// No record names its fork: the encodings are the spec's, byte for byte.
/// Blocks and states carry their slot at a fixed place, and the configuration maps it to a fork.
/// Columns change shape at Gloas, so their reader names the fork of the block they belong to.
///
/// # Versions
///
/// The metadata table records the layout version.
/// Opening an older database migrates it, one atomic step per version.
/// A version newer than this build is refused rather than misread.
#[derive(Debug)]
pub struct ChainDatabase<P: Preset> {
    /// The key-value store.
    store: Store,
    /// The fork schedule that decodes each record.
    config: ChainConfig,
    /// How much history to keep.
    mode: StorageMode,
    /// Signed blocks by root, whole or blinded.
    blocks: BlockRecords,
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
    /// States by slot, in archive mode.
    snapshots: Table,
    /// Slots of finalized states by state root.
    state_roots: Table,
    /// Light client data.
    light_client: LightClientRecords,
    /// Single named records.
    meta: Table,
    /// The preset the encoded records follow.
    preset: PhantomData<P>,
}

/// A record as the store holds it: key bytes, then value bytes.
pub type RawRecord = (Vec<u8>, Vec<u8>);

/// What one sidecar pruning pass did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SidecarPass {
    /// Blocks whose sidecars were deleted.
    pub blocks: usize,
    /// Whether the pass reached a block still kept, so nothing older is left.
    pub complete: bool,
}

/// What a new finality writes, in one atomic batch.
#[derive(Clone, Copy, Debug)]
pub struct Finality<'a, P: Preset> {
    /// The finalized checkpoint being superseded, whose state is no longer needed.
    pub previous: Checkpoint,
    /// The new finalized checkpoint.
    pub checkpoint: Checkpoint,
    /// The finalized block's post-state, the anchor to resume from.
    pub state: &'a combined::BeaconState<P>,
    /// The newly finalized blocks as slot and root pairs.
    pub chain: &'a [(Slot, Root)],
    /// Roots of blocks that finality excluded, to forget.
    pub orphans: &'a [Root],
    /// States at the snapshot slots the finality passed, in archive mode.
    pub snapshots: &'a [combined::BeaconState<P>],
    /// Roots of the newly finalized states with their slots, in archive mode.
    pub state_roots: &'a [(Root, Slot)],
}

impl<P: Preset> ChainDatabase<P> {
    /// Opens or creates a database in a directory, for a chain's fork schedule.
    ///
    /// An older layout is migrated to the current one first.
    ///
    /// # Errors
    ///
    /// - The directory cannot be opened, or another process holds it.
    /// - The layout version is unknown to this build.
    /// - A migration step fails.
    pub fn open(directory: &Path, config: ChainConfig) -> Result<Self, ChainError> {
        Self::open_with(directory, config, Options::default())
    }

    /// Opens or creates a database under explicit store options, such as without auto-compaction.
    ///
    /// # Errors
    ///
    /// Fails as opening does, and when an option breaks the store's bounds.
    pub fn open_with(
        directory: &Path,
        config: ChainConfig,
        options: Options,
    ) -> Result<Self, ChainError> {
        Self::with_store(Store::open(directory, options)?, config)
    }

    /// Rewrites every segment mostly holding dead records, to give their space back.
    ///
    /// # Errors
    ///
    /// Fails on an I/O error or a corrupt segment.
    pub fn compact(&self) -> Result<(), ChainError> {
        Ok(self.store.compact()?)
    }

    /// A database that lives in memory and vanishes with the node.
    ///
    /// # Errors
    ///
    /// Fails only if the tables cannot be named, which cannot happen for these names.
    pub fn in_memory(config: ChainConfig) -> Result<Self, ChainError> {
        Self::with_store(Store::in_memory(), config)
    }

    /// Keeps history as a storage mode says, from now on.
    ///
    /// The mode only governs what is written from here.
    /// Switching to archive mode leaves no snapshot behind the current finality.
    #[must_use]
    pub const fn with_mode(mut self, mode: StorageMode) -> Self {
        self.mode = mode;
        self
    }

    /// How much history the database keeps.
    #[must_use]
    pub const fn mode(&self) -> StorageMode {
        self.mode
    }

    /// The fork schedule records decode under.
    #[must_use]
    pub const fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Opens a database without bringing its layout to the current version, to read the version.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be opened, or another process holds it.
    pub fn open_unmigrated(directory: &Path, config: ChainConfig) -> Result<Self, ChainError> {
        Self::named(Store::open(directory, Options::default())?, config)
    }

    /// Names the tables in an open store, then brings its layout to the current version.
    fn with_store(store: Store, config: ChainConfig) -> Result<Self, ChainError> {
        let database = Self::named(store, config)?;
        database.migrate()?;
        Ok(database)
    }

    /// Names the tables in an open store.
    fn named(store: Store, config: ChainConfig) -> Result<Self, ChainError> {
        Ok(Self {
            blocks: BlockRecords::new(store.table("blocks")?, store.table("blinded_blocks")?),
            states: store.table("states")?,
            blobs: store.table("blobs")?,
            columns: store.table("columns")?,
            envelopes: store.table("envelopes")?,
            canonical: store.table("canonical")?,
            snapshots: store.table("snapshots")?,
            state_roots: store.table("state_roots")?,
            light_client: LightClientRecords::new(store.table("light_client")?),
            meta: store.table("meta")?,
            store,
            config,
            mode: StorageMode::default(),
            preset: PhantomData,
        })
    }

    /// Every table by name, in the layout's order.
    const fn tables(&self) -> [(&'static str, Table); 11] {
        [
            ("blocks", self.blocks.full_table()),
            ("blinded_blocks", self.blocks.blinded_table()),
            ("states", self.states),
            ("blobs", self.blobs),
            ("columns", self.columns),
            ("envelopes", self.envelopes),
            ("canonical", self.canonical),
            ("snapshots", self.snapshots),
            ("state_roots", self.state_roots),
            ("light_client", self.light_client.table()),
            ("meta", self.meta),
        ]
    }

    /// Entries and bytes of every table, in the layout's order.
    ///
    /// # Errors
    ///
    /// Fails when a read fails.
    pub fn usage(&self) -> Result<Vec<TableUsage>, ChainError> {
        let snapshot = self.store.snapshot();
        self.tables()
            .into_iter()
            .map(|(name, table)| {
                let mut usage = TableUsage::empty(name);
                for entry in snapshot.entries(table)? {
                    let (key, value) = entry?;
                    usage.add(key.len(), value.len());
                }
                Ok(usage)
            })
            .collect()
    }

    /// Every key and value of one table, in key order.
    ///
    /// # Errors
    ///
    /// Fails when no table has the name, or a read fails.
    pub fn entries(&self, name: &str) -> Result<Vec<RawRecord>, ChainError> {
        let tables = self.tables();
        let table = tables
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, table)| *table)
            .ok_or_else(|| ChainError::UnknownTable(name.to_owned()))?;
        let entries = self.store.snapshot().entries(table)?;
        Ok(entries.collect::<Result<_, _>>()?)
    }

    /// Deletes every archived state snapshot, and the state roots and rebuild cursor that go with them.
    ///
    /// The finalized anchor state stays, so the node still resumes.
    ///
    /// # Returns
    ///
    /// The snapshots deleted.
    ///
    /// # Errors
    ///
    /// Fails when a read or the write fails.
    pub fn prune_states(&self) -> Result<usize, ChainError> {
        let snapshot = self.store.snapshot();
        let mut batch = Batch::new();
        let mut snapshots = 0;
        for entry in snapshot.entries(self.snapshots)? {
            let (key, _) = entry?;
            batch.delete(self.snapshots, &key)?;
            snapshots += 1;
        }
        for entry in snapshot.entries(self.state_roots)? {
            let (key, _) = entry?;
            batch.delete(self.state_roots, &key)?;
        }
        batch.delete(self.meta, RECONSTRUCTED_KEY)?;
        self.store.write(&batch)?;
        Ok(snapshots)
    }

    /// The layout version the database was last written in.
    ///
    /// A database with no record is fresh when it holds no anchor, and of the first layout otherwise.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the record is malformed.
    pub fn schema_version(&self) -> Result<SchemaVersion, ChainError> {
        match self.store.get(self.meta, SCHEMA_KEY)? {
            Some(bytes) => SchemaVersion::decode(&bytes).ok_or(ChainError::Corrupt {
                what: "schema version",
                error: DecodeError::InvalidLength {
                    expected: 8,
                    actual: bytes.len(),
                },
            }),
            None if self.has_anchor()? => Ok(SchemaVersion::FIRST),
            None => Ok(SchemaVersion::CURRENT),
        }
    }

    /// Runs every migration step from the stored version to the current one.
    fn migrate(&self) -> Result<(), ChainError> {
        let mut version = self.schema_version()?;
        while version != SchemaVersion::CURRENT {
            let step = Migration::from(version).ok_or(ChainError::UnknownSchema {
                found: version,
                supported: SchemaVersion::CURRENT,
            })?;
            // Invariant: a step and its version bump commit together, so a crash repeats the step whole.
            let mut batch = Batch::new();
            step.stage(self, &mut batch)?;
            batch.put(self.meta, SCHEMA_KEY, &step.target().encode())?;
            self.store.write(&batch)?;
            version = step.target();
        }
        // A fresh database records its version at once, before any data names an anchor.
        if !self.store.contains_key(self.meta, SCHEMA_KEY)? {
            self.store
                .put(self.meta, SCHEMA_KEY, &SchemaVersion::CURRENT.encode())?;
        }
        Ok(())
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
        let mut batch = Batch::new();
        self.blocks.stage(&mut batch, root, block, false)?;
        Ok(self.store.write(&batch)?)
    }

    /// The block with a root, if stored with its payload, in the fork of its slot.
    ///
    /// A block whose payload was pruned is not returned; the stored form names it.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the stored bytes do not decode.
    pub fn block(&self, root: Root) -> Result<Option<combined::SignedBeaconBlock<P>>, ChainError> {
        self.blocks.full(&self.store, root, &self.config)
    }

    /// The block with a root as stored: whole, or blinded once its payload was pruned.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the stored bytes do not decode.
    pub fn stored_block(&self, root: Root) -> Result<Option<StoredBlock<P>>, ChainError> {
        self.blocks.stored(&self.store, root, &self.config)
    }

    /// Prunes the payloads of finalized blocks at finality, keeping their blinded form.
    ///
    /// Blocks are then served whole by taking their payload bodies back from the engine.
    #[must_use]
    pub const fn pruning_payloads(mut self, prunes: bool) -> Self {
        self.blocks = self.blocks.pruning_payloads(prunes);
        self
    }

    /// Replaces every finalized whole block below the finalized one by its blinded form.
    ///
    /// The finalized block itself keeps its payload, as the chain resumes from it.
    ///
    /// # Returns
    ///
    /// The blocks whose payload left the disk.
    ///
    /// # Errors
    ///
    /// Fails when a read or the write fails.
    pub fn prune_payloads(&self) -> Result<usize, ChainError> {
        // The checkpoint alone is read: decoding the anchor state would cost hundreds of megabytes.
        let Some(checkpoint) =
            self.read_with(self.meta, FINALIZED_KEY, "finalized checkpoint", |bytes| {
                Checkpoint::decode(bytes)
            })?
        else {
            return Ok(0);
        };
        let snapshot = self.store.snapshot();
        let mut batch = Batch::new();
        let mut pruned = 0;
        for entry in snapshot.entries(self.canonical)? {
            let (_, value) = entry?;
            let root = Root::decode(&value).map_err(|error| ChainError::Corrupt {
                what: "canonical root",
                error,
            })?;
            if root != checkpoint.root
                && self
                    .blocks
                    .stage_pruning::<P>(&snapshot, &mut batch, root, &self.config)?
            {
                pruned += 1;
            }
        }
        self.store.write(&batch)?;
        Ok(pruned)
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
            self.stage_sidecar(&mut batch, root, sidecar)?;
        }
        Ok(self.store.write(&batch)?)
    }

    /// Adds one sidecar to a batch.
    fn stage_sidecar(
        &self,
        batch: &mut Batch,
        root: Root,
        sidecar: &Sidecar<P>,
    ) -> Result<(), ChainError> {
        match sidecar {
            Sidecar::Blob(blob) => batch.put(
                self.blobs,
                &Self::index_key(root, blob.index.0),
                &blob.encode(),
            )?,
            Sidecar::Column(column) => batch.put(
                self.columns,
                &Self::index_key(root, column.index().0),
                &column.encode(),
            )?,
        }
        Ok(())
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

    /// The stored post-state of a block, if the database keeps one.
    ///
    /// Only the latest finalized anchor's state is kept.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the record does not decode.
    pub fn state(&self, root: Root) -> Result<Option<combined::BeaconState<P>>, ChainError> {
        self.read_with(self.states, &root.0, "state", |bytes| {
            combined::BeaconState::decode_at(bytes, &self.config)
        })
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
        Self::slot_key(&key).map(Some)
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

    /// The finalized chain's blocks with slots in a range, oldest first.
    ///
    /// # Arguments
    ///
    /// - `start`: the first slot, included.
    /// - `end`: the last slot, excluded.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the index holds a malformed record.
    pub fn canonical_range(&self, start: Slot, end: Slot) -> Result<Vec<(Slot, Root)>, ChainError> {
        let (lower, upper) = (start.0.to_be_bytes(), end.0.to_be_bytes());
        let snapshot = self.store.snapshot();
        let mut blocks = Vec::new();
        for entry in snapshot.range(self.canonical, lower.as_slice()..upper.as_slice())? {
            let (key, value) = entry?;
            let root = Root::decode(&value).map_err(|error| ChainError::Corrupt {
                what: "canonical root",
                error,
            })?;
            blocks.push((Self::slot_key(&key)?, root));
        }
        Ok(blocks)
    }

    /// The finalized chain's latest block at or before a slot, the one canonical there.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the index holds a malformed record.
    pub fn canonical_at_or_before(&self, slot: Slot) -> Result<Option<Root>, ChainError> {
        let upper = slot.0.to_be_bytes();
        let snapshot = self.store.snapshot();
        let Some((_, value)) = snapshot
            .range(self.canonical, ..=upper.as_slice())?
            .next_back()
            .transpose()?
        else {
            return Ok(None);
        };
        Root::decode(&value)
            .map(Some)
            .map_err(|error| ChainError::Corrupt {
                what: "canonical root",
                error,
            })
    }

    /// Where the stored, unbroken chain begins, if anything is stored.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the record is malformed.
    pub fn history_start(&self) -> Result<Option<HistoryStart>, ChainError> {
        self.read_with(
            self.meta,
            HISTORY_KEY,
            "history start",
            HistoryStart::decode,
        )
    }

    /// Adds a new history start to a batch.
    fn stage_history_start(
        &self,
        batch: &mut Batch,
        start: HistoryStart,
    ) -> Result<(), ChainError> {
        Ok(batch.put(self.meta, HISTORY_KEY, &start.encode())?)
    }

    /// Records the anchor a chain starts from: its block, its state, and the history start.
    ///
    /// The anchor state is also the first snapshot in archive mode.
    ///
    /// # Errors
    ///
    /// Fails when the write fails.
    pub(crate) fn put_anchor(
        &self,
        checkpoint: Checkpoint,
        signed: &combined::SignedBeaconBlock<P>,
        state: &combined::BeaconState<P>,
    ) -> Result<(), ChainError> {
        let mut batch = Batch::new();
        self.blocks
            .stage(&mut batch, checkpoint.root, signed, false)?;
        batch.put(self.states, &checkpoint.root.0, &state.encode())?;
        batch.put(self.meta, FINALIZED_KEY, &checkpoint.encode())?;
        batch.put(
            self.canonical,
            &signed.slot().0.to_be_bytes(),
            &checkpoint.root.0,
        )?;
        self.stage_history_start(
            &mut batch,
            HistoryStart {
                slot: signed.slot(),
                parent_root: signed.parent_root(),
            },
        )?;
        if self.mode.interval().is_some() {
            // States below a later anchor are rebuilt once backfill reaches genesis.
            if signed.slot() > Slot(0) {
                let cursor = ReconstructionCursor {
                    reached: Slot(0),
                    target: signed.slot(),
                };
                batch.put(self.meta, RECONSTRUCTED_KEY, &cursor.encode())?;
            }
            self.stage_snapshot(&mut batch, state)?;
            batch.put(
                self.state_roots,
                &state.hash_tree_root().0,
                &state.slot().0.to_be_bytes(),
            )?;
        }
        Ok(self.store.write(&batch)?)
    }

    /// Records a new finality in one atomic write.
    ///
    /// # Errors
    ///
    /// Fails when the write fails.
    pub fn finalize(&self, finality: &Finality<'_, P>) -> Result<(), ChainError> {
        let Finality {
            previous,
            checkpoint,
            state,
            chain,
            orphans,
            snapshots,
            state_roots,
        } = *finality;
        let mut batch = Batch::new();

        // Only the newest anchor state is kept here: a full state is hundreds of megabytes on mainnet.
        if previous.root != checkpoint.root {
            batch.delete(self.states, &previous.root.0)?;
        }
        batch.put(self.states, &checkpoint.root.0, &state.encode())?;
        batch.put(self.meta, FINALIZED_KEY, &checkpoint.encode())?;

        // Index the finalized chain by slot, so a slot query never needs the fork choice.
        for (slot, root) in chain {
            batch.put(self.canonical, &slot.0.to_be_bytes(), &root.0)?;
        }
        for snapshot in snapshots {
            self.stage_snapshot(&mut batch, snapshot)?;
        }
        for (root, slot) in state_roots {
            batch.put(self.state_roots, &root.0, &slot.0.to_be_bytes())?;
        }

        // Blocks off the finalized chain can never become canonical again, nor their data.
        let snapshot = self.store.snapshot();
        for root in orphans {
            self.blocks.stage_removal(&mut batch, *root)?;
            batch.delete(self.envelopes, &root.0)?;
            self.stage_sidecar_removal(&snapshot, &mut batch, *root)?;
        }

        // Finalized blocks below the new anchor lose their payloads, which the engine keeps.
        if self.blocks.prunes_payloads() {
            let superseded = chain
                .iter()
                .map(|(_, root)| *root)
                .chain([previous.root])
                .filter(|root| *root != checkpoint.root);
            for root in superseded {
                self.blocks
                    .stage_pruning::<P>(&snapshot, &mut batch, root, &self.config)?;
            }
        }
        Ok(self.store.write(&batch)?)
    }

    /// Adds the removal of every stored sidecar of a block to a batch.
    fn stage_sidecar_removal(
        &self,
        snapshot: &Snapshot,
        batch: &mut Batch,
        root: Root,
    ) -> Result<(), ChainError> {
        // Sidecar keys start with the block root, so a prefix scan finds exactly the stored ones.
        for table in [self.blobs, self.columns] {
            for key in snapshot.prefix(table, &root.0)?.keys() {
                batch.delete(table, &key)?;
            }
        }
        Ok(())
    }

    /// Stores a verified backfill segment and its new history start, in one atomic write.
    ///
    /// # Errors
    ///
    /// - The segment was checked against another start than the stored one.
    /// - The write fails.
    pub fn put_history(&self, segment: &VerifiedSegment<P>) -> Result<(), ChainError> {
        let stored = self.history_start()?;
        if stored != Some(segment.extends) {
            return Err(ChainError::StaleSegment {
                extends: segment.extends.slot,
                stored: stored.map(|start| start.slot),
            });
        }
        let mut batch = Batch::new();
        let archive = self.mode.interval().is_some();
        for (root, block) in &segment.blocks {
            // History below the anchor is finalized, so it is stored blinded when payloads are pruned.
            self.blocks.stage(&mut batch, *root, block, true)?;
            batch.put(self.canonical, &block.slot().0.to_be_bytes(), &root.0)?;
            // The block names its post-state's root, so archive lookups by root reach it at once.
            if archive {
                batch.put(
                    self.state_roots,
                    &block.message().state_root().0,
                    &block.slot().0.to_be_bytes(),
                )?;
            }
        }
        for (root, sidecar) in &segment.sidecars {
            self.stage_sidecar(&mut batch, *root, sidecar)?;
        }
        for envelope in &segment.envelopes {
            let root = envelope.message.beacon_block_root;
            batch.put(self.envelopes, &root.0, &envelope.encode())?;
        }
        self.stage_history_start(&mut batch, segment.start)?;
        Ok(self.store.write(&batch)?)
    }

    /// Adds a state snapshot to a batch, under its slot.
    fn stage_snapshot(
        &self,
        batch: &mut Batch,
        state: &combined::BeaconState<P>,
    ) -> Result<(), ChainError> {
        Ok(batch.put(
            self.snapshots,
            &state.slot().0.to_be_bytes(),
            &state.encode(),
        )?)
    }

    /// Stores state snapshots, the state roots they passed, and how far rebuilding reached.
    ///
    /// # Errors
    ///
    /// Fails when the write fails.
    pub(crate) fn put_reconstruction(
        &self,
        snapshots: &[combined::BeaconState<P>],
        state_roots: &[(Root, Slot)],
        cursor: ReconstructionCursor,
    ) -> Result<(), ChainError> {
        let mut batch = Batch::new();
        for snapshot in snapshots {
            self.stage_snapshot(&mut batch, snapshot)?;
        }
        for (root, slot) in state_roots {
            batch.put(self.state_roots, &root.0, &slot.0.to_be_bytes())?;
        }
        batch.put(self.meta, RECONSTRUCTED_KEY, &cursor.encode())?;
        Ok(self.store.write(&batch)?)
    }

    /// How far rebuilding the states below a checkpoint anchor has come, if one is due.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the record is malformed.
    pub fn reconstruction(&self) -> Result<Option<ReconstructionCursor>, ChainError> {
        self.read_with(
            self.meta,
            RECONSTRUCTED_KEY,
            "reconstruction cursor",
            ReconstructionCursor::decode,
        )
    }

    /// The latest state snapshot at or before a slot.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the stored bytes do not decode.
    pub fn snapshot_before(
        &self,
        slot: Slot,
    ) -> Result<Option<combined::BeaconState<P>>, ChainError> {
        let upper = slot.0.to_be_bytes();
        let snapshot = self.store.snapshot();
        let Some((_, bytes)) = snapshot
            .range(self.snapshots, ..=upper.as_slice())?
            .next_back()
            .transpose()?
        else {
            return Ok(None);
        };
        combined::BeaconState::decode_at(&bytes, &self.config)
            .map(Some)
            .map_err(|error| ChainError::Corrupt {
                what: "state snapshot",
                error,
            })
    }

    /// The slot of the latest state snapshot at or before a slot, read from the keys alone.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or a key is malformed.
    pub fn snapshot_slot_before(&self, slot: Slot) -> Result<Option<Slot>, ChainError> {
        let upper = slot.0.to_be_bytes();
        let snapshot = self.store.snapshot();
        snapshot
            .range(self.snapshots, ..=upper.as_slice())?
            .keys()
            .next_back()
            .map(|key| Self::slot_key(&key))
            .transpose()
    }

    /// Stores a state as a snapshot under its slot.
    ///
    /// # Errors
    ///
    /// Fails when the write fails.
    pub(crate) fn put_snapshot(&self, state: &combined::BeaconState<P>) -> Result<(), ChainError> {
        let mut batch = Batch::new();
        self.stage_snapshot(&mut batch, state)?;
        Ok(self.store.write(&batch)?)
    }

    /// The slot of a finalized state with a root, if the index holds it.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or the record is malformed.
    pub fn state_root_slot(&self, root: Root) -> Result<Option<Slot>, ChainError> {
        self.read_with(
            self.state_roots,
            &root.0,
            "state root slot",
            Self::decode_slot,
        )
    }

    /// Deletes the sidecars of finalized blocks past their retention window.
    ///
    /// Each fork's data form has its own window, so the cutoff is decided slot by slot.
    /// A margin keeps that many epochs more than the window.
    /// The pass stops at the first block still kept, and resumes there next time.
    /// See `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` in the Deneb p2p spec.
    /// See `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS` in the Fulu p2p spec.
    ///
    /// # Errors
    ///
    /// Fails when a read or the write fails.
    pub fn prune_sidecars(
        &self,
        current: Epoch,
        margin_epochs: u64,
    ) -> Result<SidecarPass, ChainError> {
        let from = self
            .read_with(
                self.meta,
                SIDECARS_PRUNED_KEY,
                "sidecar cursor",
                Self::decode_slot,
            )?
            .unwrap_or(Slot(0));
        let snapshot = self.store.snapshot();
        let mut batch = Batch::new();
        let mut cursor = from;
        let mut pruned = 0;
        let mut walked = 0;
        let mut complete = false;
        let lower = from.0.to_be_bytes();
        for entry in snapshot
            .range(self.canonical, lower.as_slice()..)?
            .take(PRUNE_SLOTS_PER_PASS)
        {
            walked += 1;
            let (key, value) = entry?;
            let slot = Self::slot_key(&key)?;
            let epoch = slot.epoch::<P>();
            let data = self.config.fork_at(epoch).blob_data();
            // Blocks before Deneb have no sidecars, so the cursor just walks past them.
            if data != BlobData::None {
                let window = self
                    .config
                    .blob_retention_epochs(data)
                    .saturating_add(margin_epochs);
                // Threshold: data of epoch e is kept while e + window + margin >= current epoch.
                if epoch.0.saturating_add(window) >= current.0 {
                    complete = true;
                    break;
                }
                let root = Root::decode(&value).map_err(|error| ChainError::Corrupt {
                    what: "canonical root",
                    error,
                })?;
                self.stage_sidecar_removal(&snapshot, &mut batch, root)?;
                pruned += 1;
            }
            cursor = slot + 1;
        }
        if cursor != from {
            batch.put(self.meta, SIDECARS_PRUNED_KEY, &cursor.0.to_be_bytes())?;
            self.store.write(&batch)?;
        }
        Ok(SidecarPass {
            blocks: pruned,
            // A pass that ran out of finalized slots also caught up.
            complete: complete || walked < PRUNE_SLOTS_PER_PASS,
        })
    }

    /// Persists what a light client server settled, so a restart serves it at once.
    ///
    /// # Arguments
    ///
    /// - `from_period`: the first sync committee period whose best update may have changed.
    /// - `earliest`: the oldest slot still served; older records go.
    ///
    /// # Errors
    ///
    /// Fails when a read or the write fails.
    pub(crate) fn put_light_client(
        &self,
        server: &LightClientServer<P>,
        from_period: u64,
        earliest: Slot,
    ) -> Result<(), ChainError> {
        let mut batch = Batch::new();
        self.light_client.stage(
            &self.store.snapshot(),
            &mut batch,
            server,
            from_period,
            earliest,
        )?;
        Ok(self.store.write(&batch)?)
    }

    /// Hands the persisted light client data back to a server.
    ///
    /// # Errors
    ///
    /// Fails when the read fails or a record does not decode.
    pub(crate) fn restore_light_client(
        &self,
        server: &mut LightClientServer<P>,
    ) -> Result<(), ChainError> {
        self.light_client
            .restore(&self.store.snapshot(), &self.config, server)
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

    /// Reads a big-endian slot key.
    fn slot_key(key: &[u8]) -> Result<Slot, ChainError> {
        Self::decode_slot(key).map_err(|error| ChainError::Corrupt {
            what: "slot key",
            error,
        })
    }

    /// Decodes a slot stored as eight big-endian bytes, the order that sorts keys by slot.
    fn decode_slot(bytes: &[u8]) -> Result<Slot, DecodeError> {
        let array: [u8; 8] = bytes.try_into().map_err(|_| DecodeError::InvalidLength {
            expected: 8,
            actual: bytes.len(),
        })?;
        Ok(Slot(u64::from_be_bytes(array)))
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
    use std::{env, fs, path::PathBuf, process, sync::Arc};

    use axiom_ssz::ByteList;
    use axiom_types::{
        Epoch, Minimal, altair, capella, combined::SignedBlindedBeaconBlock, fulu, gloas, phase0,
    };

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

    /// A Capella block at a slot, its payload naming one transaction.
    fn capella_at(slot: u64) -> combined::SignedBeaconBlock<Minimal> {
        let mut block = capella::SignedBeaconBlock::<Minimal>::default();
        block.message.slot = Slot(slot);
        let transaction = ByteList::try_from(vec![0x02, slot as u8]).unwrap();
        block
            .message
            .body
            .execution_payload
            .transactions
            .push(transaction)
            .unwrap();
        combined::SignedBeaconBlock::Capella(block)
    }

    #[test]
    fn finality_blinds_the_blocks_it_passes_when_payloads_are_pruned() {
        // Fixture state: Capella from genesis, an anchor at slot 1, then finality at slot 3.
        //
        //     1 -> 2 -> 3      finalized chain, 3 the new anchor
        let config = ChainConfig::minimal().with_forks_at_genesis(ForkName::Capella);
        let database = Database::in_memory(config).unwrap().pruning_payloads(true);
        let blocks = [capella_at(1), capella_at(2), capella_at(3)];
        let roots = blocks
            .each_ref()
            .map(combined::SignedBeaconBlock::block_root);
        for (block, root) in blocks.iter().zip(roots) {
            database.put_block(root, block).unwrap();
        }
        let state = combined::BeaconState::<Minimal>::Phase0(phase0::BeaconState::default());
        let first = Checkpoint {
            epoch: Epoch(0),
            root: roots[0],
        };
        database.put_anchor(first, &blocks[0], &state).unwrap();
        let checkpoint = Checkpoint {
            epoch: Epoch(1),
            root: roots[2],
        };
        database
            .finalize(&Finality {
                previous: first,
                checkpoint,
                state: &state,
                chain: &[(Slot(2), roots[1]), (Slot(3), roots[2])],
                orphans: &[],
                snapshots: &[],
                state_roots: &[],
            })
            .unwrap();

        // The old anchor and block 2 are blinded; the new anchor keeps its payload.
        for (block, root) in blocks[..2].iter().zip(roots) {
            assert_eq!(database.block(root).unwrap(), None);
            let blinded = SignedBlindedBeaconBlock::blinding(block).unwrap();
            assert_eq!(
                database.stored_block(root).unwrap(),
                Some(StoredBlock::Blinded(blinded))
            );
        }
        assert_eq!(
            database.stored_block(roots[2]).unwrap(),
            Some(StoredBlock::Full(blocks[2].clone()))
        );

        // Without pruning, the same finality keeps every payload.
        let config = ChainConfig::minimal().with_forks_at_genesis(ForkName::Capella);
        let keeping = Database::in_memory(config).unwrap();
        for (block, root) in blocks.iter().zip(roots) {
            keeping.put_block(root, block).unwrap();
        }
        keeping.put_anchor(first, &blocks[0], &state).unwrap();
        keeping
            .finalize(&Finality {
                previous: first,
                checkpoint,
                state: &state,
                chain: &[(Slot(2), roots[1]), (Slot(3), roots[2])],
                orphans: &[],
                snapshots: &[],
                state_roots: &[],
            })
            .unwrap();
        assert_eq!(keeping.block(roots[1]).unwrap(), Some(blocks[1].clone()));

        // The command for an existing database blinds the same two blocks.
        assert_eq!(keeping.prune_payloads().unwrap(), 2);
        assert_eq!(keeping.block(roots[1]).unwrap(), None);
        assert_eq!(keeping.block(roots[2]).unwrap(), Some(blocks[2].clone()));
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
        database.put_anchor(first, &one, &state).unwrap();
        database
            .finalize(&Finality {
                previous: first,
                checkpoint,
                state: &state,
                chain: &[(Slot(3), roots[2])],
                orphans: &[roots[1]],
                snapshots: &[],
                state_roots: &[],
            })
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
        // The anchor started the history, and the canonical block at slot 2 is block 1.
        assert_eq!(
            database.history_start().unwrap(),
            Some(HistoryStart {
                slot: Slot(1),
                parent_root: Root::ZERO,
            })
        );
        assert_eq!(
            database.canonical_at_or_before(Slot(2)).unwrap(),
            Some(roots[0])
        );
        assert_eq!(database.canonical_at_or_before(Slot(0)).unwrap(), None);
        assert_eq!(
            database.canonical_range(Slot(0), Slot(4)).unwrap(),
            [(Slot(1), roots[0]), (Slot(3), roots[2])]
        );
    }

    /// A phase0 state at a slot.
    fn state_at(slot: u64) -> combined::BeaconState<Minimal> {
        combined::BeaconState::Phase0(phase0::BeaconState::<Minimal> {
            slot: Slot(slot),
            ..Default::default()
        })
    }

    #[test]
    fn the_nearest_snapshot_at_or_before_a_slot_is_found() {
        // Fixture state: snapshots at slots 0 and 4 of an archive, both in phase0 epoch 0.
        let database = Database::in_memory(config())
            .unwrap()
            .with_mode(StorageMode::Archive(SnapshotInterval::new(4).unwrap()));
        database.put_snapshot(&state_at(0)).unwrap();
        database.put_snapshot(&state_at(4)).unwrap();

        // Slot 3 falls back to slot 0, slots 4 and 6 to slot 4.
        assert_eq!(
            database.snapshot_slot_before(Slot(3)).unwrap(),
            Some(Slot(0))
        );
        assert_eq!(
            database.snapshot_before(Slot(3)).unwrap(),
            Some(state_at(0))
        );
        assert_eq!(
            database.snapshot_before(Slot(4)).unwrap(),
            Some(state_at(4))
        );
        assert_eq!(
            database.snapshot_slot_before(Slot(6)).unwrap(),
            Some(Slot(4))
        );
    }

    #[test]
    fn an_archive_anchor_after_genesis_schedules_a_rebuild() {
        // Fixture state: an archive anchored at block 5, and a pruned database anchored the same.
        let anchor = block_at(5);
        let checkpoint = Checkpoint {
            epoch: Epoch(0),
            root: anchor.block_root(),
        };
        let state = state_at(5);
        let archive = Database::in_memory(config())
            .unwrap()
            .with_mode(StorageMode::Archive(SnapshotInterval::new(8).unwrap()));
        archive.put_anchor(checkpoint, &anchor, &state).unwrap();
        let pruned = Database::in_memory(config()).unwrap();
        pruned.put_anchor(checkpoint, &anchor, &state).unwrap();

        // The archive keeps the anchor state as a snapshot, indexed by root, and rebuilds below it.
        assert_eq!(
            archive.snapshot_before(Slot(5)).unwrap(),
            Some(state.clone())
        );
        assert_eq!(
            archive.state_root_slot(state.hash_tree_root()).unwrap(),
            Some(Slot(5))
        );
        assert_eq!(
            archive.reconstruction().unwrap(),
            Some(ReconstructionCursor {
                reached: Slot(0),
                target: Slot(5),
            })
        );
        // The pruned database keeps only the anchor state itself.
        assert_eq!(pruned.snapshot_before(Slot(5)).unwrap(), None);
        assert_eq!(pruned.reconstruction().unwrap(), None);
    }

    #[test]
    fn sidecars_past_their_window_are_pruned_and_the_cursor_resumes() {
        // Fixture state: Fulu from epoch 2, and columns kept for one epoch.
        // Finalized blocks at slot 1 (phase0), 16 (epoch 2), and 24 (epoch 3), each with a column.
        let mut config = config();
        config.min_epochs_for_data_column_sidecars_requests = 1;
        let database = Database::in_memory(config).unwrap();
        let blocks = [block_at(1), block_at(16), block_at(24)];
        let first = Checkpoint {
            epoch: Epoch(0),
            root: blocks[0].block_root(),
        };
        database
            .put_anchor(first, &blocks[0], &state_at(1))
            .unwrap();
        let chain: Vec<(Slot, Root)> = blocks
            .iter()
            .map(|block| (block.slot(), block.block_root()))
            .collect();
        database
            .finalize(&Finality {
                previous: first,
                checkpoint: first,
                state: &state_at(1),
                chain: &chain,
                orphans: &[],
                snapshots: &[],
                state_roots: &[],
            })
            .unwrap();
        for (_, root) in &chain {
            let column = fulu::DataColumnSidecar::<Minimal> {
                index: ColumnIndex(3),
                ..Default::default()
            };
            database
                .put_sidecars(*root, &[Sidecar::Column(Arc::new(column.into()))])
                .unwrap();
        }
        let held = |root: Root| {
            database
                .column(root, ColumnIndex(3), ForkName::Fulu)
                .unwrap()
                .is_some()
        };

        // A margin of one epoch keeps epoch 2 at epoch 4: 2 + 1 + 1 = 4.
        assert_eq!(
            database.prune_sidecars(Epoch(4), 1).unwrap(),
            SidecarPass {
                blocks: 0,
                complete: true,
            }
        );

        // Threshold: at epoch 4, epoch 2 + 1 < 4 expires, epoch 3 + 1 = 4 is still served.
        let pass = |epoch, blocks| {
            assert_eq!(
                database.prune_sidecars(Epoch(epoch), 0).unwrap(),
                SidecarPass {
                    blocks,
                    complete: true,
                }
            );
        };
        pass(4, 1);
        assert_eq!(
            [held(chain[0].1), held(chain[1].1), held(chain[2].1)],
            [true, false, true]
        );

        // A second pass at the same epoch resumes past slot 16 and prunes nothing.
        pass(4, 0);
        // One epoch later, slot 24 expires as well.
        pass(5, 1);
        assert!(!held(chain[2].1));
    }

    /// A directory removed when dropped.
    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new(name: &str) -> Self {
            let path = env::temp_dir().join(format!("axiom-db-{name}-{}", process::id()));
            let _fresh = fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_first_layout_database_migrates_to_the_current_one() {
        // Fixture state: an anchored database with its version and history records removed.
        // That is exactly what the first layout wrote.
        let directory = TempDirectory::new("migrate");
        let anchor = block_at(5);
        let checkpoint = Checkpoint {
            epoch: Epoch(0),
            root: anchor.block_root(),
        };
        {
            let database = Database::open(&directory.0, config()).unwrap();
            database
                .put_anchor(checkpoint, &anchor, &state_at(5))
                .unwrap();
            database.store.delete(database.meta, SCHEMA_KEY).unwrap();
            database.store.delete(database.meta, HISTORY_KEY).unwrap();
            assert_eq!(database.schema_version().unwrap(), SchemaVersion::FIRST);
            assert_eq!(database.history_start().unwrap(), None);
        }

        // Reopening runs the one step: the earliest indexed block starts the history.
        let database = Database::open(&directory.0, config()).unwrap();
        assert_eq!(database.schema_version().unwrap(), SchemaVersion::CURRENT);
        assert_eq!(
            database.history_start().unwrap(),
            Some(HistoryStart {
                slot: Slot(5),
                parent_root: Root::ZERO,
            })
        );
    }

    #[test]
    fn a_database_from_a_newer_build_is_refused() {
        // Fixture state: a database recording version 4, one past this build's.
        let directory = TempDirectory::new("future");
        {
            let database = Database::open(&directory.0, config()).unwrap();
            database
                .store
                .put(database.meta, SCHEMA_KEY, &SchemaVersion(4).encode())
                .unwrap();
        }

        let error = Database::open(&directory.0, config()).unwrap_err();
        assert!(
            matches!(
                error,
                ChainError::UnknownSchema {
                    found: SchemaVersion(4),
                    supported: SchemaVersion(3),
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn a_fresh_database_records_the_current_version() {
        let database = Database::in_memory(config()).unwrap();

        assert_eq!(
            database.store.get(database.meta, SCHEMA_KEY).unwrap(),
            Some(SchemaVersion::CURRENT.encode().to_vec())
        );
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
