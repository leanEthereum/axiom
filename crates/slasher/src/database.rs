//! The slasher's on-disk layout: every table and key format in one place.

use std::path::Path;

use axiom_ssz::Ssz;
use axiom_store::{Batch, Metrics, Options, Store, Table};
use axiom_types::{
    Epoch, Slot, ValidatorIndex,
    phase0::{AttestationData, SignedBeaconBlockHeader},
};

use crate::{Geometry, SlasherError, chunk::Chunk, records::VoteId, signers::Signers, span::Span};

/// Key of the layout in the metadata table.
const GEOMETRY_KEY: &[u8] = b"geometry";

/// Key of the latest epoch processed, in the metadata table.
const EPOCH_KEY: &[u8] = b"epoch";

/// The slasher's persistent history, typed over the store's raw tables.
///
/// # Layout
///
/// ```text
///     table       key                         value
///     span_min    row (8) + column (8)        compressed 16-bit cells
///     span_max    row (8) + column (8)        compressed 16-bit cells
///     records     target (8) + chunk (8)      compressed 32-bit vote numbers
///     votes       target (8) + number (4)     SSZ attestation data
///     signers     target (8) + number (4)     signature, then index gaps
///     counters    target (8)                  last vote number given, 4 bytes
///     rows        row (8)                     latest epoch the row was brought to, 8 bytes
///     proposals   slot (8) + proposer (8)     SSZ signed block header
///     meta        name                        layout, latest epoch
/// ```
///
/// Every integer key is big-endian, so a range scan from zero walks the oldest history first.
/// Pruning deletes such a prefix of each table.
///
/// # Invariants
///
/// One batch carries every change of one processing pass.
/// A crash therefore leaves the spans, records, and votes consistent with one another.
#[derive(Debug)]
pub struct SlasherDatabase {
    /// The key-value store.
    store: Store,
    /// Lowest-target arrays.
    span_min: Table,
    /// Highest-target arrays.
    span_max: Table,
    /// Vote numbers by target and validator chunk.
    records: Table,
    /// Vote data by vote.
    votes: Table,
    /// Vote signers by vote.
    signers: Table,
    /// Last vote number per target epoch.
    counters: Table,
    /// Latest epoch per row.
    rows: Table,
    /// Signed headers by slot and proposer.
    proposals: Table,
    /// Single named records.
    meta: Table,
}

impl SlasherDatabase {
    /// Opens or creates a database in a directory.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be opened, or another process holds it.
    pub fn open(directory: &Path) -> Result<Self, SlasherError> {
        Self::with_store(Store::open(directory, Options::default())?)
    }

    /// A database that lives in memory and vanishes with the process.
    ///
    /// # Errors
    ///
    /// Fails only if the tables cannot be named, which cannot happen for these names.
    pub fn in_memory() -> Result<Self, SlasherError> {
        Self::with_store(Store::in_memory())
    }

    /// Names every table in a store.
    fn with_store(store: Store) -> Result<Self, SlasherError> {
        Ok(Self {
            span_min: store.table("span_min")?,
            span_max: store.table("span_max")?,
            records: store.table("records")?,
            votes: store.table("votes")?,
            signers: store.table("signers")?,
            counters: store.table("counters")?,
            rows: store.table("rows")?,
            proposals: store.table("proposals")?,
            meta: store.table("meta")?,
            store,
        })
    }

    /// The store's counters, including bytes on disk.
    #[must_use]
    pub fn metrics(&self) -> Metrics {
        self.store.metrics()
    }

    /// Records the layout on first use, and refuses any other layout later.
    pub(crate) fn adopt(&self, geometry: Geometry) -> Result<(), SlasherError> {
        match self.store.get(self.meta, GEOMETRY_KEY)? {
            None => Ok(self
                .store
                .put(self.meta, GEOMETRY_KEY, &geometry.encode())?),
            Some(bytes) => {
                let stored = Geometry::decode(&bytes).ok_or(SlasherError::Corrupt {
                    table: "meta",
                    len: bytes.len(),
                    reason: "layout of the wrong length",
                })?;
                if stored == geometry {
                    Ok(())
                } else {
                    Err(SlasherError::GeometryMismatch {
                        stored,
                        configured: geometry,
                    })
                }
            }
        }
    }

    /// The latest epoch a pass processed, if any.
    pub(crate) fn epoch(&self) -> Result<Option<Epoch>, SlasherError> {
        self.store
            .get(self.meta, EPOCH_KEY)?
            .map(|bytes| Self::word(&bytes, "meta").map(Epoch))
            .transpose()
    }

    /// A stored span chunk.
    pub(crate) fn span(
        &self,
        span: Span,
        row: u64,
        column: u64,
        cells: usize,
    ) -> Result<Option<Chunk<u16>>, SlasherError> {
        let (table, name) = self.span_table(span);
        self.store
            .get(table, &Self::pair(row, column))?
            .map(|bytes| Chunk::decode(&bytes, cells, name))
            .transpose()
    }

    /// A stored record chunk.
    pub(crate) fn record(
        &self,
        target: Epoch,
        index: u64,
        cells: usize,
    ) -> Result<Option<Chunk<u32>>, SlasherError> {
        self.store
            .get(self.records, &Self::pair(target.0, index))?
            .map(|bytes| Chunk::decode(&bytes, cells, "records"))
            .transpose()
    }

    /// The data of a stored vote.
    pub(crate) fn vote_data(&self, vote: VoteId) -> Result<AttestationData, SlasherError> {
        let bytes = self
            .store
            .get(self.votes, &vote.key())?
            .ok_or(SlasherError::MissingVote {
                target: vote.target,
                id: vote.number,
            })?;
        AttestationData::decode(&bytes).map_err(|source| SlasherError::Decode {
            table: "votes",
            source,
        })
    }

    /// The signers of a stored vote.
    pub(crate) fn vote_signers(&self, vote: VoteId) -> Result<Signers, SlasherError> {
        let bytes =
            self.store
                .get(self.signers, &vote.key())?
                .ok_or(SlasherError::MissingVote {
                    target: vote.target,
                    id: vote.number,
                })?;
        Signers::decode(&bytes)
    }

    /// The last vote number given for a target epoch, zero when none was.
    pub(crate) fn counter(&self, target: Epoch) -> Result<u32, SlasherError> {
        match self.store.get(self.counters, &target.0.to_be_bytes())? {
            None => Ok(0),
            Some(bytes) => {
                let array: [u8; 4] =
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| SlasherError::Corrupt {
                            table: "counters",
                            len: bytes.len(),
                            reason: "counter of the wrong length",
                        })?;
                Ok(u32::from_be_bytes(array))
            }
        }
    }

    /// The latest epoch a row was brought to, if it was ever processed.
    pub(crate) fn row_epoch(&self, row: u64) -> Result<Option<Epoch>, SlasherError> {
        self.store
            .get(self.rows, &row.to_be_bytes())?
            .map(|bytes| Self::word(&bytes, "rows").map(Epoch))
            .transpose()
    }

    /// The header a proposer signed for a slot, if one is stored.
    pub(crate) fn proposal(
        &self,
        slot: Slot,
        proposer: ValidatorIndex,
    ) -> Result<Option<SignedBeaconBlockHeader>, SlasherError> {
        self.store
            .get(self.proposals, &Self::pair(slot.0, proposer.0))?
            .map(|bytes| {
                SignedBeaconBlockHeader::decode(&bytes).map_err(|source| SlasherError::Decode {
                    table: "proposals",
                    source,
                })
            })
            .transpose()
    }

    /// Stages a span chunk.
    pub(crate) fn put_span(
        &self,
        batch: &mut Batch,
        span: Span,
        row: u64,
        column: u64,
        chunk: &Chunk<u16>,
    ) -> Result<(), SlasherError> {
        let (table, _) = self.span_table(span);
        Ok(batch.put(table, &Self::pair(row, column), &chunk.encode())?)
    }

    /// Stages a record chunk.
    pub(crate) fn put_record(
        &self,
        batch: &mut Batch,
        target: Epoch,
        index: u64,
        chunk: &Chunk<u32>,
    ) -> Result<(), SlasherError> {
        Ok(batch.put(self.records, &Self::pair(target.0, index), &chunk.encode())?)
    }

    /// Stages a vote's data and signers.
    pub(crate) fn put_vote(
        &self,
        batch: &mut Batch,
        vote: VoteId,
        data: &AttestationData,
        signers: &Signers,
    ) -> Result<(), SlasherError> {
        batch.put(self.votes, &vote.key(), &data.encode())?;
        Ok(batch.put(self.signers, &vote.key(), &signers.encode())?)
    }

    /// Stages the last vote number given for a target epoch.
    pub(crate) fn put_counter(
        &self,
        batch: &mut Batch,
        target: Epoch,
        last: u32,
    ) -> Result<(), SlasherError> {
        Ok(batch.put(self.counters, &target.0.to_be_bytes(), &last.to_be_bytes())?)
    }

    /// Stages the latest epoch of a row.
    pub(crate) fn put_row(
        &self,
        batch: &mut Batch,
        row: u64,
        epoch: Epoch,
    ) -> Result<(), SlasherError> {
        Ok(batch.put(self.rows, &row.to_be_bytes(), &epoch.0.to_be_bytes())?)
    }

    /// Stages a signed header.
    pub(crate) fn put_proposal(
        &self,
        batch: &mut Batch,
        header: &SignedBeaconBlockHeader,
    ) -> Result<(), SlasherError> {
        let key = Self::pair(header.message.slot.0, header.message.proposer_index.0);
        Ok(batch.put(self.proposals, &key, &header.encode())?)
    }

    /// Stages the latest epoch processed.
    pub(crate) fn put_epoch(&self, batch: &mut Batch, epoch: Epoch) -> Result<(), SlasherError> {
        Ok(batch.put(self.meta, EPOCH_KEY, &epoch.0.to_be_bytes())?)
    }

    /// Commits a batch atomically.
    pub(crate) fn write(&self, batch: &Batch) -> Result<(), SlasherError> {
        Ok(self.store.write(batch)?)
    }

    /// Deletes every vote with a target before an epoch, and every header before a slot.
    ///
    /// Span cells need no deletion: the window clears a column when it reuses it.
    ///
    /// # Returns
    ///
    /// The number of entries deleted.
    pub(crate) fn prune(&self, epoch: Epoch, slot: Slot) -> Result<usize, SlasherError> {
        let snapshot = self.store.snapshot();
        let mut batch = Batch::new();
        let epoch_bound = epoch.0.to_be_bytes();
        let slot_bound = slot.0.to_be_bytes();
        let prefixes = [
            (self.records, &epoch_bound),
            (self.votes, &epoch_bound),
            (self.signers, &epoch_bound),
            (self.counters, &epoch_bound),
            (self.proposals, &slot_bound),
        ];
        for (table, bound) in prefixes {
            // Keys start with the big-endian epoch or slot, so older keys sort below the bound.
            for key in snapshot.range(table, ..bound.as_slice())?.keys() {
                batch.delete(table, &key)?;
            }
        }
        let deleted = batch.len();
        if deleted > 0 {
            self.store.write(&batch)?;
        }
        Ok(deleted)
    }

    /// The table of a span array, and its name for errors.
    const fn span_table(&self, span: Span) -> (Table, &'static str) {
        match span {
            Span::Min => (self.span_min, "span_min"),
            Span::Max => (self.span_max, "span_max"),
        }
    }

    /// Two big-endian words, as one key.
    fn pair(first: u64, second: u64) -> [u8; 16] {
        let mut key = [0; 16];
        key[..8].copy_from_slice(&first.to_be_bytes());
        key[8..].copy_from_slice(&second.to_be_bytes());
        key
    }

    /// A big-endian word from a stored value.
    fn word(bytes: &[u8], table: &'static str) -> Result<u64, SlasherError> {
        let array: [u8; 8] = bytes.try_into().map_err(|_| SlasherError::Corrupt {
            table,
            len: bytes.len(),
            reason: "word of the wrong length",
        })?;
        Ok(u64::from_be_bytes(array))
    }
}
