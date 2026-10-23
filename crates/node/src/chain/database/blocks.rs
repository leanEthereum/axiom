//! Signed blocks on disk: whole, or blinded once finality let their payloads go.

use axiom_ssz::{DecodeError, Root};
use axiom_store::{Batch, Snapshot, Store, Table};
use axiom_types::{
    BlsSignature, ChainConfig, ForkName, KzgCommitment, Preset, Slot,
    combined::{BlindedBlockError, SignedBeaconBlock, SignedBlindedBeaconBlock},
    phase0::BeaconBlockHeader,
};

use crate::ChainError;

/// Bytes before a signed block's message: the message offset, then the signature.
const MESSAGE_OFFSET: usize = 4 + 96;

/// A stored block: whole, or blinded once its payload was pruned.
///
/// A blinded block keeps the payload's header, so its root, signature, and header stay the same.
/// Serving it whole takes the payload's body back from the execution engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredBlock<P: Preset> {
    /// The block with its payload.
    Full(SignedBeaconBlock<P>),
    /// The block with its payload's header in place of the payload.
    Blinded(SignedBlindedBeaconBlock<P>),
}

impl<P: Preset> StoredBlock<P> {
    /// The block's slot.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        match self {
            Self::Full(block) => block.slot(),
            Self::Blinded(block) => block.slot(),
        }
    }

    /// The fork the block belongs to.
    #[must_use]
    pub const fn fork_name(&self) -> ForkName {
        match self {
            Self::Full(block) => block.fork_name(),
            Self::Blinded(block) => block.fork_name(),
        }
    }

    /// The root of the block's parent.
    #[must_use]
    pub const fn parent_root(&self) -> Root {
        match self {
            Self::Full(block) => block.parent_root(),
            Self::Blinded(block) => block.parent_root(),
        }
    }

    /// The block's header, the same blinded or not.
    #[must_use]
    pub fn header(&self) -> BeaconBlockHeader {
        match self {
            Self::Full(block) => block.message().header(),
            Self::Blinded(block) => block.header(),
        }
    }

    /// The proposer's signature.
    #[must_use]
    pub const fn signature(&self) -> &BlsSignature {
        match self {
            Self::Full(block) => block.signature(),
            Self::Blinded(block) => block.signature(),
        }
    }

    /// The blob commitments the block carries.
    #[must_use]
    pub fn blob_kzg_commitments(&self) -> Vec<KzgCommitment> {
        match self {
            Self::Full(block) => block.message().blob_kzg_commitments().to_vec(),
            Self::Blinded(block) => block.blob_kzg_commitments().to_vec(),
        }
    }

    /// The block whole, when its payload is still stored.
    #[must_use]
    pub fn into_full(self) -> Option<SignedBeaconBlock<P>> {
        match self {
            Self::Full(block) => Some(block),
            Self::Blinded(_) => None,
        }
    }
}

/// The two block tables: whole blocks, and blocks whose payload was pruned.
///
/// # Layout
///
/// ```text
///     table            key                    value
///     blocks           block root (32 bytes)  SSZ signed block
///     blinded_blocks   block root (32 bytes)  SSZ signed blinded block
/// ```
///
/// A block sits in exactly one of the two.
/// Both encodings carry the slot at the same place, which fixes the fork to decode in.
#[derive(Clone, Copy, Debug)]
pub(super) struct BlockRecords {
    /// Whole blocks by root.
    full: Table,
    /// Blinded blocks by root.
    blinded: Table,
    /// Whether finalized blocks lose their payloads.
    prunes_payloads: bool,
}

impl BlockRecords {
    /// The records in two tables, keeping every payload.
    pub(super) const fn new(full: Table, blinded: Table) -> Self {
        Self {
            full,
            blinded,
            prunes_payloads: false,
        }
    }

    /// The same records, pruning payloads at finality or not.
    pub(super) const fn pruning_payloads(mut self, prunes: bool) -> Self {
        self.prunes_payloads = prunes;
        self
    }

    /// Whether finalized blocks lose their payloads.
    pub(super) const fn prunes_payloads(self) -> bool {
        self.prunes_payloads
    }

    /// The table of whole blocks.
    pub(super) const fn full_table(self) -> Table {
        self.full
    }

    /// The table of blinded blocks.
    pub(super) const fn blinded_table(self) -> Table {
        self.blinded
    }

    /// Stages a block under its root, blinded when finalized and payloads are pruned.
    pub(super) fn stage<P: Preset>(
        self,
        batch: &mut Batch,
        root: Root,
        block: &SignedBeaconBlock<P>,
        finalized: bool,
    ) -> Result<(), ChainError> {
        match SignedBlindedBeaconBlock::blinding(block)
            .filter(|_| finalized && self.prunes_payloads)
        {
            Some(blinded) => batch.put(self.blinded, &root.0, &blinded.encode())?,
            None => batch.put(self.full, &root.0, &block.encode())?,
        }
        Ok(())
    }

    /// Stages the removal of a block, in whichever table it sits.
    pub(super) fn stage_removal(self, batch: &mut Batch, root: Root) -> Result<(), ChainError> {
        batch.delete(self.full, &root.0)?;
        batch.delete(self.blinded, &root.0)?;
        Ok(())
    }

    /// Stages replacing a whole block by its blinded form, if it has a payload to lose.
    ///
    /// # Returns
    ///
    /// Whether the block was whole and had a payload.
    pub(super) fn stage_pruning<P: Preset>(
        self,
        snapshot: &Snapshot,
        batch: &mut Batch,
        root: Root,
        config: &ChainConfig,
    ) -> Result<bool, ChainError> {
        let Some(bytes) = snapshot.get(self.full, &root.0)? else {
            return Ok(false);
        };
        let block = SignedBeaconBlock::<P>::decode_at(&bytes, config).map_err(|error| {
            ChainError::Corrupt {
                what: "block",
                error,
            }
        })?;
        let Some(blinded) = SignedBlindedBeaconBlock::blinding(&block) else {
            return Ok(false);
        };
        batch.put(self.blinded, &root.0, &blinded.encode())?;
        batch.delete(self.full, &root.0)?;
        Ok(true)
    }

    /// The whole block with a root, if its payload is stored.
    pub(super) fn full<P: Preset>(
        self,
        store: &Store,
        root: Root,
        config: &ChainConfig,
    ) -> Result<Option<SignedBeaconBlock<P>>, ChainError> {
        store
            .get(self.full, &root.0)?
            .map(|bytes| {
                SignedBeaconBlock::decode_at(&bytes, config).map_err(|error| ChainError::Corrupt {
                    what: "block",
                    error,
                })
            })
            .transpose()
    }

    /// The block with a root, whole or blinded, if stored.
    pub(super) fn stored<P: Preset>(
        self,
        store: &Store,
        root: Root,
        config: &ChainConfig,
    ) -> Result<Option<StoredBlock<P>>, ChainError> {
        if let Some(block) = self.full(store, root, config)? {
            return Ok(Some(StoredBlock::Full(block)));
        }
        let Some(bytes) = store.get(self.blinded, &root.0)? else {
            return Ok(None);
        };
        let corrupt = |error| ChainError::Corrupt {
            what: "blinded block",
            error,
        };
        let slot = Slot::decode_at(&bytes, MESSAGE_OFFSET).map_err(corrupt)?;
        let fork = config.fork_at(slot.epoch::<P>());
        let blinded =
            SignedBlindedBeaconBlock::decode(&bytes, fork).map_err(|error| match error {
                BlindedBlockError::Decode(error) => corrupt(error),
                // Only blocks with a payload are stored blinded, so their fork has a blinded form.
                _ => corrupt(DecodeError::InvalidLength {
                    expected: 0,
                    actual: bytes.len(),
                }),
            })?;
        Ok(Some(StoredBlock::Blinded(blinded)))
    }
}
