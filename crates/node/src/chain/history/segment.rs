//! A run of past blocks fetched backwards from the stored chain, and its verification.

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use axiom_bls::PublicKey;
use axiom_ssz::Ssz;
use axiom_state_transition::{BlockError, SignatureBatch, Verification};
use axiom_types::{
    BlobData, ChainConfig, ColumnIndex, Preset, Root, Slot, ValidatorIndex, combined,
    constants::DOMAIN_BEACON_PROPOSER, deneb::BlobSidecar, gloas::SignedExecutionPayloadEnvelope,
    phase0::SigningData,
};
use thiserror::Error;

use crate::chain::{HistoryStart, Sidecar};

/// Decompressed keys of the proposers a segment names.
pub type ProposerKeys = HashMap<ValidatorIndex, PublicKey>;

/// Past blocks and their data, as a peer served them, not yet checked.
///
/// # Overview
///
/// Backfill walks the chain from the stored start towards genesis.
/// Each segment ends right below the stored start, and must link to it by parent root.
///
/// The trusted anchor commits to every ancestor through the parent roots.
/// So the links alone authenticate the blocks, by collision resistance of SHA-256.
/// The proposer signatures are checked too, in one batch, as defense in depth.
///
/// The adversary is a peer serving a forged or a foreign chain.
/// A forged block breaks a link; a block from another fork of the chain breaks a link too.
/// A peer that omits the newest blocks of a range breaks the link to the start.
#[derive(Debug)]
pub struct HistorySegment<P: Preset> {
    /// Blocks, oldest first.
    blocks: Vec<combined::SignedBeaconBlock<P>>,
    /// Blob sidecars of the blocks, whose proofs were checked as they arrived.
    blobs: Vec<BlobSidecar<P>>,
    /// Columns of the blocks, whose proofs were checked as they arrived.
    columns: Vec<combined::DataColumnSidecar<P>>,
    /// Payload envelopes of the blocks, from Gloas on.
    envelopes: Vec<SignedExecutionPayloadEnvelope<P>>,
}

impl<P: Preset> HistorySegment<P> {
    /// A segment of blocks, oldest first, with their data.
    ///
    /// The sidecars' own proofs must already hold: inclusion and KZG.
    #[must_use]
    pub const fn new(
        blocks: Vec<combined::SignedBeaconBlock<P>>,
        blobs: Vec<BlobSidecar<P>>,
        columns: Vec<combined::DataColumnSidecar<P>>,
        envelopes: Vec<SignedExecutionPayloadEnvelope<P>>,
    ) -> Self {
        Self {
            blocks,
            blobs,
            columns,
            envelopes,
        }
    }

    /// Whether the segment holds no block.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// The proposers whose keys the signature check needs.
    #[must_use]
    pub fn proposers(&self) -> BTreeSet<ValidatorIndex> {
        self.blocks
            .iter()
            .filter(|block| !Self::is_genesis(block))
            .map(|block| block.message().proposer_index())
            .collect()
    }

    /// Checks the segment against the stored start, and readies it for storage.
    ///
    /// # Arguments
    ///
    /// - `start`: the oldest stored block, which the segment's newest block must be the parent of.
    /// - `context`: the chain, the proposers' keys, and the data the node keeps.
    ///
    /// # Errors
    ///
    /// Fails on the first broken rule; the segment is then worthless as a whole.
    pub fn verify(
        self,
        start: HistoryStart,
        context: &SegmentContext<'_>,
    ) -> Result<VerifiedSegment<P>, SegmentError> {
        let roots = self.check_links(start)?;
        self.check_signatures(&roots, context)?;
        let sidecars = self.check_sidecars(&roots, context)?;
        let envelopes = self.check_envelopes(&roots)?;
        let new_start = self.blocks.first().map_or(start, |oldest| HistoryStart {
            slot: oldest.slot(),
            parent_root: oldest.parent_root(),
        });
        Ok(VerifiedSegment {
            extends: start,
            start: new_start,
            blocks: roots.into_iter().zip(self.blocks).collect(),
            sidecars,
            envelopes,
        })
    }

    /// Checks that each block is the parent of the next, and the newest the parent of the start.
    ///
    /// # Returns
    ///
    /// Each block's root, in order.
    fn check_links(&self, start: HistoryStart) -> Result<Vec<Root>, SegmentError> {
        let roots: Vec<Root> = self
            .blocks
            .iter()
            .map(combined::SignedBeaconBlock::block_root)
            .collect();
        for (position, block) in self.blocks.iter().enumerate() {
            let slot = block.slot();
            if slot >= start.slot {
                return Err(SegmentError::NotBeforeStart {
                    slot,
                    start: start.slot,
                });
            }
            // Each block names the next one's parent, and the newest names the start's.
            let (child_slot, expected) = match self.blocks.get(position + 1) {
                Some(child) => (child.slot(), child.parent_root()),
                None => (start.slot, start.parent_root),
            };
            if slot >= child_slot {
                return Err(SegmentError::Unordered {
                    slot,
                    next: child_slot,
                });
            }
            if roots[position] != expected {
                return Err(SegmentError::BrokenLink {
                    slot,
                    root: roots[position],
                    expected,
                });
            }
        }
        Ok(roots)
    }

    /// Checks every proposer signature with one multi-pairing.
    ///
    /// See `verify_block_signature` in the phase0 beacon chain spec.
    fn check_signatures(
        &self,
        roots: &[Root],
        context: &SegmentContext<'_>,
    ) -> Result<(), SegmentError> {
        let mut batch = SignatureBatch::new(Verification::Verify);
        for (block, root) in self.blocks.iter().zip(roots) {
            // The genesis block has no proposer and carries an empty signature.
            if Self::is_genesis(block) {
                continue;
            }
            let slot = block.slot();
            let index = block.message().proposer_index();
            let key = context
                .keys
                .get(&index)
                .ok_or(SegmentError::UnknownProposer { slot, index })?;
            let domain = context.config.domain(
                DOMAIN_BEACON_PROPOSER,
                slot.epoch::<P>(),
                context.genesis_validators_root,
            );
            // The block root is the header root, so the signing root covers the whole block.
            let signing_root = SigningData {
                object_root: *root,
                domain,
            }
            .hash_tree_root();
            batch
                .push(key.clone(), signing_root, block.signature())
                .map_err(SegmentError::Signature)?;
        }
        batch.verify().map_err(SegmentError::Signature)
    }

    /// Checks that every sidecar belongs to a block, and that kept blocks have all of theirs.
    fn check_sidecars(
        &self,
        roots: &[Root],
        context: &SegmentContext<'_>,
    ) -> Result<Vec<(Root, Sidecar<P>)>, SegmentError> {
        let positions: HashMap<Root, usize> = roots
            .iter()
            .enumerate()
            .map(|(position, root)| (*root, position))
            .collect();
        let mut held: BTreeSet<(Root, u64)> = BTreeSet::new();
        let mut sidecars = Vec::new();
        let blobs = self.blobs.iter().map(|blob| {
            let root = blob.signed_block_header.message.hash_tree_root();
            (root, blob.index.0, Sidecar::Blob(Arc::new(blob.clone())))
        });
        let columns = self.columns.iter().map(|column| {
            (
                column.block_root(),
                column.index().0,
                Sidecar::Column(Arc::new(column.clone())),
            )
        });
        for (root, index, sidecar) in blobs.chain(columns) {
            let position = *positions
                .get(&root)
                .ok_or(SegmentError::StraySidecar { root, index })?;
            let block = &self.blocks[position];
            let expected = Self::expected_sidecars(block, context);
            if !expected.contains(&index) || !held.insert((root, index)) {
                return Err(SegmentError::StraySidecar { root, index });
            }
            sidecars.push((root, sidecar));
        }
        if context.retained {
            for (block, root) in self.blocks.iter().zip(roots) {
                for index in Self::expected_sidecars(block, context) {
                    if !held.contains(&(*root, index)) {
                        return Err(SegmentError::MissingSidecar {
                            slot: block.slot(),
                            index,
                        });
                    }
                }
            }
        }
        Ok(sidecars)
    }

    /// The sidecar indices a block's data needs: its blob indices, or the sampled columns.
    fn expected_sidecars(
        block: &combined::SignedBeaconBlock<P>,
        context: &SegmentContext<'_>,
    ) -> BTreeSet<u64> {
        let commitments = match block {
            // From Gloas on the bid carries the commitments, for the payload's columns.
            combined::SignedBeaconBlock::Gloas(signed) => signed
                .message
                .body
                .signed_execution_payload_bid
                .message
                .blob_kzg_commitments
                .len(),
            other => other.message().blob_kzg_commitments().len(),
        };
        if commitments == 0 {
            return BTreeSet::new();
        }
        match block.fork_name().blob_data() {
            BlobData::None => BTreeSet::new(),
            BlobData::BlobSidecars => (0..commitments as u64).collect(),
            BlobData::BlockColumns | BlobData::PayloadColumns => {
                context.sampled.iter().map(|column| column.0).collect()
            }
        }
    }

    /// Checks that every envelope reveals the payload its block's bid committed to.
    fn check_envelopes(
        &self,
        roots: &[Root],
    ) -> Result<Vec<SignedExecutionPayloadEnvelope<P>>, SegmentError> {
        for envelope in &self.envelopes {
            let root = envelope.message.beacon_block_root;
            let bid = roots
                .iter()
                .position(|candidate| *candidate == root)
                .and_then(|position| match &self.blocks[position] {
                    combined::SignedBeaconBlock::Gloas(signed) => {
                        Some(&signed.message.body.signed_execution_payload_bid.message)
                    }
                    _ => None,
                })
                .ok_or(SegmentError::StrayEnvelope(root))?;
            // The bid commits to the payload's hash, which commits to the whole payload.
            if envelope.message.payload.block_hash != bid.block_hash {
                return Err(SegmentError::StrayEnvelope(root));
            }
        }
        Ok(self.envelopes.clone())
    }

    /// Whether a block is the genesis block, which has no parent and no proposer signature.
    fn is_genesis(block: &combined::SignedBeaconBlock<P>) -> bool {
        block.slot() == Slot(0) && block.parent_root() == Root::ZERO
    }
}

/// What checking a segment needs besides the segment.
#[derive(Clone, Copy, Debug)]
pub struct SegmentContext<'a> {
    /// The fork schedule, for each block's signature domain.
    pub config: &'a ChainConfig,
    /// The root that binds signatures to this chain.
    pub genesis_validators_root: Root,
    /// Keys of every proposer the segment names.
    pub keys: &'a ProposerKeys,
    /// The columns this node samples, and so stores.
    pub sampled: &'a [ColumnIndex],
    /// Whether the segment is within the window its blob data is kept for.
    pub retained: bool,
}

/// A segment that links to the stored chain, ready to store.
///
/// Only verification makes one, so storage never takes unchecked blocks.
#[derive(Debug)]
pub struct VerifiedSegment<P: Preset> {
    /// The start the segment was checked against.
    pub(crate) extends: HistoryStart,
    /// The start once the segment is stored.
    pub(crate) start: HistoryStart,
    /// Blocks with their roots, oldest first.
    pub(crate) blocks: Vec<(Root, combined::SignedBeaconBlock<P>)>,
    /// Sidecars by block root.
    pub(crate) sidecars: Vec<(Root, Sidecar<P>)>,
    /// Payload envelopes.
    pub(crate) envelopes: Vec<SignedExecutionPayloadEnvelope<P>>,
}

impl<P: Preset> VerifiedSegment<P> {
    /// Where the stored chain begins once the segment is stored.
    #[must_use]
    pub const fn start(&self) -> HistoryStart {
        self.start
    }

    /// Blocks in the segment.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether the segment holds no block.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// Why a fetched segment cannot extend the stored chain.
#[derive(Debug, Error)]
pub enum SegmentError {
    /// A block is not older than the stored start.
    #[error("block at slot {slot} is not before the stored start at slot {start}")]
    NotBeforeStart {
        /// The block's slot.
        slot: Slot,
        /// The start's slot.
        start: Slot,
    },
    /// Blocks are not in strictly increasing slot order.
    #[error("block at slot {slot} is not before the next one at slot {next}")]
    Unordered {
        /// The block's slot.
        slot: Slot,
        /// The next block's slot.
        next: Slot,
    },
    /// A block is not the parent its child names.
    #[error("block at slot {slot} has root {root}, but its child names parent {expected}")]
    BrokenLink {
        /// The block's slot.
        slot: Slot,
        /// The block's root.
        root: Root,
        /// The parent root the child names.
        expected: Root,
    },
    /// A block names a proposer whose key was not supplied.
    #[error("block at slot {slot} names proposer {index}, whose key is unknown")]
    UnknownProposer {
        /// The block's slot.
        slot: Slot,
        /// The proposer index.
        index: ValidatorIndex,
    },
    /// A proposer signature is malformed or does not verify.
    #[error("proposer signatures: {0}")]
    Signature(#[source] BlockError),
    /// A sidecar names no block of the segment, an index its block lacks, or comes twice.
    #[error("sidecar {index} of block {root} does not belong to the segment")]
    StraySidecar {
        /// The block root the sidecar names.
        root: Root,
        /// Its blob or column index.
        index: u64,
    },
    /// A block within the retention window lacks a sidecar its data needs.
    #[error("block at slot {slot} lacks sidecar {index}")]
    MissingSidecar {
        /// The block's slot.
        slot: Slot,
        /// The missing blob or column index.
        index: u64,
    },
    /// An envelope names no Gloas block of the segment, or another payload than its bid.
    #[error("payload envelope of block {0} does not match a bid of the segment")]
    StrayEnvelope(Root),
}
