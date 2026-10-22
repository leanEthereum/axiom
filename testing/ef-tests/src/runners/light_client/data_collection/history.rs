//! The simplified chain a data collection case builds: blocks, states, and finality.

use std::collections::HashMap;

use axiom_light_client::{Header, combined::LightClientHeader};
use axiom_ssz::{Root, Ssz};
use axiom_state_transition::State;
use axiom_types::{
    Epoch, Preset, Slot,
    altair::{self, SyncAggregate},
    bellatrix, capella,
    combined::{BeaconState, SignedBeaconBlock},
    deneb, electra, gloas, phase0,
};

use crate::Failure;

/// A block by slot and root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct BlockId {
    /// The block's slot.
    pub(super) slot: Slot,
    /// The block's root.
    pub(super) root: Root,
}

impl BlockId {
    /// The block a state is the post-state of: its latest header, with the state root filled in.
    pub(super) fn of_state<P: Preset>(state: &State<P>) -> Self {
        let mut header = state.beacon().as_core().latest_block_header().clone();
        header.state_root = state.hash_tree_root();
        Self {
            slot: header.slot,
            root: header.hash_tree_root(),
        }
    }
}

/// What the case keeps of a block: its place in the tree, and its light client data.
#[derive(Clone, Debug)]
pub(super) struct BlockRecord<P: Preset> {
    /// The block's slot and root.
    pub(super) id: BlockId,
    /// Root of the parent block.
    pub(super) parent_root: Root,
    /// Root of the post-state.
    pub(super) state_root: Root,
    /// The block's light client header, in the format of its fork.
    pub(super) header: LightClientHeader<P>,
    /// The sync committee signature the block carries, from Altair on.
    pub(super) sync_aggregate: Option<SyncAggregate<P>>,
}

impl<P: Preset> BlockRecord<P> {
    /// The record of a block.
    pub(super) fn of(block: &SignedBeaconBlock<P>) -> Self {
        let header = LightClientHeader::of_block(block);
        Self {
            id: BlockId {
                slot: block.slot(),
                root: block.block_root(),
            },
            parent_root: block.parent_root(),
            state_root: Header::<P>::beacon(&header).state_root,
            header,
            sync_aggregate: block.sync_aggregate().cloned(),
        }
    }

    /// The block the vectors' generator builds for a state it starts from.
    ///
    /// It has an empty body, and the default slot, proposer, and parent.
    /// A Gloas body names the state's latest bid, as the generator's genesis block does.
    pub(super) fn genesis(state: &State<P>) -> Self {
        let state_root = state.hash_tree_root();
        let block = match state.beacon() {
            BeaconState::Phase0(_) => SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
                message: phase0::BeaconBlock {
                    state_root,
                    ..phase0::BeaconBlock::default()
                },
                ..phase0::SignedBeaconBlock::default()
            }),
            BeaconState::Altair(_) => SignedBeaconBlock::Altair(altair::SignedBeaconBlock {
                message: altair::BeaconBlock {
                    state_root,
                    ..altair::BeaconBlock::default()
                },
                ..altair::SignedBeaconBlock::default()
            }),
            BeaconState::Bellatrix(_) => {
                SignedBeaconBlock::Bellatrix(bellatrix::SignedBeaconBlock {
                    message: bellatrix::BeaconBlock {
                        state_root,
                        ..bellatrix::BeaconBlock::default()
                    },
                    ..bellatrix::SignedBeaconBlock::default()
                })
            }
            BeaconState::Capella(_) => SignedBeaconBlock::Capella(capella::SignedBeaconBlock {
                message: capella::BeaconBlock {
                    state_root,
                    ..capella::BeaconBlock::default()
                },
                ..capella::SignedBeaconBlock::default()
            }),
            BeaconState::Deneb(_) => SignedBeaconBlock::Deneb(deneb::SignedBeaconBlock {
                message: deneb::BeaconBlock {
                    state_root,
                    ..deneb::BeaconBlock::default()
                },
                ..deneb::SignedBeaconBlock::default()
            }),
            BeaconState::Electra(_) => SignedBeaconBlock::Electra(electra::SignedBeaconBlock {
                message: electra::BeaconBlock {
                    state_root,
                    ..electra::BeaconBlock::default()
                },
                ..electra::SignedBeaconBlock::default()
            }),
            BeaconState::Fulu(_) => SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
                message: electra::BeaconBlock {
                    state_root,
                    ..electra::BeaconBlock::default()
                },
                ..electra::SignedBeaconBlock::default()
            }),
            BeaconState::Gloas(beacon) => {
                let mut body = gloas::BeaconBlockBody::default();
                body.signed_execution_payload_bid.message =
                    beacon.latest_execution_payload_bid.clone();
                SignedBeaconBlock::Gloas(gloas::SignedBeaconBlock {
                    message: gloas::BeaconBlock {
                        state_root,
                        body,
                        ..gloas::BeaconBlock::default()
                    },
                    ..gloas::SignedBeaconBlock::default()
                })
            }
        };
        Self::of(&block)
    }
}

/// The blocks and states a case has seen, and what it has finalized.
///
/// See `LightClientDataCollectionTest` in the spec's light client data collection helpers.
#[derive(Debug)]
pub(super) struct History<P: Preset> {
    /// Blocks by root, pruned below the finalized slot.
    pub(super) blocks: HashMap<Root, BlockRecord<P>>,
    /// Post-states by block root, kept for building on any block.
    pub(super) post_states: HashMap<Root, State<P>>,
    /// Shared state cells, which the maps below point into.
    ///
    /// The generator's maps share state objects, and advancing one changes it in every map.
    /// Its checks record that sharing, so the cells reproduce it.
    pub(super) cells: Vec<State<P>>,
    /// Post-states by state root, as cells.
    pub(super) states: HashMap<Root, usize>,
    /// Finalized block roots by slot.
    pub(super) finalized_block_roots: HashMap<Slot, Root>,
    /// Post-states of finalized epoch boundary blocks by state root, as cells, in insertion order.
    pub(super) finalized_checkpoint_states: Vec<(Root, usize)>,
    /// The latest finalized epoch.
    pub(super) latest_finalized_epoch: Epoch,
    /// The latest finalized block.
    pub(super) latest_finalized: BlockId,
    /// The earliest slot the case has a state for.
    pub(super) tail_slot: Slot,
}

impl<P: Preset> History<P> {
    /// The ancestor of a block at or before a slot, while the blocks on the way are known.
    ///
    /// See `get_ancestor_of_block_id` in the spec's light client data collection helpers.
    pub(super) fn ancestor(&self, id: BlockId, slot: Slot) -> Option<BlockId> {
        let mut block = self.blocks.get(&id.root)?;
        loop {
            if block.id.slot <= slot {
                return Some(block.id);
            }
            block = self.blocks.get(&block.parent_root)?;
        }
    }

    /// The finalized block at a slot, or the last one before it.
    pub(super) fn finalized_at(&self, mut slot: Slot) -> Option<BlockId> {
        while slot >= self.tail_slot {
            if let Some(root) = self.finalized_block_roots.get(&slot) {
                return Some(BlockId { slot, root: *root });
            }
            if slot == Slot::GENESIS {
                return None;
            }
            slot = slot - 1;
        }
        None
    }

    /// A known block.
    pub(super) fn block(&self, root: &Root) -> Result<&BlockRecord<P>, Failure> {
        self.blocks
            .get(root)
            .ok_or_else(|| Failure(format!("block {root} is unknown")))
    }

    /// The cell of a known post-state, by state root.
    pub(super) fn state_cell(&self, root: &Root) -> Result<usize, Failure> {
        self.states
            .get(root)
            .copied()
            .ok_or_else(|| Failure(format!("state {root} is unknown")))
    }

    /// A new cell holding a state.
    pub(super) fn new_cell(&mut self, state: State<P>) -> usize {
        self.cells.push(state);
        self.cells.len() - 1
    }

    /// Records the cell of a finalized epoch boundary block's post-state, keeping first-seen order.
    pub(super) fn keep_checkpoint_state(&mut self, root: Root, cell: usize) {
        if let Some(entry) = self
            .finalized_checkpoint_states
            .iter_mut()
            .find(|(known, _)| *known == root)
        {
            entry.1 = cell;
        } else {
            self.finalized_checkpoint_states.push((root, cell));
        }
    }

    /// The cell of a finalized checkpoint state, by state root.
    pub(super) fn checkpoint_cell(&self, root: &Root) -> Result<usize, Failure> {
        self.finalized_checkpoint_states
            .iter()
            .find(|(known, _)| known == root)
            .map(|(_, cell)| *cell)
            .ok_or_else(|| Failure(format!("no finalized checkpoint state {root}")))
    }
}
