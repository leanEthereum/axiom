//! The chain: the fork choice store, its database, and the head it selects.

mod database;
mod handle;
mod head;

use std::collections::HashSet;

use axiom_fork_choice::{DataAvailability, ExecutionStatus, PayloadStatus, Store};
use axiom_ssz::Ssz;
use axiom_state_transition::{State, Verification};
use axiom_types::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconBlockBody, BeaconState, BlsSignature,
    ChainConfig, Checkpoint, Hash32, Preset, Root, SignedBeaconBlock, Slot,
};
pub use database::ChainDatabase;
pub use handle::{ChainHandle, ChainStopped};
pub use head::{ChainEvent, ExecutionHead, Head};
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::ChainError;

/// How many chain events a slow subscriber may fall behind before it starts losing them.
const EVENT_BACKLOG: usize = 256;

/// The node's view of the beacon chain.
///
/// # Overview
///
/// The fork choice store holds every block since finality and picks the head.
/// The database keeps blocks for good and an anchor state to resume from.
///
/// ```text
///     block ──> fork choice store ──> head ──> events: head, reorg, finalized
///                     │
///                     └── finality ──> database: anchor state, canonical index, orphans
/// ```
///
/// Every method is synchronous and runs on one thread.
/// Other services reach it through a handle.
#[derive(Debug)]
pub struct Chain<P: Preset> {
    /// The fork choice store.
    store: Store<P>,
    /// Persistent blocks and anchors.
    database: ChainDatabase<P>,
    /// The head as of the last head update.
    head: Head,
    /// Subscribers to head, reorg, and finality changes.
    events: broadcast::Sender<ChainEvent>,
}

impl<P: Preset> Chain<P> {
    /// A chain starting from a genesis state.
    ///
    /// The genesis block is implied by the state: an empty body committing to it.
    /// See `get_forkchoice_store` in the phase0 fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when the anchor cannot be recorded.
    pub fn from_genesis(
        config: ChainConfig,
        genesis: BeaconState<P>,
        database: ChainDatabase<P>,
    ) -> Result<Self, ChainError> {
        // The genesis header already names the body; only its state root is left blank.
        let header = &genesis.latest_block_header;
        let block = BeaconBlock {
            slot: header.slot,
            proposer_index: header.proposer_index,
            parent_root: header.parent_root,
            state_root: genesis.hash_tree_root(),
            body: BeaconBlockBody::default(),
        };
        Self::from_anchor(config, genesis, block, database)
    }

    /// A chain starting from a trusted block and its post-state, as a checkpoint sync does.
    ///
    /// The anchor is recorded as finalized, so a restart resumes from it.
    ///
    /// # Errors
    ///
    /// Fails when the block does not commit to the state, or the anchor cannot be recorded.
    pub fn from_anchor(
        config: ChainConfig,
        state: BeaconState<P>,
        block: BeaconBlock<P>,
        database: ChainDatabase<P>,
    ) -> Result<Self, ChainError> {
        let root = block.hash_tree_root();
        let checkpoint = Checkpoint {
            epoch: state.current_epoch(),
            root,
        };
        let slot = block.slot;
        // The anchor's signature is never checked, since the anchor is trusted.
        let signed = SignedBeaconBlock {
            message: block,
            signature: BlsSignature::default(),
        };
        let chain = Self::with_anchor(config, state, &signed.message, database)?;
        chain.database.put_block(root, &signed)?;
        let anchor_state = chain
            .store
            .block_state(&root)
            .ok_or(ChainError::MissingState(root))?
            .beacon();
        chain
            .database
            .finalize(checkpoint, anchor_state, &[(slot, root)], &[])?;
        Ok(chain)
    }

    /// The chain a database was left with, resuming from its finalized anchor.
    ///
    /// # Returns
    ///
    /// Nothing when the database is empty.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable or inconsistent.
    pub fn resume(
        config: ChainConfig,
        database: ChainDatabase<P>,
    ) -> Result<Option<Self>, ChainError> {
        let Some((checkpoint, state)) = database.finalized()? else {
            return Ok(None);
        };
        let block = database
            .block(checkpoint.root)?
            .ok_or(ChainError::Missing("finalized block"))?;
        Self::with_anchor(config, state, &block.message, database).map(Some)
    }

    /// Builds the store over an anchor and selects the first head.
    fn with_anchor(
        config: ChainConfig,
        state: BeaconState<P>,
        block: &BeaconBlock<P>,
        database: ChainDatabase<P>,
    ) -> Result<Self, ChainError> {
        let mut store = Store::new(config, state, block)?;
        let head = Self::read_head(&mut store)?;
        info!(slot = %head.slot, root = %head.root, "chain anchored");
        Ok(Self {
            store,
            database,
            head,
            events: broadcast::channel(EVENT_BACKLOG).0,
        })
    }

    /// A receiver of every future chain event.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<ChainEvent> {
        self.events.subscribe()
    }

    /// The head as of the latest input.
    #[must_use]
    pub const fn head(&self) -> Head {
        self.head
    }

    /// The fork choice store, for queries.
    #[must_use]
    pub const fn store(&self) -> &Store<P> {
        &self.store
    }

    /// The chain configuration.
    #[must_use]
    pub const fn config(&self) -> &ChainConfig {
        self.store.config()
    }

    /// The database, for queries.
    #[must_use]
    pub const fn database(&self) -> &ChainDatabase<P> {
        &self.database
    }

    /// Post-state of a block the fork choice still holds.
    #[must_use]
    pub fn state(&self, root: &Root) -> Option<&State<P>> {
        self.store.block_state(root)
    }

    /// A block by root, from the database.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub fn block(&self, root: Root) -> Result<Option<SignedBeaconBlock<P>>, ChainError> {
        self.database.block(root)
    }

    /// Root of the canonical block proposed at a slot, if any.
    ///
    /// Since finality the head's chain decides; before it, the finalized index does.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub fn canonical_root(&self, slot: Slot) -> Result<Option<Root>, ChainError> {
        if slot > self.head.slot {
            return Ok(None);
        }
        let finalized_slot = self
            .store
            .blocks()
            .get(&self.head.finalized.root)
            .map(|node| node.slot);
        if finalized_slot.is_some_and(|finalized| slot >= finalized) {
            // The ancestor at a slot may be an earlier block when the slot was empty.
            let blocks = self.store.blocks();
            return Ok(blocks
                .ancestor(self.head.root, slot)
                .filter(|root| blocks.get(root).is_some_and(|node| node.slot == slot)));
        }
        self.database.canonical_root(slot)
    }

    /// Advances the fork choice clock.
    ///
    /// # Errors
    ///
    /// Fails when the head cannot be recomputed.
    pub fn on_tick(&mut self, time_ms: u64) -> Result<(), ChainError> {
        self.store.on_tick(time_ms);
        // A new slot clears the proposer boost, which can move the head.
        self.update_head()
    }

    /// Imports a block whose payload verdict and data availability are known.
    ///
    /// # Returns
    ///
    /// The block's root.
    ///
    /// # Errors
    ///
    /// Fails when the fork choice refuses the block or it cannot be stored.
    pub fn import_block(
        &mut self,
        block: &SignedBeaconBlock<P>,
        availability: DataAvailability,
        payload: PayloadStatus,
    ) -> Result<Root, ChainError> {
        let root = block.message.hash_tree_root();
        self.store
            .import_block(block, availability, Verification::Verify, payload)?;
        // Store before announcing, so any reader told of the block can fetch it.
        self.database.put_block(root, block)?;
        info!(slot = %block.message.slot, %root, "imported block");
        self.update_head()?;
        Ok(root)
    }

    /// Counts a vote received on its own, outside any block.
    ///
    /// The head is not recomputed: votes arrive by the thousand each slot.
    /// The next tick or block, or an explicit update, picks up their weight.
    ///
    /// # Errors
    ///
    /// Fails when the fork choice refuses the vote.
    pub fn on_attestation(&mut self, attestation: &Attestation<P>) -> Result<(), ChainError> {
        self.store
            .on_attestation(attestation, false, Verification::Verify)?;
        Ok(())
    }

    /// Removes the weight of validators an attester slashing proves to have equivocated.
    ///
    /// # Errors
    ///
    /// Fails when the slashing does not prove an equivocation.
    pub fn on_attester_slashing(
        &mut self,
        slashing: &AttesterSlashing<P>,
    ) -> Result<(), ChainError> {
        self.store
            .on_attester_slashing(slashing, Verification::Verify)?;
        Ok(())
    }

    /// Applies the engine's later verdict on a block imported optimistically.
    ///
    /// # Errors
    ///
    /// Fails when the head cannot be recomputed.
    pub fn on_payload_verdict(
        &mut self,
        root: Root,
        verdict: PayloadStatus,
    ) -> Result<(), ChainError> {
        match verdict {
            PayloadStatus::Valid => self.store.on_valid_payload(root),
            PayloadStatus::Invalid { latest_valid_hash } => {
                warn!(%root, "engine found an invalid payload");
                self.store.invalidate_after(root, latest_valid_hash);
            }
            PayloadStatus::NotValidated => return Ok(()),
        }
        // Invalid blocks leave the viable set, which can move the head.
        self.update_head()
    }

    /// Recomputes the head and announces what changed.
    ///
    /// # Errors
    ///
    /// Fails when the fork choice has no state for its justified checkpoint or head.
    pub fn update_head(&mut self) -> Result<(), ChainError> {
        let previous = self.head;
        let head = Self::read_head(&mut self.store)?;
        if head == previous {
            return Ok(());
        }
        self.head = head;

        // A head off the previous head's chain is a reorg.
        if head.root != previous.root && !self.store.blocks().is_ancestor(head.root, previous.root)
        {
            let depth = self.reorg_depth(previous, head);
            warn!(from = %previous.root, to = %head.root, depth, "chain reorganized");
            self.announce(ChainEvent::Reorg {
                from: previous.root,
                to: head.root,
                depth,
            });
        }
        if head.root != previous.root {
            info!(slot = %head.slot, root = %head.root, optimistic = head.optimistic, "new head");
        }
        self.announce(ChainEvent::Head(head));

        if head.finalized.epoch > previous.finalized.epoch {
            self.finalize(previous.finalized, head.finalized)?;
            info!(epoch = %head.finalized.epoch, root = %head.finalized.root, "finalized");
            self.announce(ChainEvent::Finalized(head.finalized));
        }
        Ok(())
    }

    /// Persists a new finality and forgets what it excluded.
    fn finalize(&mut self, previous: Checkpoint, finalized: Checkpoint) -> Result<(), ChainError> {
        // Walk back from the new finalized block to the old one: the newly finalized chain.
        let blocks = self.store.blocks();
        let mut chain = Vec::new();
        let mut current = finalized.root;
        while current != previous.root {
            let Some(node) = blocks.get(&current) else {
                break;
            };
            chain.push((node.slot, current));
            current = node.parent_root;
        }
        let canonical: HashSet<Root> = chain.iter().map(|(_, root)| *root).collect();

        // The anchor state must be read before pruning reshapes the store.
        let state = self
            .store
            .block_state(&finalized.root)
            .ok_or(ChainError::MissingState(finalized.root))?
            .beacon()
            .clone();

        // Everything dropped that is not on the finalized chain is an orphaned fork.
        let orphans: Vec<Root> = self
            .store
            .prune()
            .into_iter()
            .filter(|root| !canonical.contains(root) && *root != previous.root)
            .collect();
        self.database.finalize(finalized, &state, &chain, &orphans)
    }

    /// Blocks on the old head's chain after the common ancestor with the new head.
    fn reorg_depth(&self, from: Head, to: Head) -> u64 {
        let blocks = self.store.blocks();
        let mut depth = 0;
        let mut current = from.root;
        while let Some(node) = blocks.get(&current) {
            if blocks.is_ancestor(to.root, current) {
                break;
            }
            depth += 1;
            current = node.parent_root;
        }
        depth
    }

    /// Reads the head and its checkpoints from the store.
    fn read_head(store: &mut Store<P>) -> Result<Head, ChainError> {
        let root = store.head()?;
        let node = *store
            .blocks()
            .get(&root)
            .ok_or(ChainError::MissingState(root))?;
        let state = store
            .block_state(&root)
            .ok_or(ChainError::MissingState(root))?;
        let justified = store.justified_checkpoint();
        let finalized = store.finalized_checkpoint();

        // A block's post-state caches the header of its own payload.
        let payload_hash = |root: &Root| -> Hash32 {
            store.block_state(root).map_or(Hash32::ZERO, |state| {
                state.beacon().latest_execution_payload_header.block_hash
            })
        };
        Ok(Head {
            root,
            slot: node.slot,
            optimistic: node.status != ExecutionStatus::Valid,
            justified,
            finalized,
            execution: ExecutionHead {
                head: state.beacon().latest_execution_payload_header.block_hash,
                safe: payload_hash(&justified.root),
                finalized: payload_hash(&finalized.root),
            },
        })
    }

    /// Sends an event to every subscriber.
    fn announce(&self, event: ChainEvent) {
        // Having no subscriber is normal, so a failed send is not an error.
        let _unheard = self.events.send(event);
    }
}
