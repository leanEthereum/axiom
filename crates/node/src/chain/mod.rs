//! The chain: the fork choice store, its database, and the head it selects.

mod availability;
mod database;
mod gossip;
mod handle;
mod head;

use std::{
    collections::{BTreeSet, HashSet},
    sync::Arc,
};

pub(crate) use availability::Sidecar;
pub use availability::Submission;
use availability::{AvailabilityBuffer, Needed, Pending, ReadyBlock, ReadyEnvelope};
use axiom_fork_choice::{DataAvailability, ExecutionStatus, ForkChoiceError, PayloadStatus, Store};
use axiom_gossip::{ChainView, GossipValidator, SubnetVote};
use axiom_light_client::{LightClientServer, PostState, combined::LightClientUpdate};
use axiom_state_transition::{EpochCommittees, State, Verification};
use axiom_telemetry::NodeMetrics;
use axiom_types::{
    BlobData, BlsSignature, ChainConfig, ColumnIndex, Epoch, ForkDigest, Hash32, Preset, Root,
    Slot,
    accessors::{CoreState, ForkState},
    bellatrix::PowBlock,
    combined,
    deneb::BlobSidecar,
    gloas::{self, PayloadAttestationMessage, SignedExecutionPayloadEnvelope},
    phase0::Checkpoint,
    vote::{CommitteeVote, ConflictingVotes, PayloadClaim},
};
pub use database::ChainDatabase;
use gossip::GossipMemory;
pub use handle::{ChainHandle, ChainStopped};
pub use head::{ChainEvent, ExecutionHead, Head};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::ChainError;

/// How many chain events a slow subscriber may fall behind before it starts losing them.
const EVENT_BACKLOG: usize = 256;

/// Sync committee periods of light client data kept behind finality.
///
/// A bootstrap embeds a whole sync committee, and one is kept per finalized epoch.
/// Two periods keep a day or more of bootstraps and updates on mainnet in a few megabytes.
/// The full node spec asks for more, back to the oldest block served; this node keeps less.
const LIGHT_CLIENT_PERIODS_KEPT: u64 = 2;

/// The node's view of the beacon chain.
///
/// # Overview
///
/// The fork choice store holds every block since finality and picks the head.
/// The database keeps blocks for good and an anchor state to resume from.
///
/// 1. A block enters the fork choice store.
/// 2. The store picks the head, which emits head, reorg, and finalized events.
/// 3. On finality, the database stores the anchor state and the canonical index, and drops orphans.
///
/// Blocks of every fork enter through the combined enums.
/// From Gloas on, a block's payload arrives apart, in an envelope that enters on its own.
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
    /// Gauges, counters, and timings the node exports.
    metrics: NodeMetrics,
    /// Database bytes written as of the last metrics update.
    bytes_written: u64,
    /// Blocks and envelopes waiting for their blob data.
    availability: AvailabilityBuffer<P>,
    /// What gossip validation remembers.
    gossip: GossipMemory,
    /// Committees of one epoch as the head state shuffles them, reused until the head moves.
    committees: Option<(Epoch, Root, Arc<EpochCommittees>)>,
    /// Light client data derived from the canonical chain.
    light_client: LightClientServer<P>,
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
        genesis: combined::BeaconState<P>,
        database: ChainDatabase<P>,
    ) -> Result<Self, ChainError> {
        // Genesis has no proposer, so its block carries no signature.
        let block = combined::SignedBeaconBlock::from_parts(
            combined::BeaconBlock::genesis(&genesis),
            BlsSignature::default(),
        );
        Self::from_anchor(config, genesis, &block, database)
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
        state: combined::BeaconState<P>,
        signed: &combined::SignedBeaconBlock<P>,
        database: ChainDatabase<P>,
    ) -> Result<Self, ChainError> {
        let root = signed.block_root();
        let checkpoint = Checkpoint {
            epoch: state.current_epoch(),
            root,
        };
        let slot = signed.slot();
        // The anchor is trusted, so its signature is kept as given and never checked.
        let mut chain = Self::with_anchor(config, state, &signed.message(), database)?;
        chain.database.put_block(root, signed)?;
        chain.offer_bootstrap(root, signed);
        let anchor_state = chain
            .store
            .block_state(&root)
            .ok_or(ChainError::MissingState(root))?
            .beacon();
        chain
            .database
            .finalize(checkpoint, checkpoint, anchor_state, &[(slot, root)], &[])?;
        Ok(chain)
    }

    /// The chain a database was left with, resuming from its finalized anchor.
    ///
    /// Blocks after the anchor are not replayed; the node fetches them again from peers.
    ///
    /// # Errors
    ///
    /// Fails when the database holds no anchor, or is unreadable or inconsistent.
    pub fn resume(config: ChainConfig, database: ChainDatabase<P>) -> Result<Self, ChainError> {
        let (checkpoint, state) = database
            .finalized()?
            .ok_or(ChainError::Missing("finalized checkpoint"))?;
        let block = database
            .block(checkpoint.root)?
            .ok_or(ChainError::Missing("finalized block"))?;
        Self::with_anchor(config, state, &block.message(), database)
    }

    /// Builds the store over an anchor and selects the first head.
    fn with_anchor(
        config: ChainConfig,
        state: combined::BeaconState<P>,
        anchor: &combined::BeaconBlock<P>,
        database: ChainDatabase<P>,
    ) -> Result<Self, ChainError> {
        let mut store = Store::new(config, State::new(state), anchor)?;
        let head = Self::read_head(&mut store)?;
        info!(slot = %head.slot, root = %head.root, fork = %anchor.fork_name(), "chain anchored");
        Ok(Self {
            store,
            database,
            head,
            events: broadcast::channel(EVENT_BACKLOG).0,
            metrics: NodeMetrics::detached(),
            bytes_written: 0,
            // Until told otherwise, sample every column: the strictest availability rule.
            availability: AvailabilityBuffer::new((0..P::NUMBER_OF_COLUMNS).map(ColumnIndex)),
            gossip: GossipMemory::default(),
            committees: None,
            light_client: LightClientServer::new(),
        })
    }

    /// Samples only the given columns, as this node's custody assigns.
    ///
    /// See `get_custody_groups` and `compute_columns_for_custody_group` in the Fulu DAS spec.
    #[must_use]
    pub fn with_custody(mut self, columns: impl IntoIterator<Item = ColumnIndex>) -> Self {
        self.availability = AvailabilityBuffer::new(columns);
        self
    }

    /// Records into the node's exported metrics instead of a private set.
    #[must_use]
    pub fn with_metrics(mut self, metrics: NodeMetrics) -> Self {
        self.metrics = metrics;
        // Publish the anchor's head at once rather than at the first change.
        self.record_head(self.head, true);
        self
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

    /// The light client data the chain serves.
    #[must_use]
    pub const fn light_client(&self) -> &LightClientServer<P> {
        &self.light_client
    }

    /// The light client data the chain serves, for recording what gossip forwarded.
    pub const fn light_client_mut(&mut self) -> &mut LightClientServer<P> {
        &mut self.light_client
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
    pub fn block(&self, root: Root) -> Result<Option<combined::SignedBeaconBlock<P>>, ChainError> {
        self.database.block(root)
    }

    /// The bid a Gloas block committed to, while the fork choice holds the block's state.
    #[must_use]
    pub fn payload_bid(&self, root: &Root) -> Option<gloas::ExecutionPayloadBid> {
        let state = self.store.block_state(root)?;
        gloas::BeaconState::<P>::from_any(state.beacon())
            .map(|gloas| gloas.latest_execution_payload_bid.clone())
    }

    /// Slot of a block, from the fork choice when it holds the block, else from the database.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub fn block_slot(&self, root: Root) -> Result<Option<Slot>, ChainError> {
        if let Some(node) = self.store.blocks().get(&root) {
            return Ok(Some(node.slot));
        }
        Ok(self.database.block(root)?.map(|block| block.slot()))
    }

    /// The root that binds signatures and topics to this chain's genesis validator set.
    #[must_use]
    pub fn genesis_validators_root(&self) -> Root {
        // Every state carries it unchanged; the head's state is always held.
        self.store
            .block_state(&self.head.root)
            .map_or(Root::ZERO, |state| state.beacon().genesis_validators_root())
    }

    /// The digest of the fork active at an epoch, which names gossip topics and tags responses.
    #[must_use]
    pub fn fork_digest(&self, epoch: Epoch) -> ForkDigest {
        self.config()
            .fork_digest(self.genesis_validators_root(), epoch)
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
        let epoch = self.store.current_epoch();
        self.store.on_tick(time_ms);
        if self.store.current_epoch() != epoch {
            // Messages from two epochs ago can no longer be gossiped, so forget them.
            self.gossip.seen.prune::<P>(self.store.current_epoch());
        }
        self.metrics
            .clock_slot
            .set_count(self.store.current_slot().0);
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
        block: &combined::SignedBeaconBlock<P>,
        availability: DataAvailability,
        payload: PayloadStatus,
    ) -> Result<Root, ChainError> {
        let root = block.block_root();
        let timer = self.metrics.block_import_seconds.start_timer();
        if let Err(error) =
            self.store
                .import_block(block, availability, Verification::Verify, payload)
        {
            // Refused blocks fail early, so timing them would skew the import latency.
            timer.discard();
            return Err(error.into());
        }
        drop(timer);
        // Store before announcing, so any reader told of the block can fetch it.
        self.database.put_block(root, block)?;
        info!(slot = %block.slot(), fork = %block.fork_name(), %root, "imported block");
        self.update_head()?;
        // Only canonical blocks feed light clients; a block that is not the head may never be.
        if self.head.root == root {
            self.offer_update(root, block);
        }
        Ok(root)
    }

    /// Imports a payload envelope whose verdict and data availability are known.
    ///
    /// The block's full variant then joins the tree, and children may build on it.
    ///
    /// # Errors
    ///
    /// Fails when the fork choice refuses the envelope or it cannot be stored.
    pub fn import_envelope(
        &mut self,
        envelope: &SignedExecutionPayloadEnvelope<P>,
        availability: DataAvailability,
        payload: PayloadStatus,
    ) -> Result<Root, ChainError> {
        let root = envelope.message.beacon_block_root;
        self.store.on_execution_payload_envelope(
            envelope,
            availability,
            Verification::Verify,
            payload,
        )?;
        self.database.put_envelope(envelope)?;
        info!(%root, "imported payload envelope");
        self.update_head()?;
        Ok(root)
    }

    /// Hands over a block that passed gossip or sync checks, with its payload verdict.
    ///
    /// The block imports now if its data is complete, or later when the last sidecar arrives.
    ///
    /// # Errors
    ///
    /// Fails when the block is imported now and the fork choice refuses it.
    pub fn submit_block(
        &mut self,
        block: Arc<combined::SignedBeaconBlock<P>>,
        payload: PayloadStatus,
    ) -> Result<Submission, ChainError> {
        let root = block.block_root();
        if self.store.blocks().contains(&root) {
            return Ok(Submission::Imported(root));
        }
        let data = block.fork_name().blob_data();
        let commitments = block.message().blob_kzg_commitments().len() as u64;
        let needed = match data {
            BlobData::BlobSidecars if commitments > 0 => Needed::Blobs(commitments),
            BlobData::BlockColumns if commitments > 0 => Needed::Custody,
            // Gloas blocks commit through their bid; the envelope waits instead.
            BlobData::None
            | BlobData::BlobSidecars
            | BlobData::BlockColumns
            | BlobData::PayloadColumns => Needed::Nothing,
        };
        let needed = self.within_retention(block.slot(), data, needed);
        let item = Pending::Block(ReadyBlock { block, payload });
        match self.availability.offer(root, item, needed) {
            Some(ready) => self
                .import_ready(root, ready)
                .map(|()| Submission::Imported(root)),
            None => Ok(Submission::Waiting(root)),
        }
    }

    /// Hands over a payload envelope that passed gossip or sync checks, with its verdict.
    ///
    /// The envelope imports now if its block's blob data is complete, or later.
    ///
    /// # Errors
    ///
    /// Fails when the envelope's block is unknown, or the envelope is imported now and refused.
    pub fn submit_envelope(
        &mut self,
        envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
        payload: PayloadStatus,
    ) -> Result<Submission, ChainError> {
        let root = envelope.message.beacon_block_root;
        let state = self
            .store
            .block_state(&root)
            .ok_or(ForkChoiceError::UnknownBlock(root))?;
        let slot = state.beacon().slot();
        // Only a Gloas block's state holds a bid; any other block has no envelope at all.
        let commitments = gloas::BeaconState::<P>::from_any(state.beacon())
            .map(|gloas| {
                gloas
                    .latest_execution_payload_bid
                    .blob_kzg_commitments
                    .len()
            })
            .ok_or(ForkChoiceError::NoPayloadCommittee(root))?;
        let needed = if commitments > 0 {
            Needed::Custody
        } else {
            Needed::Nothing
        };
        let needed = self.within_retention(slot, BlobData::PayloadColumns, needed);
        let item = Pending::Envelope(ReadyEnvelope { envelope, payload });
        match self.availability.offer(root, item, needed) {
            Some(ready) => self
                .import_ready(root, ready)
                .map(|()| Submission::Imported(root)),
            None => Ok(Submission::Waiting(root)),
        }
    }

    /// Hands over a verified custody column, which may complete a waiting block or envelope.
    ///
    /// # Returns
    ///
    /// The root of the block the column released and imported, if any.
    ///
    /// # Errors
    ///
    /// Fails when a released item is refused by the fork choice.
    pub fn submit_column(
        &mut self,
        column: Arc<combined::DataColumnSidecar<P>>,
    ) -> Result<Option<Root>, ChainError> {
        self.submit_sidecar(Sidecar::Column(column))
    }

    /// Hands over a verified blob sidecar, which may complete a waiting block.
    ///
    /// # Returns
    ///
    /// The root of the block the blob released and imported, if any.
    ///
    /// # Errors
    ///
    /// Fails when a released block is refused by the fork choice.
    pub fn submit_blob(&mut self, blob: Arc<BlobSidecar<P>>) -> Result<Option<Root>, ChainError> {
        self.submit_sidecar(Sidecar::Blob(blob))
    }

    /// Hands over a verified sidecar of either kind.
    fn submit_sidecar(&mut self, sidecar: Sidecar<P>) -> Result<Option<Root>, ChainError> {
        let root = sidecar.block_root();
        match self.availability.offer_sidecar(sidecar) {
            Some(ready) => self.import_ready(root, ready).map(|()| Some(root)),
            None => Ok(None),
        }
    }

    /// The columns this node samples and serves.
    #[must_use]
    pub const fn custody(&self) -> &BTreeSet<ColumnIndex> {
        self.availability.custody()
    }

    /// Runs gossip validation against the chain.
    ///
    /// The validator borrows the store and the gossip memory for the duration of the check.
    pub fn validate_gossip<R>(
        &mut self,
        check: impl FnOnce(&mut GossipValidator<'_, '_, P>) -> R,
    ) -> R {
        let mut view = ChainView::new(
            &mut self.store,
            &self.gossip.unimported,
            &self.gossip.payload_statuses,
        );
        let mut validator = GossipValidator::new(&mut view, &mut self.gossip.seen);
        check(&mut validator)
    }

    /// The data requirement, waived for blocks older than peers must serve their data for.
    ///
    /// See the notes on the retention window in the Deneb and Fulu fork choice specs.
    const fn within_retention(&self, slot: Slot, data: BlobData, needed: Needed) -> Needed {
        let window = self.config().blob_retention_epochs(data);
        if slot.epoch::<P>().0.saturating_add(window) < self.store.current_epoch().0 {
            Needed::Nothing
        } else {
            needed
        }
    }

    /// Imports a block or envelope whose data is available, then stores its sidecars.
    fn import_ready(&mut self, root: Root, ready: Pending<P>) -> Result<(), ChainError> {
        let sidecars = self.availability.take_sidecars(&root);
        let imported = match &ready {
            Pending::Block(ready) => {
                self.import_block(&ready.block, DataAvailability::Available, ready.payload)
            }
            Pending::Envelope(ready) => {
                self.import_envelope(&ready.envelope, DataAvailability::Available, ready.payload)
            }
        };
        match (imported, ready) {
            (Ok(_), _) => {
                // An earlier refusal, for want of a parent or of time, no longer holds.
                self.gossip.forget(&root);
                self.database.put_sidecars(root, &sidecars)
            }
            (Err(error), Pending::Block(ready)) => {
                // Only a block that can never import condemns its descendants on gossip.
                // A missing parent or an early arrival may still resolve.
                if Self::is_permanent(&error) {
                    let invalid_payload = matches!(ready.payload, PayloadStatus::Invalid { .. });
                    self.gossip.refuse(root, &ready.block, invalid_payload);
                }
                Err(error)
            }
            (Err(error), Pending::Envelope(_)) => Err(error),
        }
    }

    /// Derives the light client update a new head signs for its parent, and keeps it if better.
    ///
    /// Updates are routine to fail: phase0 has no committee, and few signers prove nothing.
    /// So a failure is logged and never stops the import.
    /// See `create_light_client_update` in the Altair light client full node spec.
    fn offer_update(&mut self, root: Root, block: &combined::SignedBeaconBlock<P>) {
        let parent_root = block.parent_root();
        let (Some(signature_state), Some(attested_state)) = (
            self.store.block_state(&root),
            self.store.block_state(&parent_root),
        ) else {
            return;
        };
        let created = self.database.block(parent_root).and_then(|parent| {
            let parent = parent.ok_or(ChainError::MissingState(parent_root))?;
            let finalized_root = attested_state.beacon().finalized_checkpoint().root;
            let finalized_block = self.database.block(finalized_root)?;
            let signature = PostState::new(signature_state.beacon(), block)?;
            let attested = PostState::new(attested_state.beacon(), &parent)?;
            let update = LightClientUpdate::create(
                self.store.config(),
                &signature,
                &attested,
                finalized_block.as_ref(),
            )?;
            Ok(self.light_client.offer_update(update)?)
        });
        if let Err(error) = created {
            debug!(%root, %error, "no light client update from the block");
        }
    }

    /// Keeps the bootstrap of a block whose post-state the fork choice holds.
    ///
    /// See `create_light_client_bootstrap` in the Altair light client full node spec.
    fn offer_bootstrap(&mut self, root: Root, block: &combined::SignedBeaconBlock<P>) {
        let Some(state) = self.store.block_state(&root) else {
            return;
        };
        let offered = PostState::new(state.beacon(), block)
            .and_then(|post| self.light_client.offer_bootstrap(&post));
        if let Err(error) = offered {
            debug!(%root, %error, "no light client bootstrap for the block");
        }
    }

    /// Whether a block failure would recur on every retry.
    const fn is_permanent(error: &ChainError) -> bool {
        matches!(
            error,
            ChainError::ForkChoice(
                ForkChoiceError::InvalidBlock { .. }
                    | ForkChoiceError::DataUnavailable(_)
                    | ForkChoiceError::NotDescendantOfFinalized { .. }
                    | ForkChoiceError::BeforeFinalized { .. }
            )
        )
    }

    /// Start of a slot, in milliseconds since the Unix epoch.
    #[must_use]
    pub const fn slot_start_ms(&self, slot: Slot) -> u64 {
        self.store.slot_clock().slot_start_ms(slot)
    }

    /// Counts a vote received on its own, outside any block.
    ///
    /// The head is not recomputed: votes arrive by the thousand each slot.
    /// The next tick or block, or an explicit update, picks up their weight.
    ///
    /// # Errors
    ///
    /// Fails when the fork choice refuses the vote.
    pub fn on_vote(&mut self, vote: &CommitteeVote) -> Result<(), ChainError> {
        self.store
            .on_attestation(vote, false, Verification::Verify)?;
        Ok(())
    }

    /// Counts one validator's vote, received alone on an attestation subnet.
    ///
    /// The vote becomes an aggregate with one committee and one participant.
    ///
    /// # Arguments
    ///
    /// - `claim`: what the vote says about its head's payload, as its fork reads the data index.
    ///
    /// # Errors
    ///
    /// Fails when the attester is not in the committee named, or the fork choice refuses the vote.
    pub fn on_subnet_vote<V: SubnetVote>(
        &mut self,
        vote: &V,
        claim: PayloadClaim,
    ) -> Result<(), ChainError> {
        let data = vote.data();
        let committee_index = vote.committee_index();
        let invalid = |reason| ChainError::InvalidVote {
            slot: data.slot,
            committee: committee_index,
            reason,
        };
        let committees = self.committees_at(data.target.epoch)?;
        let committee = committees
            .committee(data.slot, committee_index)
            .ok_or_else(|| invalid("no such committee at the slot"))?;
        let attester = vote
            .attester(committee)
            .map_err(|_| invalid("attester not in the committee"))?;

        // One participant bit at the attester's place in its committee.
        //
        //     committee 2 of the slot: [v9, v4, v7]   attester v4   ->   bits 010
        let bits = committee.iter().map(|member| *member == attester).collect();
        let aggregate = CommitteeVote {
            data: data.clone(),
            signature: *vote.signature(),
            committees: vec![committee_index],
            bits,
            payload: claim,
        };
        // The signature is checked again against the committee the store resolves.
        // A committee from a branch with another shuffling then fails the check.
        // It never credits the wrong validator.
        self.store
            .on_attestation(&aggregate, false, Verification::Verify)?;
        Ok(())
    }

    /// Committees of an epoch as the head state shuffles them.
    ///
    /// Shuffling walks every validator, so the result is kept until the head changes.
    fn committees_at(&mut self, epoch: Epoch) -> Result<Arc<EpochCommittees>, ChainError> {
        if let Some((cached, root, committees)) = &self.committees
            && *cached == epoch
            && *root == self.head.root
        {
            return Ok(Arc::clone(committees));
        }
        let state = self
            .store
            .block_state(&self.head.root)
            .ok_or(ChainError::MissingState(self.head.root))?;
        let committees = Arc::new(EpochCommittees::compute(state.beacon(), epoch));
        self.committees = Some((epoch, self.head.root, Arc::clone(&committees)));
        Ok(committees)
    }

    /// Removes the weight of validators an attester slashing proves to have equivocated.
    ///
    /// # Errors
    ///
    /// Fails when the slashing does not prove an equivocation.
    pub fn on_attester_slashing(&mut self, votes: &ConflictingVotes) -> Result<(), ChainError> {
        self.store
            .on_attester_slashing(votes, Verification::Verify)?;
        Ok(())
    }

    /// Counts a payload timeliness committee member's vote on its slot's payload.
    ///
    /// # Errors
    ///
    /// Fails when the fork choice refuses the vote.
    pub fn on_payload_attestation(
        &mut self,
        message: &PayloadAttestationMessage,
    ) -> Result<(), ChainError> {
        self.store
            .on_payload_attestation_message(message, false, Verification::Verify)?;
        Ok(())
    }

    /// Records a proof-of-work block the execution layer reported, for the merge transition check.
    ///
    /// See `get_pow_block` in the Bellatrix fork choice spec.
    pub fn on_pow_block(&mut self, block: PowBlock) {
        self.store.on_pow_block(block);
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
        let timer = self.metrics.fork_choice_seconds.start_timer();
        let head = Self::read_head(&mut self.store)?;
        drop(timer);
        if head == previous {
            return Ok(());
        }

        // A head off the previous head's chain is a reorg; measure it before pruning can hide it.
        let reorg = (head.root != previous.root
            && !self.store.blocks().is_ancestor(head.root, previous.root))
        .then(|| self.reorg_depth(previous, head));

        // Invariant: finality reaches the disk before the head moves.
        // A failed write leaves the head as it was, so the next update tries again.
        let finalized = head.finalized.epoch > previous.finalized.epoch;
        if finalized {
            self.finalize(previous.finalized, head.finalized)?;
        }

        self.head = head;
        self.record_head(head, head.slot.epoch::<P>() != previous.slot.epoch::<P>());
        if let Some(depth) = reorg {
            warn!(from = %previous.root, to = %head.root, depth, "chain reorganized");
            self.metrics.reorgs.inc();
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

        if finalized {
            // Waiting items and refused blocks at or before finality can never matter again.
            let finalized_slot = head.finalized.epoch.start_slot::<P>();
            self.availability.prune(finalized_slot);
            self.gossip.prune(finalized_slot);
            info!(epoch = %head.finalized.epoch, root = %head.finalized.root, "finalized");
            self.announce(ChainEvent::Finalized(head.finalized));
        }
        Ok(())
    }

    /// Persists a new finality, then forgets what it excluded.
    ///
    /// The database write comes first: if it fails, the store keeps everything and nothing is lost.
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

        // Blocks neither on the finalized chain nor after it are orphaned forks.
        let orphans: Vec<Root> = blocks
            .iter()
            .map(|(root, _)| *root)
            .filter(|root| {
                !canonical.contains(root)
                    && *root != previous.root
                    && !blocks.is_ancestor(*root, finalized.root)
            })
            .collect();
        let state = self
            .store
            .block_state(&finalized.root)
            .ok_or(ChainError::MissingState(finalized.root))?
            .beacon();
        self.database
            .finalize(previous, finalized, state, &chain, &orphans)?;

        // A finalized checkpoint block is what light clients bootstrap from.
        if let Some(block) = self.database.block(finalized.root)? {
            self.offer_bootstrap(finalized.root, &block);
        }
        let kept = LIGHT_CLIENT_PERIODS_KEPT * P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let earliest = Epoch(finalized.epoch.0.saturating_sub(kept));
        self.light_client.prune(earliest.start_slot::<P>());

        // Only now that the disk agrees, drop the excluded blocks from memory.
        self.store.prune();
        Ok(())
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
        let root = store.head()?.root;
        let node = *store
            .blocks()
            .get(&root)
            .ok_or(ChainError::MissingState(root))?;
        let state = store
            .block_state(&root)
            .ok_or(ChainError::MissingState(root))?;
        let justified = store.justified_checkpoint();
        let finalized = store.finalized_checkpoint();

        // A block's post-state caches the hash of the latest payload the chain accepted.
        let payload_hash = |root: &Root| -> Hash32 {
            store
                .block_state(root)
                .and_then(|state| state.beacon().latest_execution_block_hash())
                .unwrap_or(Hash32::ZERO)
        };
        Ok(Head {
            root,
            slot: node.slot,
            optimistic: node.status != ExecutionStatus::Valid,
            justified,
            finalized,
            execution: ExecutionHead {
                head: state
                    .beacon()
                    .latest_execution_block_hash()
                    .unwrap_or(Hash32::ZERO),
                safe: payload_hash(&justified.root),
                finalized: payload_hash(&finalized.root),
            },
        })
    }

    /// Publishes the head's numbers to the metrics.
    ///
    /// Counting active validators walks the whole registry, so it runs only on a new epoch.
    fn record_head(&mut self, head: Head, new_epoch: bool) {
        let metrics = &self.metrics;
        metrics.head_slot.set_count(head.slot.0);
        metrics.finalized_epoch.set_count(head.finalized.epoch.0);
        metrics
            .current_justified_epoch
            .set_count(head.justified.epoch.0);
        if let Some(state) = self.store.block_state(&head.root) {
            let beacon = state.beacon();
            metrics
                .previous_justified_epoch
                .set_count(beacon.previous_justified_checkpoint().epoch.0);
            metrics
                .processed_deposits
                .set_count(beacon.eth1_deposit_index());
            if new_epoch {
                let epoch = beacon.current_epoch();
                let active = beacon
                    .validators()
                    .iter()
                    .filter(|validator| validator.is_active_at(epoch))
                    .count();
                metrics.current_active_validators.set_count(active as u64);
            }
        }
        // The store counts bytes since it opened; the counter takes the increase.
        let written = self.database.bytes_written();
        metrics
            .store_bytes_written
            .inc_by(written.saturating_sub(self.bytes_written));
        self.bytes_written = written;
    }

    /// Sends an event to every subscriber.
    fn announce(&self, event: ChainEvent) {
        // Having no subscriber is normal, so a failed send is not an error.
        let _unheard = self.events.send(event);
    }
}
