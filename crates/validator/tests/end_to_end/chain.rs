//! The test beacon node's chain: a built chain, the votes it collects, and the duties it reports.

use std::collections::BTreeMap;

use axiom_beacon_json::api::{
    AttesterDuty, Duties, ProposerDuty, PtcDuty, SyncDuty, ValidatorResponse, ValidatorStatus,
};
use axiom_bls::Signature;
use axiom_ef_tests::chain_builder::{
    BlockAttestations, BlockInputs, ChainBuilder, UnsignedProposal,
};
use axiom_ssz::{BitList, ProgressiveBitList, Ssz};
use axiom_state_transition::{EpochCommittees, State, gloas::ptc::PtcWindow};
use axiom_types::{
    BlsPubkey, BlsSignature, ChainConfig, CommitteeIndex, Epoch, ForkName, Minimal, Preset, Root,
    Slot, ValidatorIndex,
    accessors::{CoreState, ForkState},
    altair::{SyncAggregate, SyncCommitteeContribution, SyncCommitteeMessage},
    combined,
    constants::{G2_POINT_AT_INFINITY, SYNC_COMMITTEE_SUBNET_COUNT},
    electra, gloas,
    phase0::{self, AttestationData, Checkpoint},
};
use axiom_validator::beacon::{Aggregate, PoolAttestation, ProducedBlock, SignedProposal};

/// One committee's votes for one slot, as single votes arrive.
#[derive(Clone, Debug)]
struct CommitteeVotes {
    /// The vote, the same for every member that agrees.
    data: AttestationData,
    /// Members of the committee.
    size: usize,
    /// Each voter's signature, by its position in the committee.
    signatures: BTreeMap<usize, BlsSignature>,
    /// Whether a block already carries these votes.
    included: bool,
}

/// The votes of several committees of one slot, merged into one attestation's parts.
#[derive(Clone, Debug)]
struct MergedVote {
    /// The committees present.
    committee_bits: electra::CommitteeBits<Minimal>,
    /// Members of every present committee together.
    size: usize,
    /// Positions that signed, across the committees back to back.
    positions: Vec<usize>,
    /// The shared vote.
    data: AttestationData,
    /// Aggregate of every signature.
    signature: BlsSignature,
}

/// What the node has seen happen, for the test to check.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    /// Blocks applied with every signature checked.
    pub(crate) blocks: u64,
    /// Envelopes applied with their blocks.
    pub(crate) envelopes: u64,
    /// Single votes accepted into the pool.
    pub(crate) votes: u64,
    /// Signed aggregates received.
    pub(crate) aggregates: u64,
    /// Sync committee messages received.
    pub(crate) sync_messages: u64,
    /// Signed sync contributions received.
    pub(crate) contributions: u64,
    /// Payload timeliness votes received.
    pub(crate) payload_votes: u64,
    /// Proposer preferences received.
    pub(crate) preferences: u64,
}

/// A beacon node's chain, reduced to what a validator client exercises.
pub(crate) struct TestChain {
    /// The chain and its state.
    builder: ChainBuilder<Minimal>,
    /// Single votes by slot and committee.
    votes: BTreeMap<(Slot, CommitteeIndex), CommitteeVotes>,
    /// Sync messages by slot and block root, each validator's signature.
    sync: BTreeMap<(Slot, Root), BTreeMap<ValidatorIndex, BlsSignature>>,
    /// Envelopes of produced Gloas blocks, by block root.
    envelopes: BTreeMap<Root, gloas::ExecutionPayloadEnvelope<Minimal>>,
    /// A published Gloas block waiting for its envelope.
    pending: Option<combined::SignedBeaconBlock<Minimal>>,
    /// Root of the latest applied block.
    head: Root,
    /// Slot of the latest applied block.
    head_slot: Slot,
    /// What happened so far.
    pub(crate) tally: Tally,
}

impl TestChain {
    /// A chain at its genesis.
    pub(crate) fn new(builder: ChainBuilder<Minimal>) -> Self {
        // The genesis header leaves its state root zero until slot 1 fills it with the genesis state's.
        // The block of slot 1 names the filled header as its parent, so the head does too.
        let state = builder.state();
        let mut header = state.beacon().latest_block_header().clone();
        if header.state_root == Root::ZERO {
            header.state_root = state.hash_tree_root();
        }
        let head = header.hash_tree_root();
        Self {
            builder,
            votes: BTreeMap::new(),
            sync: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            pending: None,
            head,
            head_slot: Slot(0),
            tally: Tally::default(),
        }
    }

    /// The configuration.
    pub(crate) const fn config(&self) -> &ChainConfig {
        self.builder.config()
    }

    /// The state after the latest block.
    pub(crate) const fn state(&self) -> &State<Minimal> {
        self.builder.state()
    }

    /// Root and slot of the head block.
    pub(crate) const fn head(&self) -> (Root, Slot) {
        (self.head, self.head_slot)
    }

    /// The head state advanced to a slot, without moving the chain.
    fn state_at(&self, slot: Slot) -> State<Minimal> {
        let mut state = self.builder.state().clone();
        if slot > state.beacon().slot() {
            state
                .process_slots(self.builder.config(), slot)
                .expect("an empty slot always processes");
        }
        state
    }

    /// The root an epoch's shuffling depends on: the head's ancestor at the dependent slot.
    ///
    /// The dependent slot is the last slot before the lookahead epoch, or genesis.
    /// A head at or before that slot is its own ancestor there, so the head's root is the answer.
    /// The state's root history holds only slots before the head's.
    /// See `get_shuffling_dependent_root` in the phase0 fork choice spec.
    pub(crate) fn shuffling_root(&self, epoch: Epoch) -> Root {
        let dependent_slot = epoch
            .saturating_sub(Minimal::MIN_SEED_LOOKAHEAD)
            .start_slot::<Minimal>()
            .saturating_sub(1);
        if self.head_slot <= dependent_slot {
            return self.head;
        }
        // Invariant: duties are asked for the current epoch and the next only.
        // Their dependent slot is then at most 16 slots behind the head, inside 64 slots of roots.
        self.builder
            .state()
            .beacon()
            .block_root_at_slot(dependent_slot)
            .expect("the dependent slot lies within the root history")
    }

    /// Counts signed proposer preferences, each committed to its proposal's shuffling.
    pub(crate) fn receive_preferences(&mut self, preferences: &[gloas::SignedProposerPreferences]) {
        for signed in preferences {
            // Invariant: preferences commit to the shuffling one epoch before the proposal.
            let epoch = signed.message.proposal_slot.epoch::<Minimal>();
            assert_eq!(signed.message.dependent_root, self.shuffling_root(epoch));
        }
        self.tally.preferences += preferences.len() as u64;
    }

    /// Registry entries of the given keys.
    pub(crate) fn validators(&self, pubkeys: &[BlsPubkey]) -> Vec<ValidatorResponse> {
        let beacon = self.builder.state().beacon();
        beacon
            .validators()
            .iter()
            .enumerate()
            .filter(|(_, validator)| pubkeys.contains(&validator.pubkey))
            .map(|(index, validator)| ValidatorResponse {
                index: ValidatorIndex(index as u64),
                balance: beacon.balances()[index],
                status: ValidatorStatus::ActiveOngoing,
                validator: validator.clone(),
            })
            .collect()
    }

    /// Every proposer of an epoch.
    pub(crate) fn proposer_duties(&self, epoch: Epoch) -> Duties<ProposerDuty> {
        let beacon = self.builder.state().beacon();
        let start = epoch.start_slot::<Minimal>();
        let data = (start.0..start.0 + Minimal::SLOTS_PER_EPOCH)
            .map(Slot)
            .filter(|slot| *slot > Slot(0))
            .map(|slot| {
                let index = self
                    .state_at(slot)
                    .beacon_proposer_index()
                    .expect("an active set elects a proposer");
                ProposerDuty {
                    pubkey: beacon.validators()[index.as_usize()].pubkey,
                    validator_index: index,
                    slot,
                }
            })
            .collect();
        Duties {
            dependent_root: Some(self.shuffling_root(epoch)),
            execution_optimistic: false,
            data,
        }
    }

    /// Committee seats of some validators in an epoch.
    pub(crate) fn attester_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Duties<AttesterDuty> {
        let state = self.state_at(epoch.start_slot::<Minimal>().max(self.head_slot));
        let beacon = state.beacon();
        let committees = EpochCommittees::compute(beacon, epoch);
        let per_slot = committees.committees_per_slot();
        let mut data = Vec::new();
        for slot in epoch.start_slot::<Minimal>().0
            ..epoch.start_slot::<Minimal>().0 + Minimal::SLOTS_PER_EPOCH
        {
            for committee_index in 0..per_slot {
                let committee = committees
                    .committee(Slot(slot), CommitteeIndex(committee_index))
                    .expect("committees exist for every slot");
                for (position, member) in committee.iter().enumerate() {
                    if indices.contains(member) {
                        data.push(AttesterDuty {
                            pubkey: beacon.validators()[member.as_usize()].pubkey,
                            validator_index: *member,
                            committee_index: CommitteeIndex(committee_index),
                            committee_length: committee.len() as u64,
                            committees_at_slot: per_slot,
                            validator_committee_index: position as u64,
                            slot: Slot(slot),
                        });
                    }
                }
            }
        }
        Duties {
            dependent_root: Some(self.shuffling_root(epoch)),
            execution_optimistic: false,
            data,
        }
    }

    /// Sync committee seats of some validators for an epoch's period, from Altair on.
    pub(crate) fn sync_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Option<Vec<SyncDuty>> {
        let beacon = self.builder.state().beacon();
        let sync = beacon.sync_committees()?;
        let period = |epoch: Epoch| epoch.0 / Minimal::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let committee = if period(epoch) == period(beacon.current_epoch()) {
            sync.current_sync_committee()
        } else if period(epoch) == period(beacon.current_epoch()) + 1 {
            sync.next_sync_committee()
        } else {
            return None;
        };
        let mut seats: BTreeMap<ValidatorIndex, Vec<u64>> = BTreeMap::new();
        for (seat, pubkey) in committee.pubkeys.iter().enumerate() {
            let Some(index) = beacon.validators().iter().position(|v| v.pubkey == *pubkey) else {
                continue;
            };
            let index = ValidatorIndex(index as u64);
            if indices.contains(&index) {
                seats.entry(index).or_default().push(seat as u64);
            }
        }
        Some(
            seats
                .into_iter()
                .map(|(index, seats)| SyncDuty {
                    pubkey: beacon.validators()[index.as_usize()].pubkey,
                    validator_index: index,
                    validator_sync_committee_indices: seats,
                })
                .collect(),
        )
    }

    /// Payload timeliness seats of some validators in a Gloas epoch.
    pub(crate) fn ptc_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Option<Vec<PtcDuty>> {
        let state = self.state_at(epoch.start_slot::<Minimal>().max(self.head_slot));
        let gloas_state = gloas::BeaconState::from_any(state.beacon())?;
        let fork_epoch = self.builder.config().gloas_fork_epoch;
        let mut duties = Vec::new();
        for slot in epoch.start_slot::<Minimal>().0
            ..epoch.start_slot::<Minimal>().0 + Minimal::SLOTS_PER_EPOCH
        {
            let committee = PtcWindow::of_slot(gloas_state, Slot(slot), fork_epoch).ok()?;
            for member in committee {
                if indices.contains(member) {
                    duties.push(PtcDuty {
                        pubkey: gloas_state.validators()[member.as_usize()].pubkey,
                        validator_index: *member,
                        slot: Slot(slot),
                    });
                }
            }
        }
        Some(duties)
    }

    /// The vote a committee should sign at a slot.
    pub(crate) fn attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> AttestationData {
        let state = self.state_at(slot);
        let beacon = state.beacon();
        let epoch = slot.epoch::<Minimal>();
        let fork = self.builder.config().fork_at(epoch);
        let target_slot = epoch.start_slot::<Minimal>();
        let target_root = if self.head_slot <= target_slot {
            self.head
        } else {
            beacon.block_root_at_slot(target_slot).unwrap_or(self.head)
        };
        // From Electra the index names no committee; at Gloas it says whether the payload is present.
        let index = match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb => committee_index,
            ForkName::Electra | ForkName::Fulu => CommitteeIndex(0),
            ForkName::Gloas => CommitteeIndex(u64::from(self.head_slot < slot)),
        };
        AttestationData {
            slot,
            index,
            beacon_block_root: self.head,
            source: beacon.current_justified_checkpoint(),
            target: Checkpoint {
                epoch,
                root: target_root,
            },
        }
    }

    /// Accepts a single vote into the pool.
    pub(crate) fn add_vote(&mut self, vote: PoolAttestation<Minimal>) {
        let data = vote.data().clone();
        let state = self.state_at(data.slot.max(self.head_slot));
        let committees = EpochCommittees::compute(state.beacon(), data.slot.epoch::<Minimal>());
        let (committee_index, position, signature) = match vote {
            PoolAttestation::Phase0(attestation) => {
                let position = attestation
                    .aggregation_bits
                    .iter()
                    .position(|bit| bit)
                    .expect("one bit set");
                (data.index, position, attestation.signature)
            }
            PoolAttestation::Single(single) => {
                let committee = committees
                    .committee(data.slot, single.committee_index)
                    .expect("the committee exists");
                let position = committee
                    .iter()
                    .position(|member| *member == single.attester_index)
                    .expect("the attester sits in its committee");
                (single.committee_index, position, single.signature)
            }
        };
        let size = committees
            .committee(data.slot, committee_index)
            .expect("the committee exists")
            .len();
        let entry = self
            .votes
            .entry((data.slot, committee_index))
            .or_insert_with(|| CommitteeVotes {
                data: data.clone(),
                size,
                signatures: BTreeMap::new(),
                included: false,
            });
        assert_eq!(entry.data, data, "honest voters agree on the vote");
        entry.signatures.insert(position, signature);
        self.tally.votes += 1;
    }

    /// The aggregate of a committee's votes, in the shape of a fork.
    pub(crate) fn aggregate(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
        data_root: Root,
        fork: ForkName,
    ) -> Option<Aggregate<Minimal>> {
        let votes = self.votes.get(&(slot, committee_index))?;
        if votes.data.hash_tree_root() != data_root {
            return None;
        }
        let signature = aggregate_signatures(votes.signatures.values());
        let positions: Vec<usize> = votes.signatures.keys().copied().collect();
        Some(match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb => Aggregate::Phase0(phase0::Attestation {
                aggregation_bits: bit_list(votes.size, &positions),
                data: votes.data.clone(),
                signature,
            }),
            ForkName::Electra | ForkName::Fulu => {
                let mut committee_bits = electra::CommitteeBits::<Minimal>::default();
                committee_bits.set(committee_index.as_usize(), true);
                Aggregate::Electra(electra::Attestation {
                    aggregation_bits: bit_list(votes.size, &positions),
                    data: votes.data.clone(),
                    signature,
                    committee_bits,
                })
            }
            ForkName::Gloas => {
                let mut committee_bits = electra::CommitteeBits::<Minimal>::default();
                committee_bits.set(committee_index.as_usize(), true);
                Aggregate::Gloas(gloas::Attestation {
                    aggregation_bits: progressive_bits(votes.size, &positions),
                    data: votes.data.clone(),
                    signature,
                    committee_bits,
                })
            }
        })
    }

    /// Accepts sync committee messages.
    pub(crate) fn add_sync_messages(&mut self, messages: Vec<SyncCommitteeMessage>) {
        for message in messages {
            self.sync
                .entry((message.slot, message.beacon_block_root))
                .or_default()
                .insert(message.validator_index, message.signature);
            self.tally.sync_messages += 1;
        }
    }

    /// The seats of the sync committee signing at a slot, as validator indices.
    fn sync_seats(&self, slot: Slot) -> Option<Vec<ValidatorIndex>> {
        let state = self.state_at((slot + 1).max(self.head_slot));
        let beacon = state.beacon();
        let sync = beacon.sync_committees()?;
        Some(
            sync.current_sync_committee()
                .pubkeys
                .iter()
                .map(|pubkey| {
                    let index = beacon
                        .validators()
                        .iter()
                        .position(|validator| validator.pubkey == *pubkey)
                        .expect("sync members are registered");
                    ValidatorIndex(index as u64)
                })
                .collect(),
        )
    }

    /// A subcommittee's contribution from the pool.
    pub(crate) fn contribution(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        root: Root,
    ) -> Option<SyncCommitteeContribution<Minimal>> {
        let seats = self.sync_seats(slot)?;
        let signed = self.sync.get(&(slot, root))?;
        let per_subnet = (Minimal::SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT) as usize;
        let start = subcommittee_index as usize * per_subnet;
        let mut contribution = SyncCommitteeContribution::<Minimal> {
            slot,
            beacon_block_root: root,
            subcommittee_index,
            ..SyncCommitteeContribution::default()
        };
        let mut signatures = Vec::new();
        for (offset, member) in seats[start..start + per_subnet].iter().enumerate() {
            if let Some(signature) = signed.get(member) {
                contribution.aggregation_bits.set(offset, true);
                signatures.push(*signature);
            }
        }
        if signatures.is_empty() {
            return None;
        }
        contribution.signature = aggregate_signatures(signatures.iter());
        Some(contribution)
    }

    /// The payload timeliness vote for a slot, once its block is the head.
    pub(crate) fn payload_attestation_data(
        &self,
        slot: Slot,
    ) -> Option<gloas::PayloadAttestationData> {
        (self.head_slot == slot).then_some(gloas::PayloadAttestationData {
            beacon_block_root: self.head,
            slot,
            payload_present: true,
            blob_data_available: true,
        })
    }

    /// Builds the block of a slot around a proposer's reveal and the pooled votes.
    pub(crate) fn produce(
        &mut self,
        slot: Slot,
        randao_reveal: BlsSignature,
    ) -> ProducedBlock<Minimal> {
        let fork = self.builder.config().fork_at(slot.epoch::<Minimal>());
        let inputs = BlockInputs {
            randao_reveal,
            attestations: self.block_votes(slot, fork),
            sync_aggregate: self.sync_aggregate(slot),
        };
        let UnsignedProposal { block, envelope } = self
            .builder
            .produce(slot, &inputs)
            .expect("the produced block is valid");
        if let Some(envelope) = envelope {
            self.envelopes.insert(envelope.beacon_block_root, envelope);
        }
        match block {
            combined::BeaconBlock::Deneb(block) => {
                ProducedBlock::Deneb(axiom_types::deneb::BlockContents {
                    block,
                    ..Default::default()
                })
            }
            combined::BeaconBlock::Electra(block) => {
                ProducedBlock::Electra(electra::BlockContents {
                    block,
                    ..Default::default()
                })
            }
            combined::BeaconBlock::Fulu(block) => {
                ProducedBlock::Fulu(axiom_types::fulu::BlockContents {
                    block,
                    ..Default::default()
                })
            }
            block => ProducedBlock::Block(block),
        }
    }

    /// The pooled votes a block of a slot carries, in its fork's shape.
    ///
    /// Votes of the previous epoch and this one, not yet included, at least one slot old.
    /// From Electra on, one attestation carries every committee of a slot.
    fn block_votes(&self, slot: Slot, fork: ForkName) -> BlockAttestations<Minimal> {
        let oldest = Slot(slot.0.saturating_sub(Minimal::SLOTS_PER_EPOCH));
        let candidates: Vec<(CommitteeIndex, &CommitteeVotes)> = self
            .votes
            .range((oldest, CommitteeIndex(0))..(slot, CommitteeIndex(0)))
            .filter(|(_, votes)| !votes.included && !votes.signatures.is_empty())
            .map(|((_, committee), votes)| (*committee, votes))
            .collect();
        match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb => BlockAttestations::Phase0(
                candidates
                    .iter()
                    .rev()
                    .take(Minimal::MAX_ATTESTATIONS as usize)
                    .map(|(_, votes)| phase0::Attestation {
                        aggregation_bits: bit_list(
                            votes.size,
                            &votes.signatures.keys().copied().collect::<Vec<_>>(),
                        ),
                        data: votes.data.clone(),
                        signature: aggregate_signatures(votes.signatures.values()),
                    })
                    .collect(),
            ),
            ForkName::Electra | ForkName::Fulu => BlockAttestations::Electra(
                self.merged(&candidates)
                    .into_iter()
                    .take(Minimal::MAX_ATTESTATIONS_ELECTRA as usize)
                    .map(|vote| electra::Attestation {
                        aggregation_bits: bit_list(vote.size, &vote.positions),
                        data: vote.data,
                        signature: vote.signature,
                        committee_bits: vote.committee_bits,
                    })
                    .collect(),
            ),
            ForkName::Gloas => BlockAttestations::Gloas(
                self.merged(&candidates)
                    .into_iter()
                    .take(Minimal::MAX_ATTESTATIONS_ELECTRA as usize)
                    .map(|vote| gloas::Attestation {
                        aggregation_bits: progressive_bits(vote.size, &vote.positions),
                        data: vote.data,
                        signature: vote.signature,
                        committee_bits: vote.committee_bits,
                    })
                    .collect(),
            ),
        }
    }

    /// Each slot's votes merged across its committees, newest slot first, as Electra carries them.
    ///
    /// The bits of each named committee run back to back, in committee order.
    /// Committees share one vote from Electra on, so an older vote naming committee 1 is left out.
    fn merged(&self, candidates: &[(CommitteeIndex, &CommitteeVotes)]) -> Vec<MergedVote> {
        let electra = self.config().electra_fork_epoch;
        let mut slots: BTreeMap<(Slot, Root), Vec<(CommitteeIndex, &CommitteeVotes)>> =
            BTreeMap::new();
        for (committee, votes) in candidates {
            let names_committee = votes.data.slot.epoch::<Minimal>() < electra;
            if names_committee && votes.data.index != CommitteeIndex(0) {
                continue;
            }
            slots
                .entry((votes.data.slot, votes.data.hash_tree_root()))
                .or_default()
                .push((*committee, *votes));
        }
        slots
            .into_values()
            .rev()
            .map(|committees| {
                let mut committee_bits = electra::CommitteeBits::<Minimal>::default();
                let mut positions = Vec::new();
                let mut size = 0;
                for (committee, votes) in &committees {
                    committee_bits.set(committee.as_usize(), true);
                    positions.extend(votes.signatures.keys().map(|position| size + position));
                    size += votes.size;
                }
                MergedVote {
                    committee_bits,
                    size,
                    positions,
                    data: committees[0].1.data.clone(),
                    signature: aggregate_signatures(
                        committees
                            .iter()
                            .flat_map(|(_, votes)| votes.signatures.values()),
                    ),
                }
            })
            .collect()
    }

    /// The sync aggregate a block of a slot carries: the previous slot's messages on its parent.
    fn sync_aggregate(&self, slot: Slot) -> Option<SyncAggregate<Minimal>> {
        let voted = Slot(slot.0.checked_sub(1)?);
        let seats = self.sync_seats(voted)?;
        let mut aggregate = SyncAggregate::<Minimal> {
            sync_committee_signature: G2_POINT_AT_INFINITY,
            ..SyncAggregate::default()
        };
        let Some(signed) = self.sync.get(&(voted, self.head)) else {
            return Some(aggregate);
        };
        // A validator with two seats signs once and is counted twice.
        let mut signatures = Vec::new();
        for (seat, member) in seats.iter().enumerate() {
            if let Some(signature) = signed.get(member) {
                aggregate.sync_committee_bits.set(seat, true);
                signatures.push(*signature);
            }
        }
        if !signatures.is_empty() {
            aggregate.sync_committee_signature = aggregate_signatures(signatures.iter());
        }
        Some(aggregate)
    }

    /// The envelope built beside a Gloas block.
    pub(crate) fn envelope(&self, root: Root) -> Option<gloas::ExecutionPayloadEnvelope<Minimal>> {
        self.envelopes.get(&root).cloned()
    }

    /// Applies a published block, or holds a Gloas block until its envelope comes.
    pub(crate) fn publish(&mut self, proposal: &SignedProposal<Minimal>) -> Result<(), String> {
        let block = proposal
            .block()
            .ok_or("the test node builds no blinded blocks")?;
        if block.fork_name() == ForkName::Gloas {
            self.pending = Some(block);
            return Ok(());
        }
        self.apply(&block, None)
    }

    /// Applies the held Gloas block with its signed envelope.
    pub(crate) fn publish_envelope(
        &mut self,
        envelope: &gloas::SignedExecutionPayloadEnvelope<Minimal>,
    ) -> Result<(), String> {
        let block = self
            .pending
            .take()
            .ok_or("no block waits for an envelope")?;
        self.apply(&block, Some(envelope))?;
        self.tally.envelopes += 1;
        Ok(())
    }

    /// Applies a block with every signature checked, and marks the votes it carries.
    fn apply(
        &mut self,
        block: &combined::SignedBeaconBlock<Minimal>,
        envelope: Option<&gloas::SignedExecutionPayloadEnvelope<Minimal>>,
    ) -> Result<(), String> {
        self.builder
            .apply(block, envelope)
            .map_err(|error| error.to_string())?;
        for vote in block.message().committee_votes() {
            for committee in vote.committees {
                if let Some(votes) = self.votes.get_mut(&(vote.data.slot, committee)) {
                    votes.included = true;
                }
            }
        }
        self.head = block.block_root();
        self.head_slot = block.slot();
        self.tally.blocks += 1;
        Ok(())
    }
}

/// A bit list of a length with some positions set.
fn bit_list<N: axiom_ssz::Length>(len: usize, positions: &[usize]) -> BitList<N> {
    let mut bits = BitList::with_len(len).expect("a committee fits an attestation");
    for position in positions {
        bits.set(*position, true);
    }
    bits
}

/// A progressive bit list of a length with some positions set.
fn progressive_bits(len: usize, positions: &[usize]) -> ProgressiveBitList {
    let mut bits = ProgressiveBitList::with_len(len);
    for position in positions {
        bits.set(*position, true);
    }
    bits
}

/// The aggregate of signatures.
fn aggregate_signatures<'a>(signatures: impl Iterator<Item = &'a BlsSignature>) -> BlsSignature {
    let points: Vec<Signature> = signatures
        .map(|signature| Signature::from_bytes(&signature.0).expect("validators sign valid points"))
        .collect();
    BlsSignature(
        Signature::aggregate(&points)
            .expect("at least one signature")
            .to_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use axiom_ef_tests::{
        Case, Vectors,
        chain_builder::{ChainBuilder, PYSPEC_GENESIS},
    };
    use axiom_types::{Epoch, Minimal, Slot, phase0};

    use super::TestChain;
    use crate::schedule;

    #[test]
    fn the_shuffling_root_is_the_heads_ancestor_at_the_dependent_slot() {
        let Some(vectors) = Vectors::locate() else {
            return;
        };
        let genesis: phase0::BeaconState<Minimal> =
            Case::new(vectors.consensus().join(PYSPEC_GENESIS))
                .ssz("state")
                .expect("the genesis vector decodes");

        // Fixture state: the node's chain at genesis, and a twin builder that signs its blocks.
        let mut proposer = ChainBuilder::<Minimal>::new(schedule(), genesis.clone())
            .expect("the pyspec genesis builds");
        let mut chain = TestChain::new(
            ChainBuilder::new(schedule(), genesis).expect("the pyspec genesis builds"),
        );
        let genesis_root = chain.head().0;

        // Epoch 1 depends on slot 0, the genesis block, while the head is still genesis.
        assert_eq!(chain.shuffling_root(Epoch(1)), genesis_root);

        // Blocks at slots 1 to 7 fill epoch 0.
        let mut roots = vec![genesis_root];
        for _ in 1..=7 {
            let proposal = proposer.propose().expect("the next block builds");
            chain
                .apply(proposal.block(), None)
                .expect("the block applies with its signatures");
            roots.push(proposal.block().block_root());
        }
        // It still does once seven blocks build on it.
        assert_eq!(chain.shuffling_root(Epoch(1)), genesis_root);

        // Epoch 2 depends on slot 7, the last of epoch 0.
        // The head sits at slot 7, before any block of epoch 1 lands.
        // The state's root history stops at slot 6, so the answer is the head itself.
        assert_eq!(chain.head(), (roots[7], Slot(7)));
        assert_eq!(chain.shuffling_root(Epoch(2)), roots[7]);

        // Mutation: the block of slot 8 lands; epoch 2 still depends on the block of slot 7.
        let proposal = proposer.propose().expect("the next block builds");
        chain
            .apply(proposal.block(), None)
            .expect("the block applies with its signatures");
        assert_eq!(chain.shuffling_root(Epoch(2)), roots[7]);
    }
}
