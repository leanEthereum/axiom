//! The gossip rules, one method per topic, in the spec's order.

use axiom_das::ColumnSidecar;
use axiom_fork_choice::{BlockNode, ForkChoiceError};
use axiom_kzg::Kzg;
use axiom_ssz::Ssz;
use axiom_state_transition::State;
use axiom_types::{
    BlsPubkey, BlsSignature, ChainConfig, ColumnIndex, Domain, DomainType, Epoch, Gwei, Preset,
    Root, Slot, SubnetId, ValidatorIndex,
    accessors::{CoreState, ForkState},
    altair::{self, SignedContributionAndProof, SyncCommitteeContribution, SyncCommitteeMessage},
    bellatrix,
    capella::{self, SignedBlsToExecutionChange},
    combined::{self, BeaconState},
    constants::{
        BLS_WITHDRAWAL_PREFIX, BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_BUILDER,
        DOMAIN_BEACON_PROPOSER, DOMAIN_BLS_TO_EXECUTION_CHANGE, DOMAIN_PROPOSER_PREFERENCES,
        DOMAIN_PTC_ATTESTER, DOMAIN_SYNC_COMMITTEE, PAYLOAD_BUILDER_VERSION,
        SYNC_COMMITTEE_SUBNET_COUNT, TARGET_AGGREGATORS_PER_COMMITTEE,
        TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
    },
    deneb::{self, BlobSidecar},
    electra,
    fulu::{
        self, DataColumnSidecar, PartialDataColumnGroupId, PartialDataColumnHeader,
        PartialDataColumnSidecar,
    },
    gloas::{
        self, Builder, ExecutionPayloadBid, PayloadAttestationMessage, SignedExecutionPayloadBid,
        SignedExecutionPayloadEnvelope, SignedProposerPreferences,
    },
    phase0::{
        self, AttestationData, BeaconBlockHeader, ProposerSlashing, SignedVoluntaryExit, Validator,
    },
};

use crate::{
    BlobSubnets, ChainView, CheckedBlob, Detail, GossipError, GossipFork, Seen, SeenPartialHeader,
    VoteIndex, VoteWindow,
    fork::{Bounded, BuilderFunds, ExecutionRequestLimits, GasTarget, Ptc, Verdict},
    partial_column::{PartialCells, PartialHeader},
    signers::Signers,
    signing_claim::SigningClaim,
    vote::{Aggregate, SignedAggregate, SlashingEvidence, SubnetVote},
};

/// Validates gossip messages against a chain view, remembering what it forwarded.
///
/// Each method mirrors one `validate_*_gossip` function of the spec.
/// Only a message that passes every rule updates the seen state.
///
/// A topic every fork shares takes the fork as a type, which names its messages and amendments.
#[derive(Debug)]
pub struct GossipValidator<'a, 'b, P: Preset> {
    /// The node's view of the chain.
    view: &'a mut ChainView<'b, P>,
    /// Messages already forwarded.
    seen: &'a mut Seen,
}

impl<'a, 'b, P: Preset> GossipValidator<'a, 'b, P> {
    /// A validator over a view and its seen state.
    pub const fn new(view: &'a mut ChainView<'b, P>, seen: &'a mut Seen) -> Self {
        Self { view, seen }
    }

    /// The chain configuration the rules read.
    #[must_use]
    pub const fn config(&self) -> &ChainConfig {
        self.view.config()
    }

    /// Validates a block of a fork.
    ///
    /// See `validate_beacon_block_gossip` in the phase0 p2p spec, and the amendments of each fork.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn beacon_block<F: GossipFork<Preset = P>>(
        &mut self,
        signed: &F::SignedBeaconBlock,
        now_ms: u64,
    ) -> Verdict {
        let (block, signature) = F::split_block(signed);
        // The header has the block's root, so it stands in for the block in signatures.
        let header = F::block_header(block);
        let key = (header.slot, header.proposer_index);
        let proposer_detail = Detail::Validator(header.proposer_index);
        if self.seen.proposer_slots.contains(&key) {
            return Err(GossipError::ignore(
                "block is not the first valid block for this slot and proposer",
            )
            .with(proposer_detail));
        }
        self.header_slot_is_timely(
            header.slot,
            now_ms,
            "block is from a future slot",
            "block is not from a slot greater than the latest finalized slot",
        )?;
        let parent_detail = Detail::Block(header.parent_root);
        let Some(parent) = self.view.block(&header.parent_root) else {
            return Err(GossipError::ignore("block's parent has not been seen").with(parent_detail));
        };
        if !self.view.is_imported(&header.parent_root) {
            return Err(F::failed_parent(self.view, block));
        }

        let state = self.head_state()?;
        let beacon = state.beacon();
        let proposer =
            Self::registered(beacon, header.proposer_index, "proposer index out of range")?;
        let domain = self.domain(beacon, DOMAIN_BEACON_PROPOSER, header.slot.epoch::<P>());
        if !SigningClaim::new(&header, domain, signature).is_signed_by(&proposer.pubkey) {
            return Err(GossipError::reject("invalid proposer signature").with(proposer_detail));
        }
        F::check_execution(self.view, &state, block)?;
        if header.slot <= parent.slot {
            return Err(
                GossipError::reject("block is not from a higher slot than its parent").with(
                    Detail::Slot {
                        slot: header.slot,
                        reference: parent.slot,
                    },
                ),
            );
        }
        if !self.view.descends_from_finalized(header.parent_root) {
            return Err(GossipError::reject(
                "finalized checkpoint is not an ancestor of block",
            ));
        }
        F::check_body(self.view.config(), block)?;
        let parent_state = self.parent_state(&header.parent_root, header.slot)?;
        let expected_proposer = parent_state
            .beacon_proposer_index()
            .map_err(|_| GossipError::ignore("proposer shuffling is unavailable"))?;
        if header.proposer_index != expected_proposer {
            return Err(GossipError::reject(
                "block proposer_index does not match expected proposer",
            )
            .with(Detail::Mismatch {
                actual: header.proposer_index.0,
                expected: expected_proposer.0,
            }));
        }
        F::check_parent_state(self.view, block, &parent_state)?;

        self.seen.proposer_slots.insert(key);
        Ok(())
    }

    /// Validates a block of whichever fork it belongs to.
    ///
    /// This is the entry point for a block decoded before its topic was known.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn any_beacon_block(
        &mut self,
        signed: &combined::SignedBeaconBlock<P>,
        now_ms: u64,
    ) -> Verdict {
        match signed {
            combined::SignedBeaconBlock::Phase0(block) => {
                self.beacon_block::<phase0::BeaconState<P>>(block, now_ms)
            }
            combined::SignedBeaconBlock::Altair(block) => {
                self.beacon_block::<altair::BeaconState<P>>(block, now_ms)
            }
            combined::SignedBeaconBlock::Bellatrix(block) => {
                self.beacon_block::<bellatrix::BeaconState<P>>(block, now_ms)
            }
            combined::SignedBeaconBlock::Capella(block) => {
                self.beacon_block::<capella::BeaconState<P>>(block, now_ms)
            }
            combined::SignedBeaconBlock::Deneb(block) => {
                self.beacon_block::<deneb::BeaconState<P>>(block, now_ms)
            }
            combined::SignedBeaconBlock::Electra(block) => {
                self.beacon_block::<electra::BeaconState<P>>(block, now_ms)
            }
            combined::SignedBeaconBlock::Fulu(block) => {
                self.beacon_block::<fulu::BeaconState<P>>(block, now_ms)
            }
            combined::SignedBeaconBlock::Gloas(block) => {
                self.beacon_block::<gloas::BeaconState<P>>(block, now_ms)
            }
        }
    }

    /// Validates an aggregate of a fork, and its aggregator's proof of selection.
    ///
    /// See `validate_beacon_aggregate_and_proof_gossip` in the phase0 p2p spec.
    /// Deneb widens the time window, and Electra and Gloas give the data index new meanings.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn aggregate_and_proof<F: GossipFork<Preset = P>>(
        &mut self,
        signed: &F::SignedAggregateAndProof,
        now_ms: u64,
    ) -> Verdict {
        let aggregate = signed.aggregate();
        let data = aggregate.data();
        if let Some(reason) = F::VOTE_INDEX.aggregate_violation(data.index.0) {
            return Err(GossipError::reject(reason).with(Detail::Bound {
                value: data.index.0,
                bound: 1,
            }));
        }
        let index = aggregate.committee()?;
        let aggregator_index = signed.aggregator_index();
        let aggregator_detail = Detail::Validator(aggregator_index);

        let bits = aggregate.bits();
        let data_key = (data.target.epoch, data.hash_tree_root(), index);
        if self
            .seen
            .aggregate_data_roots
            .get(&data_key)
            .is_some_and(|seen| Seen::is_covered(seen, &bits))
        {
            return Err(GossipError::ignore("already seen aggregate for this data"));
        }
        let aggregator_key = (data.target.epoch, aggregator_index);
        if self.seen.aggregator_epochs.contains(&aggregator_key) {
            return Err(GossipError::ignore(
                "already seen aggregate for this epoch and aggregator",
            )
            .with(aggregator_detail));
        }
        self.voted_block_is_valid(data.beacon_block_root)?;

        let mut state = self.head_state()?;
        let committees = state.compute_committees(data.target.epoch);
        let index_out_of_range =
            GossipError::reject("committee index out of range").with(Detail::Bound {
                value: index.0,
                bound: committees.committees_per_slot(),
            });
        if index.0 >= committees.committees_per_slot() {
            return Err(index_out_of_range);
        }
        self.vote_is_timely::<F>(
            data,
            now_ms,
            "aggregate slot is from a future slot",
            "aggregate epoch is not current or previous epoch",
        )?;
        let committee = committees
            .committee(data.slot, index)
            .ok_or(index_out_of_range)?
            .to_vec();
        if bits.len() != committee.len() {
            return Err(GossipError::reject(
                "aggregation bits length does not match committee size",
            )
            .with(Detail::Mismatch {
                actual: bits.len() as u64,
                expected: committee.len() as u64,
            }));
        }
        let attesters: Vec<ValidatorIndex> = committee
            .iter()
            .zip(&bits)
            .filter(|(_, bit)| **bit)
            .map(|(validator, _)| *validator)
            .collect();
        if attesters.is_empty() {
            return Err(GossipError::reject("aggregate has no participants"));
        }
        // Threshold: about 16 aggregators per committee, picked by the hash of a slot signature.
        let modulo = (committee.len() as u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
        if !signed.selection_proof().selects(modulo) {
            return Err(
                GossipError::reject("validator is not selected as aggregator")
                    .with(aggregator_detail),
            );
        }
        if !committee.contains(&aggregator_index) {
            return Err(
                GossipError::reject("aggregator is not a member of the committee")
                    .with(aggregator_detail),
            );
        }
        Signers::of(state.beacon(), self.view.config()).verify_aggregator(signed)?;
        if !Signers::of(state.beacon(), self.view.config()).attested(
            attesters,
            data,
            aggregate.signature(),
        ) {
            return Err(GossipError::reject("invalid aggregate signature"));
        }
        self.vote_is_on_chain(data)?;
        if F::VOTE_INDEX == VoteIndex::PayloadPresence {
            self.view.vote_payload_is_consistent(data)?;
        }

        self.seen.aggregator_epochs.insert(aggregator_key);
        self.seen
            .aggregate_data_roots
            .entry(data_key)
            .or_default()
            .push(bits);
        Ok(())
    }

    /// Validates one validator's attestation of a fork on its subnet.
    ///
    /// See `validate_beacon_attestation_gossip` in the phase0 p2p spec.
    /// Deneb widens the time window, Electra names the attester, and Gloas reads the payload.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn beacon_attestation<F: GossipFork<Preset = P>>(
        &mut self,
        attestation: &F::SubnetAttestation,
        now_ms: u64,
        subnet: SubnetId,
    ) -> Verdict {
        let data = attestation.data();
        if let Some(reason) = F::VOTE_INDEX.attestation_violation(data.index.0) {
            return Err(GossipError::reject(reason).with(Detail::Bound {
                value: data.index.0,
                bound: 1,
            }));
        }
        self.voted_block_is_valid(data.beacon_block_root)?;

        let mut state = self.head_state()?;
        let committees = state.compute_committees(data.target.epoch);
        let per_slot = committees.committees_per_slot();
        let committee_index = attestation.committee_index();
        if committee_index.0 >= per_slot {
            return Err(
                GossipError::reject("committee index out of range").with(Detail::Bound {
                    value: committee_index.0,
                    bound: per_slot,
                }),
            );
        }
        // Subnets count committees from the start of the epoch, wrapping at the subnet count.
        let expected_subnet = (per_slot * data.slot.index_in_epoch::<P>() + committee_index.0)
            % self.view.config().attestation_subnet_count;
        if expected_subnet != subnet.0 {
            return Err(GossipError::reject("attestation is for wrong subnet").with(
                Detail::Mismatch {
                    actual: subnet.0,
                    expected: expected_subnet,
                },
            ));
        }
        self.vote_is_timely::<F>(
            data,
            now_ms,
            "attestation slot is from a future slot",
            "attestation epoch is not current or previous epoch",
        )?;
        let committee = committees
            .committee(data.slot, committee_index)
            .unwrap_or_default();
        let attester_index = attestation.attester(committee)?;
        let key = (data.target.epoch, attester_index);
        let attester_detail = Detail::Validator(attester_index);
        if self.seen.attestation_validator_epochs.contains(&key) {
            return Err(GossipError::ignore(
                "already seen attestation for this epoch and validator",
            )
            .with(attester_detail));
        }
        let signers = Signers::of(state.beacon(), self.view.config());
        if !signers.attested(vec![attester_index], data, attestation.signature()) {
            return Err(GossipError::reject("invalid attestation signature").with(attester_detail));
        }
        self.vote_is_on_chain(data)?;
        if F::VOTE_INDEX == VoteIndex::PayloadPresence {
            self.view.vote_payload_is_consistent(data)?;
        }

        self.seen.attestation_validator_epochs.insert(key);
        Ok(())
    }

    /// Validates a voluntary exit under a fork's rules.
    ///
    /// See `validate_voluntary_exit_gossip` in the phase0 p2p spec, amended by Deneb.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn voluntary_exit<F: GossipFork<Preset = P>>(
        &mut self,
        signed: &SignedVoluntaryExit,
        now_ms: u64,
    ) -> Verdict {
        let exit = &signed.message;
        let validator_detail = Detail::Validator(exit.validator_index);
        if self
            .seen
            .voluntary_exit_indices
            .contains(&exit.validator_index)
        {
            return Err(
                GossipError::ignore("already seen voluntary exit for this validator")
                    .with(validator_detail),
            );
        }
        if self.view.is_future_epoch(exit.epoch, now_ms) {
            return Err(
                GossipError::ignore("voluntary exit epoch is in the future").with(Detail::Epoch {
                    epoch: exit.epoch,
                    reference: self.view.current_slot(now_ms).epoch::<P>(),
                }),
            );
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        let validator =
            Self::registered(beacon, exit.validator_index, "validator index out of range")?;
        let epoch = beacon.current_epoch();
        if validator.exit_epoch != Epoch::FAR_FUTURE {
            return Err(
                GossipError::ignore("validator has already initiated exit").with(validator_detail)
            );
        }
        if !validator.is_active_at(epoch) {
            return Err(GossipError::reject("validator is not active").with(validator_detail));
        }
        let eligible = Epoch(
            validator
                .activation_epoch
                .0
                .saturating_add(self.view.config().shard_committee_period),
        );
        if epoch < eligible {
            return Err(
                GossipError::reject("validator has not been active long enough").with(
                    Detail::Epoch {
                        epoch,
                        reference: eligible,
                    },
                ),
            );
        }
        let domain = F::exit_domain(beacon, self.view.config(), exit.epoch);
        if !SigningClaim::new(exit, domain, &signed.signature).is_signed_by(&validator.pubkey) {
            return Err(
                GossipError::reject("invalid voluntary exit signature").with(validator_detail)
            );
        }
        self.seen
            .voluntary_exit_indices
            .insert(exit.validator_index);
        Ok(())
    }

    /// Validates a proposer slashing.
    ///
    /// See `validate_proposer_slashing_gossip` in the phase0 p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn proposer_slashing(&mut self, slashing: &ProposerSlashing) -> Verdict {
        let header_1 = &slashing.signed_header_1.message;
        let header_2 = &slashing.signed_header_2.message;
        let proposer_index = header_1.proposer_index;
        let proposer_detail = Detail::Validator(proposer_index);
        if self
            .seen
            .proposer_slashing_indices
            .contains(&proposer_index)
        {
            return Err(
                GossipError::ignore("already seen proposer slashing for this proposer")
                    .with(proposer_detail),
            );
        }
        if header_1.slot != header_2.slot {
            return Err(
                GossipError::reject("header slots do not match").with(Detail::Slot {
                    slot: header_2.slot,
                    reference: header_1.slot,
                }),
            );
        }
        if header_1.proposer_index != header_2.proposer_index {
            return Err(
                GossipError::reject("header proposer indices do not match").with(
                    Detail::Mismatch {
                        actual: header_2.proposer_index.0,
                        expected: proposer_index.0,
                    },
                ),
            );
        }
        if header_1 == header_2 {
            return Err(GossipError::reject("headers are not different").with(proposer_detail));
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        let proposer = Self::registered(beacon, proposer_index, "proposer index out of range")?;
        if !proposer.is_slashable_at(beacon.current_epoch()) {
            return Err(GossipError::reject("proposer is not slashable").with(proposer_detail));
        }
        for signed in [&slashing.signed_header_1, &slashing.signed_header_2] {
            let domain = self.domain(
                beacon,
                DOMAIN_BEACON_PROPOSER,
                signed.message.slot.epoch::<P>(),
            );
            if !SigningClaim::new(&signed.message, domain, &signed.signature)
                .is_signed_by(&proposer.pubkey)
            {
                return Err(GossipError::reject("invalid proposer slashing signature")
                    .with(proposer_detail));
            }
        }
        self.seen.proposer_slashing_indices.insert(proposer_index);
        Ok(())
    }

    /// Validates an attester slashing of any fork.
    ///
    /// See `validate_attester_slashing_gossip` in the phase0 p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn attester_slashing(&mut self, slashing: &impl SlashingEvidence) -> Verdict {
        let both = slashing.common_signers();
        let [first, second] = slashing.votes();
        if both
            .iter()
            .all(|index| self.seen.attester_slashing_indices.contains(index))
        {
            return Err(GossipError::ignore(
                "all attester slashing indices already seen",
            ));
        }
        if !first.data.is_slashable_with(second.data) {
            return Err(GossipError::reject("attestation data is not slashable"));
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        for (vote, out_of_range, invalid) in [
            (
                first,
                "validator index out of range in indexed attestation 1",
                "invalid indexed attestation 1",
            ),
            (
                second,
                "validator index out of range in indexed attestation 2",
                "invalid indexed attestation 2",
            ),
        ] {
            let count = beacon.validators().len() as u64;
            if let Some(index) = vote.indices.iter().find(|index| index.0 >= count) {
                return Err(GossipError::reject(out_of_range).with(Detail::Bound {
                    value: index.0,
                    bound: count,
                }));
            }
            if !Signers::of(state.beacon(), self.view.config()).is_valid_indexed_attestation(vote) {
                return Err(GossipError::reject(invalid));
            }
        }
        let epoch = beacon.current_epoch();
        if !both
            .iter()
            .any(|index| beacon.validators()[index.as_usize()].is_slashable_at(epoch))
        {
            return Err(GossipError::reject(
                "no slashable validators in intersection",
            ));
        }
        self.seen.attester_slashing_indices.extend(both);
        Ok(())
    }

    /// Validates a sync committee contribution and its aggregator's proof.
    ///
    /// See `validate_sync_committee_contribution_and_proof_gossip` in the Altair p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn sync_contribution(
        &mut self,
        signed: &SignedContributionAndProof<P>,
        now_ms: u64,
    ) -> Verdict {
        let message = &signed.message;
        let contribution = &message.contribution;
        let bits: Vec<bool> = contribution.aggregation_bits.iter().collect();
        let data_key = (
            contribution.slot,
            contribution.beacon_block_root,
            contribution.subcommittee_index,
        );
        if self
            .seen
            .sync_contribution_data
            .get(&data_key)
            .is_some_and(|seen| Seen::is_covered(seen, &bits))
        {
            return Err(GossipError::ignore(
                "already seen contribution for this data",
            ));
        }
        let aggregator_key = (
            contribution.slot,
            message.aggregator_index,
            contribution.subcommittee_index,
        );
        let aggregator_detail = Detail::Validator(message.aggregator_index);
        if self
            .seen
            .sync_contribution_aggregator_slots
            .contains(&aggregator_key)
        {
            return Err(
                GossipError::ignore("already seen contribution from this aggregator")
                    .with(aggregator_detail),
            );
        }
        self.contribution_is_well_formed(contribution, &bits, now_ms)?;
        // Threshold: about 16 aggregators per subcommittee.
        let modulo = (P::SYNC_COMMITTEE_SIZE
            / SYNC_COMMITTEE_SUBNET_COUNT
            / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
            .max(1);
        if !message.selection_proof.selects(modulo) {
            return Err(
                GossipError::reject("validator is not selected as aggregator")
                    .with(aggregator_detail),
            );
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        let aggregator = Self::registered(
            beacon,
            message.aggregator_index,
            "aggregator index out of range",
        )?;
        let subcommittee = Signers::of(state.beacon(), self.view.config())
            .sync_subcommittee(contribution.subcommittee_index);
        if !subcommittee.contains(&aggregator.pubkey) {
            return Err(
                GossipError::reject("aggregator is not a member of the committee")
                    .with(aggregator_detail),
            );
        }
        Signers::of(state.beacon(), self.view.config())
            .verify_contributor(&aggregator.pubkey, signed)?;
        let epoch = contribution.slot.epoch::<P>();
        let participants: Vec<BlsPubkey> = subcommittee
            .iter()
            .zip(&bits)
            .filter(|(_, bit)| **bit)
            .map(|(pubkey, _)| *pubkey)
            .collect();
        let sync_domain = self.domain(beacon, DOMAIN_SYNC_COMMITTEE, epoch);
        if !SigningClaim::new(
            &contribution.beacon_block_root,
            sync_domain,
            &contribution.signature,
        )
        .is_signed_by_all(&participants)
        {
            return Err(GossipError::reject("invalid aggregate signature"));
        }
        self.seen
            .sync_contribution_aggregator_slots
            .insert(aggregator_key);
        self.seen
            .sync_contribution_data
            .entry(data_key)
            .or_default()
            .push(bits);
        Ok(())
    }

    /// Validates one sync committee member's message on its subnet.
    ///
    /// See `validate_sync_committee_message_gossip` in the Altair p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn sync_committee_message(
        &mut self,
        message: &SyncCommitteeMessage,
        now_ms: u64,
        subnet: SubnetId,
    ) -> Verdict {
        let key = (message.slot, message.validator_index, subnet);
        let validator_detail = Detail::Validator(message.validator_index);
        if self.seen.sync_message_validator_slots.contains(&key) {
            return Err(GossipError::ignore(
                "already seen message from this validator for this slot and subnet",
            )
            .with(validator_detail));
        }
        if !self.view.is_within_slot_range(message.slot, 0, now_ms) {
            return Err(
                GossipError::ignore("message is not for the current slot").with(Detail::Slot {
                    slot: message.slot,
                    reference: self.view.current_slot(now_ms),
                }),
            );
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        let validator = Self::registered(
            beacon,
            message.validator_index,
            "validator index out of range",
        )?;
        // The subnet holds the subcommittees the validator sits in, by position in the committee.
        let size = (P::SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT) as usize;
        let in_subnet = Signers::of(state.beacon(), self.view.config())
            .sync_committee_for_next_slot()
            .iter()
            .enumerate()
            .any(|(position, pubkey)| {
                *pubkey == validator.pubkey && (position / size) as u64 == subnet.0
            });
        if !in_subnet {
            return Err(
                GossipError::reject("subnet_id is not valid for the validator")
                    .with(validator_detail),
            );
        }
        let domain = self.domain(beacon, DOMAIN_SYNC_COMMITTEE, message.slot.epoch::<P>());
        if !SigningClaim::new(&message.beacon_block_root, domain, &message.signature)
            .is_signed_by(&validator.pubkey)
        {
            return Err(
                GossipError::reject("invalid sync committee message signature")
                    .with(validator_detail),
            );
        }
        self.seen.sync_message_validator_slots.insert(key);
        Ok(())
    }

    /// Validates a withdrawal credential change.
    ///
    /// See `validate_bls_to_execution_change_gossip` in the Capella p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn bls_to_execution_change(
        &mut self,
        signed: &SignedBlsToExecutionChange,
        now_ms: u64,
    ) -> Verdict {
        let change = &signed.message;
        let validator_detail = Detail::Validator(change.validator_index);
        if self
            .seen
            .bls_to_execution_change_indices
            .contains(&change.validator_index)
        {
            return Err(GossipError::ignore(
                "already seen BLS to execution change for this validator",
            )
            .with(validator_detail));
        }
        let capella = self.view.config().capella_fork_epoch;
        if self.view.is_future_epoch(capella, now_ms) {
            return Err(
                GossipError::ignore("current epoch is pre-capella").with(Detail::Epoch {
                    epoch: self.view.current_slot(now_ms).epoch::<P>(),
                    reference: capella,
                }),
            );
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        let validator = Self::registered(
            beacon,
            change.validator_index,
            "validator index out of range",
        )?;
        let credentials = validator.withdrawal_credentials.0;
        if credentials[0] != BLS_WITHDRAWAL_PREFIX {
            return Err(
                GossipError::reject("validator does not have BLS withdrawal credentials")
                    .with(validator_detail),
            );
        }
        if credentials[1..] != Root::sha256(&change.from_bls_pubkey.0).0[1..] {
            return Err(GossipError::reject(
                "pubkey does not match validator withdrawal credentials",
            )
            .with(validator_detail));
        }
        let domain = Domain::compute(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            self.view.config().genesis_fork_version,
            beacon.genesis_validators_root(),
        );
        if !SigningClaim::new(change, domain, &signed.signature)
            .is_signed_by(&change.from_bls_pubkey)
        {
            return Err(
                GossipError::reject("invalid BLS to execution change signature")
                    .with(validator_detail),
            );
        }
        self.seen
            .bls_to_execution_change_indices
            .insert(change.validator_index);
        Ok(())
    }

    /// Validates a data column sidecar on its subnet, including its cell proofs.
    ///
    /// See `validate_data_column_sidecar_gossip` in the Fulu p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn data_column_sidecar(
        &mut self,
        sidecar: &DataColumnSidecar<P>,
        now_ms: u64,
        subnet: SubnetId,
        kzg: &Kzg,
    ) -> Verdict {
        let header = &sidecar.signed_block_header.message;
        let key = (header.slot, header.proposer_index, sidecar.index);
        let proposer_detail = Detail::Validator(header.proposer_index);
        if self.seen.data_column_sidecar_tuples.contains(&key) {
            return Err(GossipError::ignore(
                "already seen sidecar from this proposer for this slot and index",
            )
            .with(proposer_detail));
        }
        let checked = ColumnSidecar(sidecar);
        if let Err(error) = checked.verify_structure(self.view.config()) {
            return Err(GossipError::reject("invalid sidecar").with(Detail::Column(error)));
        }
        let expected_subnet = sidecar.index.0 % self.view.config().data_column_sidecar_subnet_count;
        if expected_subnet != subnet.0 {
            return Err(GossipError::reject("sidecar is for wrong subnet").with(
                Detail::Mismatch {
                    actual: subnet.0,
                    expected: expected_subnet,
                },
            ));
        }
        self.header_slot_is_timely(
            header.slot,
            now_ms,
            "sidecar is from a future slot",
            "sidecar is not from a slot greater than the latest finalized slot",
        )?;
        let parent_detail = Detail::Block(header.parent_root);
        let Some(parent) = self.view.block(&header.parent_root) else {
            return Err(
                GossipError::ignore("sidecar's parent has not been seen").with(parent_detail)
            );
        };
        if !self.view.is_imported(&header.parent_root) {
            return Err(
                GossipError::reject("sidecar's parent failed validation").with(parent_detail)
            );
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        let proposer =
            Self::registered(beacon, header.proposer_index, "proposer index out of range")?;
        let domain = self.domain(beacon, DOMAIN_BEACON_PROPOSER, header.slot.epoch::<P>());
        if !SigningClaim::new(header, domain, &sidecar.signed_block_header.signature)
            .is_signed_by(&proposer.pubkey)
        {
            return Err(
                GossipError::reject("invalid proposer signature on sidecar block header")
                    .with(proposer_detail),
            );
        }
        if header.slot <= parent.slot {
            return Err(
                GossipError::reject("sidecar is not from a higher slot than its parent").with(
                    Detail::Slot {
                        slot: header.slot,
                        reference: parent.slot,
                    },
                ),
            );
        }
        if !self.view.descends_from_finalized(header.parent_root) {
            return Err(GossipError::reject(
                "finalized checkpoint is not an ancestor of sidecar's block",
            )
            .with(parent_detail));
        }
        if let Err(error) = checked.verify_inclusion_proof() {
            return Err(
                GossipError::reject("invalid sidecar inclusion proof").with(Detail::Column(error))
            );
        }
        if let Err(error) = checked.verify_kzg_proofs(kzg) {
            return Err(
                GossipError::reject("invalid sidecar kzg proofs").with(Detail::Column(error))
            );
        }
        let parent_state = self.parent_state(&header.parent_root, header.slot)?;
        let expected_proposer = parent_state
            .beacon_proposer_index()
            .map_err(|_| GossipError::ignore("proposer shuffling is unavailable"))?;
        if header.proposer_index != expected_proposer {
            return Err(GossipError::reject(
                "sidecar proposer_index does not match expected proposer",
            )
            .with(Detail::Mismatch {
                actual: header.proposer_index.0,
                expected: expected_proposer.0,
            }));
        }
        self.seen.data_column_sidecar_tuples.insert(key);
        Ok(())
    }

    /// Validates a blob sidecar on its subnet, including its proofs.
    ///
    /// Deneb and Electra differ only in their limits, which the caller picks by fork.
    /// See `validate_blob_sidecar_gossip` in the Deneb and Electra p2p specs.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn blob_sidecar(
        &mut self,
        sidecar: &BlobSidecar<P>,
        now_ms: u64,
        subnet: SubnetId,
        limits: BlobSubnets,
        kzg: &Kzg,
    ) -> Verdict {
        let header = &sidecar.signed_block_header.message;
        let key = (header.slot, header.proposer_index, sidecar.index);
        let proposer_detail = Detail::Validator(header.proposer_index);
        if self.seen.blob_sidecar_tuples.contains(&key) {
            return Err(GossipError::ignore(
                "already seen blob sidecar from this proposer for this slot and index",
            )
            .with(proposer_detail));
        }
        if sidecar.index.0 >= limits.max_blobs {
            return Err(
                GossipError::reject("blob index out of range").with(Detail::Bound {
                    value: sidecar.index.0,
                    bound: limits.max_blobs,
                }),
            );
        }
        let expected_subnet = limits.subnet(sidecar.index);
        if expected_subnet != subnet.0 {
            return Err(
                GossipError::reject("blob sidecar is for wrong subnet").with(Detail::Mismatch {
                    actual: subnet.0,
                    expected: expected_subnet,
                }),
            );
        }
        self.header_slot_is_timely(
            header.slot,
            now_ms,
            "blob sidecar is from a future slot",
            "blob sidecar is not from a slot greater than the latest finalized slot",
        )?;
        let parent_detail = Detail::Block(header.parent_root);
        let Some(parent) = self.view.block(&header.parent_root) else {
            return Err(
                GossipError::ignore("blob sidecar's parent has not been seen").with(parent_detail),
            );
        };
        if !self.view.is_imported(&header.parent_root) {
            return Err(
                GossipError::reject("blob sidecar's parent failed validation").with(parent_detail),
            );
        }
        self.header_is_signed(
            &sidecar.signed_block_header.message,
            &sidecar.signed_block_header.signature,
            "invalid proposer signature on blob sidecar block header",
        )?;
        if header.slot <= parent.slot {
            return Err(GossipError::reject(
                "blob sidecar is not from a higher slot than its parent",
            )
            .with(Detail::Slot {
                slot: header.slot,
                reference: parent.slot,
            }));
        }
        if !self.view.descends_from_finalized(header.parent_root) {
            return Err(GossipError::reject(
                "finalized checkpoint is not an ancestor of blob sidecar's block",
            )
            .with(parent_detail));
        }
        let checked = CheckedBlob(sidecar);
        if !checked.has_valid_inclusion_proof() {
            return Err(GossipError::reject("invalid blob sidecar inclusion proof"));
        }
        if !checked.has_valid_kzg_proof(kzg) {
            return Err(GossipError::reject("invalid blob kzg proof"));
        }
        self.proposer_is_expected(
            header.parent_root,
            header.slot,
            header.proposer_index,
            "blob sidecar proposer_index does not match expected proposer",
        )?;
        self.seen.blob_sidecar_tuples.insert(key);
        Ok(())
    }

    /// Validates a partial data column: a header for a block, some cells of one column, or both.
    ///
    /// A validated header is remembered for its block, so later cells on any column can use it.
    /// See `validate_partial_data_column_sidecar_gossip` in the Fulu partial columns spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn partial_data_column_sidecar(
        &mut self,
        sidecar: &PartialDataColumnSidecar<P>,
        now_ms: u64,
        group: &PartialDataColumnGroupId,
        column: ColumnIndex,
        kzg: &Kzg,
    ) -> Verdict {
        let present: Vec<bool> = sidecar.cells_present_bitmap.iter().collect();
        let cells = PartialCells::<P> {
            present: &present,
            cells: &sidecar.partial_column,
            proofs: &sidecar.kzg_proofs,
        };
        let header = sidecar.header.first();
        cells.is_well_formed(header.is_some())?;
        let block_root = group.beacon_block_root;
        if let Some(header) = header {
            self.partial_header(header, now_ms, block_root)?;
        }
        if cells.announced() == 0 {
            return Ok(());
        }
        let Some(header) = self
            .seen
            .partial_data_column_headers
            .get(&block_root)
            .cloned()
        else {
            return Err(
                GossipError::ignore("valid corresponding header has not been seen")
                    .with(Detail::Block(block_root)),
            );
        };
        self.header_slot_is_timely(
            header.slot,
            now_ms,
            "corresponding header is from a future slot",
            "corresponding header is not from a slot greater than the latest finalized slot",
        )?;
        cells.match_commitments(header.commitments.len())?;
        if !cells.have_valid_kzg_proofs(&header.commitments, column, kzg) {
            return Err(GossipError::reject("invalid sidecar kzg proofs"));
        }
        Ok(())
    }

    /// Validates the header of a partial column message, and remembers it once valid.
    fn partial_header(
        &mut self,
        header: &PartialDataColumnHeader<P>,
        now_ms: u64,
        block_root: Root,
    ) -> Verdict {
        let checked = PartialHeader(header);
        let block_header = &header.signed_block_header.message;
        let detail = Detail::Block(block_root);
        if self
            .seen
            .partial_data_column_headers
            .get(&block_root)
            .is_some_and(|prior| prior.root != header.hash_tree_root())
        {
            return Err(
                GossipError::reject("header differs from previously validated header").with(detail),
            );
        }
        if block_header.hash_tree_root() != block_root {
            return Err(GossipError::reject(
                "header's block root does not match group id's block root",
            )
            .with(detail));
        }
        if header.kzg_commitments.is_empty() {
            return Err(GossipError::reject("header's kzg_commitments is empty").with(detail));
        }
        self.header_slot_is_timely(
            block_header.slot,
            now_ms,
            "header is from a future slot",
            "header is not from a slot greater than the latest finalized slot",
        )?;
        let parent_detail = Detail::Block(block_header.parent_root);
        let Some(parent) = self.view.block(&block_header.parent_root) else {
            return Err(
                GossipError::ignore("header's parent has not been seen").with(parent_detail)
            );
        };
        if !self.view.is_imported(&block_header.parent_root) {
            return Err(
                GossipError::reject("header's parent failed validation").with(parent_detail)
            );
        }
        self.header_is_signed(
            block_header,
            &header.signed_block_header.signature,
            "invalid proposer signature on header",
        )?;
        if block_header.slot <= parent.slot {
            return Err(
                GossipError::reject("header is not from a higher slot than its parent").with(
                    Detail::Slot {
                        slot: block_header.slot,
                        reference: parent.slot,
                    },
                ),
            );
        }
        if !self.view.descends_from_finalized(block_header.parent_root) {
            return Err(GossipError::reject(
                "finalized checkpoint is not an ancestor of header's block",
            )
            .with(parent_detail));
        }
        if !checked.has_valid_inclusion_proof() {
            return Err(GossipError::reject("invalid header inclusion proof").with(detail));
        }
        self.proposer_is_expected(
            block_header.parent_root,
            block_header.slot,
            block_header.proposer_index,
            "header proposer_index does not match expected proposer",
        )?;
        self.seen
            .partial_data_column_headers
            .insert(block_root, SeenPartialHeader::of(header));
        Ok(())
    }

    /// Checks a block header's proposer signature against the head state.
    ///
    /// The reason words the rule for the message carrying the header.
    fn header_is_signed(
        &mut self,
        header: &BeaconBlockHeader,
        signature: &BlsSignature,
        reason: &'static str,
    ) -> Verdict {
        let state = self.head_state()?;
        let beacon = state.beacon();
        let proposer =
            Self::registered(beacon, header.proposer_index, "proposer index out of range")?;
        let domain = self.domain(beacon, DOMAIN_BEACON_PROPOSER, header.slot.epoch::<P>());
        if !SigningClaim::new(header, domain, signature).is_signed_by(&proposer.pubkey) {
            return Err(GossipError::reject(reason).with(Detail::Validator(header.proposer_index)));
        }
        Ok(())
    }

    /// Checks that a proposer is the one the parent's state expects at a slot.
    ///
    /// When the shuffling cannot be computed, the spec says to ignore rather than reject.
    fn proposer_is_expected(
        &self,
        parent: Root,
        slot: Slot,
        proposer: ValidatorIndex,
        reason: &'static str,
    ) -> Verdict {
        let parent_state = self.parent_state(&parent, slot)?;
        let expected = parent_state
            .beacon_proposer_index()
            .map_err(|_| GossipError::ignore("proposer shuffling is unavailable"))?;
        if proposer != expected {
            return Err(GossipError::reject(reason).with(Detail::Mismatch {
                actual: proposer.0,
                expected: expected.0,
            }));
        }
        Ok(())
    }

    /// Validates a Gloas data column sidecar, whose commitments sit in its block's bid.
    ///
    /// See `validate_data_column_sidecar_gossip` in the Gloas p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn gloas_data_column_sidecar(
        &mut self,
        sidecar: &gloas::DataColumnSidecar<P>,
        now_ms: u64,
        subnet: SubnetId,
        kzg: &Kzg,
    ) -> Verdict {
        let root = sidecar.beacon_block_root;
        let key = (root, sidecar.index);
        if self.seen.data_column_sidecar_roots.contains(&key) {
            return Err(
                GossipError::ignore("already seen sidecar for this block root and index")
                    .with(Detail::Block(root)),
            );
        }
        let expected_subnet = sidecar.index.0 % self.view.config().data_column_sidecar_subnet_count;
        if expected_subnet != subnet.0 {
            return Err(GossipError::reject("sidecar is for wrong subnet").with(
                Detail::Mismatch {
                    actual: subnet.0,
                    expected: expected_subnet,
                },
            ));
        }
        if self.view.is_future_slot(sidecar.slot, now_ms) {
            return Err(
                GossipError::ignore("sidecar is from a future slot").with(Detail::Slot {
                    slot: sidecar.slot,
                    reference: self.view.current_slot(now_ms),
                }),
            );
        }
        let (block, bid) = self.bid_block(
            root,
            "block for sidecar's beacon block root has not been seen",
            "block for sidecar's beacon block root failed validation",
        )?;
        if sidecar.slot != block.slot {
            return Err(
                GossipError::reject("sidecar's slot does not match block's slot").with(
                    Detail::Slot {
                        slot: sidecar.slot,
                        reference: block.slot,
                    },
                ),
            );
        }
        let present = vec![true; sidecar.column.len()];
        let cells = PartialCells::<P> {
            present: &present,
            cells: &sidecar.column,
            proofs: &sidecar.kzg_proofs,
        };
        let commitments = &bid.blob_kzg_commitments;
        // See verify_data_column_sidecar in the Gloas p2p spec.
        if sidecar.index.0 >= P::NUMBER_OF_COLUMNS
            || sidecar.column.is_empty()
            || sidecar.column.len() != commitments.len()
            || sidecar.column.len() != sidecar.kzg_proofs.len()
        {
            return Err(
                GossipError::reject("invalid sidecar").with(Detail::Mismatch {
                    actual: sidecar.column.len() as u64,
                    expected: commitments.len() as u64,
                }),
            );
        }
        if !cells.have_valid_kzg_proofs(commitments, sidecar.index, kzg) {
            return Err(GossipError::reject("invalid sidecar kzg proofs").with(Detail::Block(root)));
        }
        self.seen.data_column_sidecar_roots.insert(key);
        Ok(())
    }

    /// Validates some cells of one Gloas column, checked against their block's bid.
    ///
    /// Gloas dropped the partial header: the block's bid names the blobs.
    /// See `validate_partial_data_column_sidecar_gossip` in the Gloas partial columns spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn gloas_partial_data_column_sidecar(
        &self,
        sidecar: &gloas::PartialDataColumnSidecar<P>,
        group: &gloas::PartialDataColumnGroupId,
        column: ColumnIndex,
        kzg: &Kzg,
    ) -> Verdict {
        let present: Vec<bool> = sidecar.cells_present_bitmap.iter().collect();
        let cells = PartialCells::<P> {
            present: &present,
            cells: &sidecar.partial_column,
            proofs: &sidecar.kzg_proofs,
        };
        cells.is_well_formed(false)?;
        let (block, bid) = self.bid_block(
            group.beacon_block_root,
            "group id's block has not been seen",
            "group id's block failed validation",
        )?;
        if group.slot != block.slot {
            return Err(
                GossipError::reject("group id's slot does not match the block's slot").with(
                    Detail::Slot {
                        slot: group.slot,
                        reference: block.slot,
                    },
                ),
            );
        }
        cells.match_commitments(bid.blob_kzg_commitments.len())?;
        if !cells.have_valid_kzg_proofs(&bid.blob_kzg_commitments, column, kzg) {
            return Err(GossipError::reject("invalid sidecar kzg proofs")
                .with(Detail::Block(group.beacon_block_root)));
        }
        Ok(())
    }

    /// Validates an execution payload envelope against its block's bid.
    ///
    /// See `validate_execution_payload_envelope_gossip` in the Gloas p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn execution_payload_envelope(
        &mut self,
        signed: &SignedExecutionPayloadEnvelope<P>,
    ) -> Verdict {
        let envelope = &signed.message;
        let payload = &envelope.payload;
        let root = envelope.beacon_block_root;
        let key = (root, envelope.builder_index);
        if self.seen.execution_payload_envelopes.contains(&key) {
            return Err(GossipError::ignore(
                "already seen envelope for this block root from this builder",
            )
            .with(Detail::Block(root)));
        }
        let (block, bid) = self.bid_block(
            root,
            "envelope's block has not been seen",
            "envelope's block failed validation",
        )?;
        let finalized_slot = self.view.finalized.epoch.start_slot::<P>();
        if payload.slot_number < finalized_slot.0 {
            return Err(GossipError::ignore(
                "envelope is from a slot before the latest finalized slot",
            )
            .with(Detail::Slot {
                slot: Slot(payload.slot_number),
                reference: finalized_slot,
            }));
        }
        if block.slot.0 != payload.slot_number {
            return Err(
                GossipError::reject("block's slot does not match payload's slot number").with(
                    Detail::Mismatch {
                        actual: payload.slot_number,
                        expected: block.slot.0,
                    },
                ),
            );
        }
        if envelope.builder_index != bid.builder_index {
            return Err(GossipError::reject(
                "envelope's builder index does not match the bid's builder index",
            )
            .with(Detail::Mismatch {
                actual: envelope.builder_index.0,
                expected: bid.builder_index.0,
            }));
        }
        if payload.block_hash != bid.block_hash {
            return Err(GossipError::reject(
                "payload's block hash does not match the bid's block hash",
            )
            .with(Detail::Block(root)));
        }
        if envelope.execution_requests.hash_tree_root() != bid.execution_requests_root {
            return Err(GossipError::reject(
                "envelope's execution requests root does not match the bid's",
            )
            .with(Detail::Block(root)));
        }
        ExecutionRequestLimits(&envelope.execution_requests).check::<P>()?;
        Bounded::new(
            payload.withdrawals.len(),
            P::MAX_WITHDRAWALS_PER_PAYLOAD,
            "too many withdrawals",
        )
        .check()?;
        // The block's own post-state names the proposer and the builders that may sign.
        let state = self.view.store.block_state(&root).cloned().ok_or_else(|| {
            GossipError::ignore("envelope's block state is unavailable").with(Detail::Block(root))
        })?;
        let gloas = Self::gloas_state(&state)?;
        let pubkey = if envelope.builder_index == BUILDER_INDEX_SELF_BUILD {
            let proposer = gloas.latest_block_header.proposer_index;
            gloas
                .validators
                .get(proposer.as_usize())
                .map(|validator| validator.pubkey)
        } else {
            gloas
                .builders
                .get(envelope.builder_index.as_usize())
                .map(|builder| builder.pubkey)
        };
        let domain = gloas.domain(DOMAIN_BEACON_BUILDER, gloas.current_epoch());
        if !pubkey.is_some_and(|pubkey| {
            SigningClaim::new(envelope, domain, &signed.signature).is_signed_by(&pubkey)
        }) {
            return Err(GossipError::reject("invalid envelope signature").with(Detail::Block(root)));
        }
        self.seen.execution_payload_envelopes.insert(key);
        self.seen
            .execution_payloads
            .insert(payload.block_hash, payload.gas_limit);
        Ok(())
    }

    /// Validates a payload timeliness committee member's vote on its slot's payload.
    ///
    /// See `validate_payload_attestation_message_gossip` in the Gloas p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn payload_attestation_message(
        &mut self,
        message: &PayloadAttestationMessage,
        now_ms: u64,
    ) -> Verdict {
        let data = &message.data;
        let validator_detail = Detail::Validator(message.validator_index);
        let gloas_epoch = self.view.config().gloas_fork_epoch;
        if data.slot.epoch::<P>() < gloas_epoch {
            return Err(
                GossipError::reject("payload attestation's slot is pre-gloas").with(
                    Detail::Epoch {
                        epoch: data.slot.epoch::<P>(),
                        reference: gloas_epoch,
                    },
                ),
            );
        }
        let key = (data.slot, message.validator_index);
        if self.seen.payload_attestation_validators.contains(&key) {
            return Err(GossipError::ignore(
                "already seen payload attestation from this validator",
            )
            .with(validator_detail));
        }
        if !self.view.is_current_slot(data.slot, now_ms) {
            return Err(
                GossipError::ignore("payload attestation is not for the current slot").with(
                    Detail::Slot {
                        slot: data.slot,
                        reference: self.view.current_slot(now_ms),
                    },
                ),
            );
        }
        let root = data.beacon_block_root;
        let Some(block) = self.view.block(&root) else {
            return Err(
                GossipError::ignore("payload attestation's block has not been seen")
                    .with(Detail::Block(root)),
            );
        };
        if !self.view.is_imported(&root) {
            return Err(
                GossipError::reject("payload attestation's block failed validation")
                    .with(Detail::Block(root)),
            );
        }
        if block.slot != data.slot {
            return Err(GossipError::ignore(
                "payload attestation's block is not at the assigned slot",
            )
            .with(Detail::Slot {
                slot: block.slot,
                reference: data.slot,
            }));
        }
        let state = self.head_state()?;
        let gloas = Self::gloas_state(&state)?;
        let validator = Self::registered(
            state.beacon(),
            message.validator_index,
            "validator index out of range",
        )?;
        if !Ptc::of(gloas, data.slot).contains(&message.validator_index) {
            return Err(GossipError::reject(
                "validator is not in the payload timeliness committee",
            )
            .with(validator_detail));
        }
        let domain = gloas.domain(DOMAIN_PTC_ATTESTER, data.slot.epoch::<P>());
        if !SigningClaim::new(data, domain, &message.signature).is_signed_by(&validator.pubkey) {
            return Err(
                GossipError::reject("invalid payload attestation signature").with(validator_detail)
            );
        }
        self.seen.payload_attestation_validators.insert(key);
        Ok(())
    }

    /// Validates a builder's bid for a slot's payload.
    ///
    /// See `validate_execution_payload_bid_gossip` in the Gloas p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn execution_payload_bid(
        &mut self,
        signed: &SignedExecutionPayloadBid,
        now_ms: u64,
    ) -> Verdict {
        let bid = &signed.message;
        let builder_detail = Detail::Builder(bid.builder_index);
        let bid_key = (
            bid.slot,
            bid.parent_block_hash,
            bid.parent_block_root,
            bid.builder_index,
        );
        if self.seen.execution_payload_bids.contains(&bid_key) {
            return Err(GossipError::ignore(
                "already seen valid bid for this slot, parent, and builder",
            ));
        }
        let best_key = (bid.slot, bid.parent_block_hash, bid.parent_block_root);
        if let Some(best) = self.seen.best_execution_payload_bid.get(&best_key)
            && bid.value <= *best
        {
            return Err(GossipError::ignore(
                "bid is not the highest value bid seen for this slot and parent",
            )
            .with(Detail::Bound {
                value: bid.value.0,
                bound: best.0,
            }));
        }
        self.bid_is_well_formed(bid, now_ms)?;
        let parent_root = bid.parent_block_root;
        let Some(parent) = self.view.block(&parent_root) else {
            return Err(
                GossipError::ignore("bid's parent block root is not a known beacon block")
                    .with(Detail::Block(parent_root)),
            );
        };
        if bid.slot <= parent.slot {
            return Err(
                GossipError::reject("bid's slot is not higher than its parent's slot").with(
                    Detail::Slot {
                        slot: bid.slot,
                        reference: parent.slot,
                    },
                ),
            );
        }
        let state = self
            .view
            .store
            .block_state(&parent_root)
            .cloned()
            .ok_or_else(|| {
                GossipError::ignore("bid's parent block post-state is unavailable")
                    .with(Detail::Block(parent_root))
            })?;
        let proposal_epoch = bid.slot.epoch::<P>();
        let state_epoch = state.beacon().current_epoch();
        if proposal_epoch > state_epoch + P::MIN_SEED_LOOKAHEAD {
            return Err(
                GossipError::ignore("bid's slot is past the parent's proposer lookahead").with(
                    Detail::Epoch {
                        epoch: proposal_epoch,
                        reference: state_epoch,
                    },
                ),
            );
        }
        self.bid_matches_preferences(bid)?;
        if !self.bid_is_compatible_with_head(bid)? {
            return Err(GossipError::ignore(
                "bid is not compatible with the current head branch",
            ));
        }
        if bid.prev_randao != state.beacon().randao_mix(state_epoch) {
            return Err(GossipError::reject("bid's previous randao is incorrect"));
        }
        let advanced = self.parent_state(&parent_root, bid.slot)?;
        let gloas = Self::gloas_state(&advanced)?;
        let builder = self.bid_builder(bid, gloas)?;
        let domain = gloas.domain(DOMAIN_BEACON_BUILDER, gloas.current_epoch());
        if !SigningClaim::new(bid, domain, &signed.signature).is_signed_by(&builder.pubkey) {
            return Err(GossipError::reject("invalid bid signature").with(builder_detail));
        }
        self.seen.execution_payload_bids.insert(bid_key);
        self.seen
            .best_execution_payload_bid
            .insert(best_key, bid.value);
        Ok(())
    }

    /// Validates a proposer's preferences for a slot it will propose.
    ///
    /// See `validate_proposer_preferences_gossip` in the Gloas p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn proposer_preferences(
        &mut self,
        signed: &SignedProposerPreferences,
        now_ms: u64,
    ) -> Verdict {
        let preferences = &signed.message;
        let slot = preferences.proposal_slot;
        let dependent_root = preferences.dependent_root;
        let key = (slot, dependent_root);
        if self.seen.proposer_preferences.contains_key(&key) {
            return Err(GossipError::ignore(
                "already seen preferences for this dependent root and proposal slot",
            ));
        }
        let proposal_epoch = slot.epoch::<P>();
        let gloas_epoch = self.view.config().gloas_fork_epoch;
        if proposal_epoch < gloas_epoch {
            return Err(
                GossipError::ignore("proposal epoch is pre-gloas").with(Detail::Epoch {
                    epoch: proposal_epoch,
                    reference: gloas_epoch,
                }),
            );
        }
        if self.view.is_past_slot(slot, now_ms) {
            return Err(
                GossipError::ignore("proposal slot has already started").with(Detail::Slot {
                    slot,
                    reference: self.view.current_slot(now_ms),
                }),
            );
        }
        // See compute_shuffling_lookahead_start_slot in the phase0 fork choice spec.
        let lookahead_start = proposal_epoch
            .saturating_sub(P::MIN_SEED_LOOKAHEAD)
            .start_slot::<P>();
        if self.view.is_future_slot(lookahead_start, now_ms) {
            return Err(
                GossipError::ignore("proposer for the proposal slot is not yet known").with(
                    Detail::Slot {
                        slot: lookahead_start,
                        reference: self.view.current_slot(now_ms),
                    },
                ),
            );
        }
        self.dependent_block_is_possible(dependent_root, lookahead_start)?;
        let state = self
            .view
            .state_at(&dependent_root, lookahead_start)
            .map_err(|error| {
                GossipError::ignore("dependent block's state is unavailable")
                    .with(Self::missing_block(&error))
            })?;
        let validator_detail = Detail::Validator(preferences.validator_index);
        let lookahead = &Self::gloas_state(&state)?.proposer_lookahead;
        let index = (slot.0 - lookahead_start.0) as usize;
        if lookahead.get(index) != Some(&preferences.validator_index) {
            return Err(
                GossipError::reject("validator is not the proposer for the given slot")
                    .with(validator_detail),
            );
        }
        let beacon = state.beacon();
        let validator = Self::registered(
            beacon,
            preferences.validator_index,
            "validator is not the proposer for the given slot",
        )?;
        let domain = Domain::compute(
            DOMAIN_PROPOSER_PREFERENCES,
            self.view.config().fork_version_at(proposal_epoch),
            beacon.genesis_validators_root(),
        );
        if !SigningClaim::new(preferences, domain, &signed.signature)
            .is_signed_by(&validator.pubkey)
        {
            return Err(
                GossipError::reject("invalid proposer preferences signature")
                    .with(validator_detail),
            );
        }
        self.seen.proposer_preferences.insert(key, signed.clone());
        Ok(())
    }

    /// The builder behind a bid, checked able and willing to pay it.
    fn bid_builder<'s>(
        &self,
        bid: &ExecutionPayloadBid,
        state: &'s gloas::BeaconState<P>,
    ) -> Result<&'s Builder, GossipError> {
        let builder_detail = Detail::Builder(bid.builder_index);
        let builder = state
            .builders
            .get(bid.builder_index.as_usize())
            .ok_or_else(|| {
                GossipError::reject("builder index out of range").with(Detail::Bound {
                    value: bid.builder_index.0,
                    bound: state.builders.len() as u64,
                })
            })?;
        if builder.version != PAYLOAD_BUILDER_VERSION {
            return Err(
                GossipError::reject("builder is not a payload builder").with(builder_detail)
            );
        }
        // Activity reads the finality of the state advanced to the bid's slot, not the store's.
        // Advancing across an epoch boundary can finalize the builder's deposit epoch.
        // See is_active_builder in the Gloas beacon chain spec.
        let finalized = self
            .view
            .state_finality
            .unwrap_or(state.finalized_checkpoint)
            .epoch;
        if !(builder.deposit_epoch < finalized && builder.withdrawable_epoch == Epoch::FAR_FUTURE) {
            return Err(GossipError::reject("builder is not active").with(builder_detail));
        }
        if !BuilderFunds::of(state, bid.builder_index).cover::<P>(bid.value) {
            return Err(GossipError::ignore("builder cannot cover bid value").with(builder_detail));
        }
        // The parent payload may carry the builder's exit, which would leave the bid unpaid.
        let owner = (builder.pubkey, builder.execution_address);
        if bid.parent_block_hash == state.latest_execution_payload_bid.block_hash
            && let Some(envelope) = self.view.payloads.get(&bid.parent_block_root)
            && envelope
                .execution_requests
                .builder_exits
                .iter()
                .any(|request| (request.pubkey, request.source_address) == owner)
        {
            return Err(GossipError::ignore("builder may exit").with(builder_detail));
        }
        Ok(builder)
    }

    /// Checks a bid's own fields: its timing, payment, hashes, and blob count.
    fn bid_is_well_formed(&self, bid: &ExecutionPayloadBid, now_ms: u64) -> Verdict {
        // See is_current_or_next_slot in the Gloas p2p spec.
        let next_slot = bid.slot.0.checked_sub(1).map(Slot);
        if !self.view.is_current_slot(bid.slot, now_ms)
            && !next_slot.is_some_and(|slot| self.view.is_current_slot(slot, now_ms))
        {
            return Err(
                GossipError::ignore("bid's slot is not the current or next slot").with(
                    Detail::Slot {
                        slot: bid.slot,
                        reference: self.view.current_slot(now_ms),
                    },
                ),
            );
        }
        if bid.execution_payment != Gwei(0) {
            return Err(
                GossipError::reject("bid's execution payment must be zero").with(
                    Detail::Mismatch {
                        actual: bid.execution_payment.0,
                        expected: 0,
                    },
                ),
            );
        }
        if bid.block_hash == bid.parent_block_hash {
            return Err(GossipError::reject(
                "bid's block hash equals its parent block hash",
            ));
        }
        let max_blobs = self
            .view
            .config()
            .blob_parameters(bid.slot.epoch::<P>())
            .max_blobs_per_block;
        Bounded::new(
            bid.blob_kzg_commitments.len(),
            max_blobs,
            "too many blob kzg commitments",
        )
        .check()
    }

    /// Checks a bid against the preferences its proposer gossiped, and its parent payload.
    fn bid_matches_preferences(&self, bid: &ExecutionPayloadBid) -> Verdict {
        let dependent_root = self
            .view
            .shuffling_dependent_root(bid.parent_block_root, bid.slot.epoch::<P>());
        let Some(preferences) = self
            .seen
            .proposer_preferences
            .get(&(bid.slot, dependent_root))
            .map(|signed| &signed.message)
        else {
            return Err(
                GossipError::ignore("matching proposer preferences have not been seen")
                    .with(Detail::Block(dependent_root)),
            );
        };
        if bid.fee_recipient != preferences.fee_recipient {
            return Err(GossipError::ignore(
                "bid's fee recipient does not match the proposer's preference",
            ));
        }
        let Some(parent_gas_limit) = self.seen.execution_payloads.get(&bid.parent_block_hash)
        else {
            return Err(GossipError::ignore(
                "bid's parent block hash is not a known execution payload",
            ));
        };
        if !GasTarget::new(*parent_gas_limit, preferences.target_gas_limit).allows(bid.gas_limit) {
            return Err(GossipError::ignore(
                "bid's gas limit is not compatible with the proposer's target",
            )
            .with(Detail::Mismatch {
                actual: bid.gas_limit,
                expected: preferences.target_gas_limit,
            }));
        }
        Ok(())
    }

    /// Whether a bid builds where the head says the next block goes.
    ///
    /// See `is_bid_compatible_with_head` in the Gloas p2p spec.
    fn bid_is_compatible_with_head(
        &mut self,
        bid: &ExecutionPayloadBid,
    ) -> Result<bool, GossipError> {
        let store = &mut *self.view.store;
        let head = store.head().map_err(|error| {
            GossipError::ignore("head state is unavailable").with(Self::missing_block(&error))
        })?;
        // The store holds the head, and the head block's node carries its bid's hashes.
        let Some(head_block) = store.blocks().get(&head.root).copied() else {
            return Ok(false);
        };
        let builds_on_parent_block = bid.parent_block_root == head_block.parent_root;
        let builds_on_parent_payload = bid.parent_block_hash == head_block.parent_block_hash;
        if builds_on_parent_block && builds_on_parent_payload {
            return Ok(true);
        }
        if bid.parent_block_root != head.root {
            return Ok(false);
        }
        let on_full = store
            .should_build_on_full(head, bid.slot)
            .map_err(|error| {
                GossipError::ignore("head block is unknown").with(Self::missing_block(&error))
            })?;
        if on_full {
            Ok(bid.parent_block_hash == head_block.execution_block_hash)
        } else {
            Ok(builds_on_parent_payload)
        }
    }

    /// Checks that a dependent block is known, valid, and can fix the shuffling of a lookahead.
    fn dependent_block_is_possible(&mut self, root: Root, lookahead_start: Slot) -> Verdict {
        let detail = Detail::Block(root);
        let Some(dependent) = self.view.block(&root) else {
            return Err(GossipError::ignore("dependent block has not been seen").with(detail));
        };
        if !self.view.is_imported(&root) {
            return Err(GossipError::ignore("dependent block failed validation").with(detail));
        }
        // See compute_shuffling_dependent_slot in the phase0 fork choice spec.
        let dependent_slot = lookahead_start.saturating_sub(1);
        if dependent.slot > dependent_slot {
            return Err(GossipError::reject(
                "dependent block is after the shuffling dependent slot",
            )
            .with(Detail::Slot {
                slot: dependent.slot,
                reference: dependent_slot,
            }));
        }
        if !self.is_valid_dependent_root(root, dependent_slot)? {
            return Err(
                GossipError::ignore("dependent block is not a possible dependent block")
                    .with(detail),
            );
        }
        Ok(())
    }

    /// Whether a block may be the last before a slot on some branch, now or later.
    ///
    /// See `is_valid_dependent_root` in the Gloas fork choice spec.
    fn is_valid_dependent_root(&mut self, root: Root, slot: Slot) -> Result<bool, GossipError> {
        let head = self.view.store.head().map_err(|error| {
            GossipError::ignore("head state is unavailable").with(Self::missing_block(&error))
        })?;
        if head.root == root {
            return Ok(true);
        }
        let store_children = self.view.store.blocks().children(&root).iter().copied();
        let unimported_children = self
            .view
            .unimported
            .iter()
            .filter(|(_, node)| node.parent_root == root)
            .map(|(child, _)| *child);
        Ok(store_children
            .chain(unimported_children)
            .any(|child| self.view.block(&child).is_some_and(|node| node.slot > slot)))
    }

    /// A seen block with a post-state, and the bid it carries.
    ///
    /// The reasons word the rules for the message naming the block.
    fn bid_block(
        &self,
        root: Root,
        unseen_reason: &'static str,
        failed_reason: &'static str,
    ) -> Result<(BlockNode, &ExecutionPayloadBid), GossipError> {
        let detail = Detail::Block(root);
        let Some(block) = self.view.block(&root) else {
            return Err(GossipError::ignore(unseen_reason).with(detail));
        };
        if !self.view.is_imported(&root) {
            return Err(GossipError::reject(failed_reason).with(detail));
        }
        let bid = self
            .view
            .bids
            .get(&root)
            .ok_or_else(|| GossipError::ignore("block's bid is unknown").with(detail))?;
        Ok((block, bid))
    }

    /// The Gloas state inside a state of any fork.
    fn gloas_state(state: &State<P>) -> Result<&gloas::BeaconState<P>, GossipError> {
        gloas::BeaconState::from_any(state.beacon())
            .ok_or_else(|| GossipError::ignore("state is not a Gloas state"))
    }

    /// Checks that a block header's slot has started and comes after finality.
    ///
    /// The reasons word the two rules for the message, a block or a sidecar.
    fn header_slot_is_timely(
        &self,
        slot: Slot,
        now_ms: u64,
        future_reason: &'static str,
        finalized_reason: &'static str,
    ) -> Verdict {
        if self.view.is_future_slot(slot, now_ms) {
            return Err(GossipError::ignore(future_reason).with(Detail::Slot {
                slot,
                reference: self.view.current_slot(now_ms),
            }));
        }
        let finalized_slot = self.view.finalized.epoch.start_slot::<P>();
        if slot <= finalized_slot {
            return Err(GossipError::ignore(finalized_reason).with(Detail::Slot {
                slot,
                reference: finalized_slot,
            }));
        }
        Ok(())
    }

    /// Checks that a vote is within its fork's propagation window and lies in its target epoch.
    ///
    /// The reasons word the Deneb rules for the message, an aggregate or an attestation.
    fn vote_is_timely<F: GossipFork<Preset = P>>(
        &self,
        data: &AttestationData,
        now_ms: u64,
        future_reason: &'static str,
        epoch_reason: &'static str,
    ) -> Verdict {
        let current = self.view.current_slot(now_ms);
        match F::VOTE_WINDOW {
            VoteWindow::SlotRange => {
                let range = self.view.config().attestation_propagation_slot_range;
                if !self.view.is_within_slot_range(data.slot, range, now_ms) {
                    return Err(GossipError::ignore(
                        "attestation slot not within propagation range",
                    )
                    .with(Detail::Slot {
                        slot: data.slot,
                        reference: current,
                    }));
                }
            }
            VoteWindow::CurrentOrPreviousEpoch => {
                if self.view.is_future_slot(data.slot, now_ms) {
                    return Err(GossipError::ignore(future_reason).with(Detail::Slot {
                        slot: data.slot,
                        reference: current,
                    }));
                }
                let epoch = data.slot.epoch::<P>();
                if !self.view.is_current_or_previous_epoch(epoch, now_ms) {
                    return Err(GossipError::ignore(epoch_reason).with(Detail::Epoch {
                        epoch,
                        reference: current.epoch::<P>(),
                    }));
                }
            }
        }
        let epoch = data.slot.epoch::<P>();
        if data.target.epoch != epoch {
            return Err(
                GossipError::reject("attestation epoch does not match target epoch").with(
                    Detail::Epoch {
                        epoch: data.target.epoch,
                        reference: epoch,
                    },
                ),
            );
        }
        Ok(())
    }

    /// Checks that a contribution is for the current slot, an existing subcommittee, and someone.
    fn contribution_is_well_formed(
        &self,
        contribution: &SyncCommitteeContribution<P>,
        bits: &[bool],
        now_ms: u64,
    ) -> Verdict {
        if !self.view.is_within_slot_range(contribution.slot, 0, now_ms) {
            return Err(
                GossipError::ignore("contribution is not for the current slot").with(
                    Detail::Slot {
                        slot: contribution.slot,
                        reference: self.view.current_slot(now_ms),
                    },
                ),
            );
        }
        if contribution.subcommittee_index >= SYNC_COMMITTEE_SUBNET_COUNT {
            return Err(GossipError::reject("subcommittee index out of range").with(
                Detail::Bound {
                    value: contribution.subcommittee_index,
                    bound: SYNC_COMMITTEE_SUBNET_COUNT,
                },
            ));
        }
        if !bits.iter().any(|bit| *bit) {
            return Err(GossipError::reject("contribution has no participants"));
        }
        Ok(())
    }

    /// The validator at an index of a state's registry.
    ///
    /// The reason words the rule for the message's role, such as proposer or aggregator.
    fn registered<'s>(
        beacon: &'s BeaconState<P>,
        index: ValidatorIndex,
        reason: &'static str,
    ) -> Result<&'s Validator, GossipError> {
        beacon.validators().get(index.as_usize()).ok_or_else(|| {
            GossipError::reject(reason).with(Detail::Bound {
                value: index.0,
                bound: beacon.validators().len() as u64,
            })
        })
    }

    /// Checks that a vote's target is on its head block's chain, which descends from finality.
    fn vote_is_on_chain(&self, data: &AttestationData) -> Verdict {
        // The target must be the checkpoint of the voted block's own chain.
        if self
            .view
            .checkpoint_block(data.beacon_block_root, data.target.epoch)
            != Some(data.target.root)
        {
            return Err(
                GossipError::reject("target block is not an ancestor of LMD vote block")
                    .with(Detail::Block(data.target.root)),
            );
        }
        // A vote off the finalized chain is useless but may come from an honest lagging peer.
        if !self.view.descends_from_finalized(data.beacon_block_root) {
            return Err(
                GossipError::ignore("finalized checkpoint is not an ancestor of block")
                    .with(Detail::Block(data.beacon_block_root)),
            );
        }
        Ok(())
    }

    /// Checks that the block a vote names is known and valid.
    fn voted_block_is_valid(&self, root: Root) -> Verdict {
        if self.view.block(&root).is_none() {
            return Err(
                GossipError::ignore("block being voted for has not been seen")
                    .with(Detail::Block(root)),
            );
        }
        if !self.view.is_imported(&root) {
            return Err(
                GossipError::reject("block being voted for failed validation")
                    .with(Detail::Block(root)),
            );
        }
        Ok(())
    }

    /// Signature domain of a message type at an epoch, under the fork schedule.
    ///
    /// The head state may not have crossed the fork the message's epoch is in.
    /// Its own fork record would then give the previous version and reject an honest message.
    fn domain(&self, state: &BeaconState<P>, domain_type: DomainType, epoch: Epoch) -> Domain {
        self.view
            .config()
            .domain(domain_type, epoch, state.genesis_validators_root())
    }

    /// The head's post-state, which most rules read.
    fn head_state(&mut self) -> Result<State<P>, GossipError> {
        self.view.head_state().map_err(|error| {
            GossipError::ignore("head state is unavailable").with(Self::missing_block(&error))
        })
    }

    /// A parent's post-state advanced to a slot, to find that slot's proposer.
    ///
    /// When the shuffling cannot be computed, the spec says to ignore rather than reject.
    fn parent_state(&self, parent: &Root, slot: Slot) -> Result<State<P>, GossipError> {
        self.view.state_at(parent, slot).map_err(|error| {
            GossipError::ignore("proposer shuffling is unavailable")
                .with(Self::missing_block(&error))
        })
    }

    /// The block whose state a fork choice lookup lacked, when that is why it failed.
    const fn missing_block(error: &ForkChoiceError) -> Detail {
        match error {
            ForkChoiceError::MissingState(root) => Detail::Block(*root),
            _ => Detail::None,
        }
    }
}
