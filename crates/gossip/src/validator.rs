//! The gossip rules, one method per topic, in the spec's order.

use axiom_das::ColumnSidecar;
use axiom_fork_choice::{ExecutionStatus, ForkChoiceError};
use axiom_kzg::Kzg;
use axiom_ssz::Ssz;
use axiom_state_transition::State;
use axiom_types::{
    BlsPubkey, CommitteeIndex, Domain, Epoch, Preset, Root, Slot, SubnetId, ValidatorIndex,
    accessors::CoreState,
    combined::BeaconState,
    constants::{
        BLS_WITHDRAWAL_PREFIX, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER,
        DOMAIN_BLS_TO_EXECUTION_CHANGE, DOMAIN_SYNC_COMMITTEE, DOMAIN_VOLUNTARY_EXIT,
        SYNC_COMMITTEE_SUBNET_COUNT, TARGET_AGGREGATORS_PER_COMMITTEE,
        TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
    },
    fulu::{
        Attestation, AttestationData, AttesterSlashing, DataColumnSidecar, ProposerSlashing,
        SignedAggregateAndProof, SignedBeaconBlock, SignedBlsToExecutionChange,
        SignedContributionAndProof, SignedVoluntaryExit, SingleAttestation,
        SyncCommitteeContribution, SyncCommitteeMessage, Validator,
    },
};

use crate::{ChainView, Detail, GossipError, Seen, signers::Signers, signing_claim::SigningClaim};

/// Shorthand for a rule's outcome.
type Verdict = Result<(), GossipError>;

/// Validates gossip messages against a chain view, remembering what it forwarded.
///
/// Each method mirrors one `validate_*_gossip` function of the spec.
/// Only a message that passes every rule updates the seen state.
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

    /// Validates a block.
    ///
    /// See `validate_beacon_block_gossip` in the Fulu p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn beacon_block(&mut self, signed: &SignedBeaconBlock<P>, now_ms: u64) -> Verdict {
        let block = &signed.message;
        let key = (block.slot, block.proposer_index);
        let proposer_detail = Detail::Validator(block.proposer_index);
        if self.seen.proposer_slots.contains(&key) {
            return Err(GossipError::ignore(
                "block is not the first valid block for this slot and proposer",
            )
            .with(proposer_detail));
        }
        self.header_slot_is_timely(
            block.slot,
            now_ms,
            "block is from a future slot",
            "block is not from a slot greater than the latest finalized slot",
        )?;
        let parent_detail = Detail::Block(block.parent_root);
        let Some(parent) = self.view.block(&block.parent_root) else {
            return Err(GossipError::ignore("block's parent has not been seen").with(parent_detail));
        };
        let parent_status = self.view.payload_status(&block.parent_root);
        if !self.view.is_imported(&block.parent_root) {
            // A parent that failed with an unvalidated payload failed for consensus reasons.
            let verdict =
                if parent_status.is_none_or(|status| status == ExecutionStatus::Optimistic) {
                    GossipError::reject("block's parent is invalid and its payload is optimistic")
                } else {
                    GossipError::ignore("block's parent is invalid and its payload is processed")
                };
            return Err(verdict.with(parent_detail));
        }
        if parent_status == Some(ExecutionStatus::Invalid) {
            return Err(
                GossipError::ignore("block's parent is valid and its payload is invalid")
                    .with(parent_detail),
            );
        }

        let state = self.head_state()?;
        let beacon = state.beacon();
        let proposer =
            Self::registered(beacon, block.proposer_index, "proposer index out of range")?;
        let domain = beacon.domain(DOMAIN_BEACON_PROPOSER, block.slot.epoch::<P>());
        if !SigningClaim::new(block, domain, &signed.signature).is_signed_by(&proposer.pubkey) {
            return Err(GossipError::reject("invalid proposer signature").with(proposer_detail));
        }
        let expected_timestamp =
            beacon.genesis_time() + block.slot.0 * self.view.config().slot_duration_ms / 1000;
        let timestamp = block.body.execution_payload.timestamp;
        if timestamp != expected_timestamp {
            return Err(
                GossipError::reject("incorrect execution payload timestamp").with(
                    Detail::Mismatch {
                        actual: timestamp,
                        expected: expected_timestamp,
                    },
                ),
            );
        }
        if block.slot <= parent.slot {
            return Err(
                GossipError::reject("block is not from a higher slot than its parent").with(
                    Detail::Slot {
                        slot: block.slot,
                        reference: parent.slot,
                    },
                ),
            );
        }
        if !self.view.descends_from_finalized(block.parent_root) {
            return Err(GossipError::reject(
                "finalized checkpoint is not an ancestor of block",
            ));
        }
        let max_blobs = self
            .view
            .config()
            .blob_parameters(block.slot.epoch::<P>())
            .max_blobs_per_block;
        let blobs = block.body.blob_kzg_commitments.len() as u64;
        if blobs > max_blobs {
            return Err(
                GossipError::reject("too many blob kzg commitments").with(Detail::Bound {
                    value: blobs,
                    bound: max_blobs,
                }),
            );
        }
        let parent_state = self.parent_state(&block.parent_root, block.slot)?;
        let expected_proposer = parent_state
            .beacon_proposer_index()
            .map_err(|_| GossipError::ignore("proposer shuffling is unavailable"))?;
        if block.proposer_index != expected_proposer {
            return Err(GossipError::reject(
                "block proposer_index does not match expected proposer",
            )
            .with(Detail::Mismatch {
                actual: block.proposer_index.0,
                expected: expected_proposer.0,
            }));
        }

        self.seen.proposer_slots.insert(key);
        Ok(())
    }

    /// Validates an aggregate and its aggregator's proof of selection.
    ///
    /// See `validate_beacon_aggregate_and_proof_gossip` in the Electra p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn aggregate_and_proof(
        &mut self,
        signed: &SignedAggregateAndProof<P>,
        now_ms: u64,
    ) -> Verdict {
        let message = &signed.message;
        let aggregate = &message.aggregate;
        let data = &aggregate.data;
        let index = Self::aggregate_committee(aggregate)?;
        let aggregator_detail = Detail::Validator(message.aggregator_index);

        let bits: Vec<bool> = aggregate.aggregation_bits.iter().collect();
        let data_key = (data.target.epoch, data.hash_tree_root(), index);
        if self
            .seen
            .aggregate_data_roots
            .get(&data_key)
            .is_some_and(|seen| Seen::is_covered(seen, &bits))
        {
            return Err(GossipError::ignore("already seen aggregate for this data"));
        }
        let aggregator_key = (data.target.epoch, message.aggregator_index);
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
        self.vote_is_timely(
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
        if !message.selection_proof.selects(modulo) {
            return Err(
                GossipError::reject("validator is not selected as aggregator")
                    .with(aggregator_detail),
            );
        }
        if !committee.contains(&message.aggregator_index) {
            return Err(
                GossipError::reject("aggregator is not a member of the committee")
                    .with(aggregator_detail),
            );
        }
        Signers::of(state.beacon()).verify_aggregator(signed)?;
        if !Signers::of(state.beacon()).attested(attesters, aggregate) {
            return Err(GossipError::reject("invalid aggregate signature"));
        }
        self.vote_is_on_chain(data)?;

        self.seen.aggregator_epochs.insert(aggregator_key);
        self.seen
            .aggregate_data_roots
            .entry(data_key)
            .or_default()
            .push(bits);
        Ok(())
    }

    /// Validates one validator's attestation on its subnet.
    ///
    /// See `validate_beacon_attestation_gossip` in the Electra p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn beacon_attestation(
        &mut self,
        attestation: &SingleAttestation,
        now_ms: u64,
        subnet: SubnetId,
    ) -> Verdict {
        let data = &attestation.data;
        let key = (data.target.epoch, attestation.attester_index);
        let attester_detail = Detail::Validator(attestation.attester_index);
        if self.seen.attestation_validator_epochs.contains(&key) {
            return Err(GossipError::ignore(
                "already seen attestation for this epoch and validator",
            )
            .with(attester_detail));
        }
        if data.index.0 != 0 {
            return Err(
                GossipError::reject("attestation data index is non-zero").with(Detail::Mismatch {
                    actual: data.index.0,
                    expected: 0,
                }),
            );
        }
        self.voted_block_is_valid(data.beacon_block_root)?;

        let mut state = self.head_state()?;
        let committees = state.compute_committees(data.target.epoch);
        let per_slot = committees.committees_per_slot();
        if attestation.committee_index.0 >= per_slot {
            return Err(
                GossipError::reject("committee index out of range").with(Detail::Bound {
                    value: attestation.committee_index.0,
                    bound: per_slot,
                }),
            );
        }
        // Subnets count committees from the start of the epoch, wrapping at the subnet count.
        let expected_subnet = (per_slot * data.slot.index_in_epoch::<P>()
            + attestation.committee_index.0)
            % self.view.config().attestation_subnet_count;
        if expected_subnet != subnet.0 {
            return Err(GossipError::reject("attestation is for wrong subnet").with(
                Detail::Mismatch {
                    actual: subnet.0,
                    expected: expected_subnet,
                },
            ));
        }
        self.vote_is_timely(
            data,
            now_ms,
            "attestation slot is from a future slot",
            "attestation epoch is not current or previous epoch",
        )?;
        let in_committee = committees
            .committee(data.slot, attestation.committee_index)
            .is_some_and(|committee| committee.contains(&attestation.attester_index));
        if !in_committee {
            return Err(
                GossipError::reject("attester is not a member of the committee")
                    .with(attester_detail),
            );
        }
        let beacon = state.beacon();
        let attester = &beacon.validators()[attestation.attester_index.as_usize()];
        let domain = beacon.domain(DOMAIN_BEACON_ATTESTER, data.target.epoch);
        if !SigningClaim::new(data, domain, &attestation.signature).is_signed_by(&attester.pubkey) {
            return Err(GossipError::reject("invalid attestation signature").with(attester_detail));
        }
        self.vote_is_on_chain(data)?;

        self.seen.attestation_validator_epochs.insert(key);
        Ok(())
    }

    /// Validates a voluntary exit.
    ///
    /// See `validate_voluntary_exit_gossip` in the Deneb p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn voluntary_exit(&mut self, signed: &SignedVoluntaryExit, now_ms: u64) -> Verdict {
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
        let domain = Domain::compute(
            DOMAIN_VOLUNTARY_EXIT,
            self.view.config().capella_fork_version,
            beacon.genesis_validators_root(),
        );
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
            let domain = beacon.domain(DOMAIN_BEACON_PROPOSER, signed.message.slot.epoch::<P>());
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

    /// Validates an attester slashing.
    ///
    /// See `validate_attester_slashing_gossip` in the phase0 p2p spec.
    ///
    /// # Errors
    ///
    /// Ignores or rejects as the spec's rules say.
    pub fn attester_slashing(&mut self, slashing: &AttesterSlashing<P>) -> Verdict {
        let both = slashing.common_signers();
        if both
            .iter()
            .all(|index| self.seen.attester_slashing_indices.contains(index))
        {
            return Err(GossipError::ignore(
                "all attester slashing indices already seen",
            ));
        }
        if !slashing
            .attestation_1
            .data
            .is_slashable_with(&slashing.attestation_2.data)
        {
            return Err(GossipError::reject("attestation data is not slashable"));
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        for (attestation, out_of_range, invalid) in [
            (
                &slashing.attestation_1,
                "validator index out of range in indexed attestation 1",
                "invalid indexed attestation 1",
            ),
            (
                &slashing.attestation_2,
                "validator index out of range in indexed attestation 2",
                "invalid indexed attestation 2",
            ),
        ] {
            let count = beacon.validators().len() as u64;
            if let Some(index) = attestation
                .attesting_indices
                .iter()
                .find(|index| index.0 >= count)
            {
                return Err(GossipError::reject(out_of_range).with(Detail::Bound {
                    value: index.0,
                    bound: count,
                }));
            }
            if !Signers::of(state.beacon()).is_valid_indexed_attestation(attestation) {
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
        let subcommittee =
            Signers::of(state.beacon()).sync_subcommittee(contribution.subcommittee_index);
        if !subcommittee.contains(&aggregator.pubkey) {
            return Err(
                GossipError::reject("aggregator is not a member of the committee")
                    .with(aggregator_detail),
            );
        }
        Signers::of(state.beacon()).verify_contributor(&aggregator.pubkey, signed)?;
        let epoch = contribution.slot.epoch::<P>();
        let participants: Vec<BlsPubkey> = subcommittee
            .iter()
            .zip(&bits)
            .filter(|(_, bit)| **bit)
            .map(|(pubkey, _)| *pubkey)
            .collect();
        let sync_domain = beacon.domain(DOMAIN_SYNC_COMMITTEE, epoch);
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
        let in_subnet = Signers::of(state.beacon())
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
        let domain = beacon.domain(DOMAIN_SYNC_COMMITTEE, message.slot.epoch::<P>());
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
        let domain = beacon.domain(DOMAIN_BEACON_PROPOSER, header.slot.epoch::<P>());
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

    /// The one committee an aggregate's data and bits select.
    fn aggregate_committee(aggregate: &Attestation<P>) -> Result<CommitteeIndex, GossipError> {
        if aggregate.data.index.0 != 0 {
            return Err(
                GossipError::reject("aggregate data index is non-zero").with(Detail::Mismatch {
                    actual: aggregate.data.index.0,
                    expected: 0,
                }),
            );
        }
        let committees: Vec<CommitteeIndex> = aggregate.committee_indices().collect();
        let [index] = committees[..] else {
            return Err(GossipError::reject(
                "aggregate committee bits must specify exactly one committee",
            )
            .with(Detail::Mismatch {
                actual: committees.len() as u64,
                expected: 1,
            }));
        };
        Ok(index)
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

    /// Checks that a vote's slot has started, is recent, and lies in its target epoch.
    ///
    /// The reasons word the first two rules for the message, an aggregate or an attestation.
    fn vote_is_timely(
        &self,
        data: &AttestationData,
        now_ms: u64,
        future_reason: &'static str,
        epoch_reason: &'static str,
    ) -> Verdict {
        if self.view.is_future_slot(data.slot, now_ms) {
            return Err(GossipError::ignore(future_reason).with(Detail::Slot {
                slot: data.slot,
                reference: self.view.current_slot(now_ms),
            }));
        }
        let epoch = data.slot.epoch::<P>();
        if !self.view.is_current_or_previous_epoch(epoch, now_ms) {
            return Err(GossipError::ignore(epoch_reason).with(Detail::Epoch {
                epoch,
                reference: self.view.current_slot(now_ms).epoch::<P>(),
            }));
        }
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
