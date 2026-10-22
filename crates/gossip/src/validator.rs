//! The gossip rules, one method per topic, in the spec's order.

use axiom_das::ColumnSidecar;
use axiom_fork_choice::ExecutionStatus;
use axiom_kzg::Kzg;
use axiom_ssz::Ssz;
use axiom_state_transition::State;
use axiom_types::{
    AttestationData, AttesterSlashing, BlsPubkey, CommitteeIndex, DataColumnSidecar, Domain, Epoch,
    Preset, ProposerSlashing, Root, SignedAggregateAndProof, SignedBeaconBlock,
    SignedBlsToExecutionChange, SignedContributionAndProof, SignedVoluntaryExit, SingleAttestation,
    Slot, SubnetId, SyncCommitteeMessage, ValidatorIndex,
    constants::{
        BLS_WITHDRAWAL_PREFIX, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER,
        DOMAIN_BLS_TO_EXECUTION_CHANGE, DOMAIN_SYNC_COMMITTEE, DOMAIN_VOLUNTARY_EXIT,
        SYNC_COMMITTEE_SUBNET_COUNT, TARGET_AGGREGATORS_PER_COMMITTEE,
        TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
    },
};

use crate::{ChainView, GossipError, Seen, signers::Signers, signing_claim::SigningClaim};

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
        if self.seen.proposer_slots.contains(&key) {
            return Err(GossipError::Ignore(
                "block is not the first valid block for this slot and proposer",
            ));
        }
        if self.view.is_future_slot(block.slot, now_ms) {
            return Err(GossipError::Ignore("block is from a future slot"));
        }
        if block.slot <= self.view.finalized.epoch.start_slot::<P>() {
            return Err(GossipError::Ignore(
                "block is not from a slot greater than the latest finalized slot",
            ));
        }
        let Some(parent) = self.view.block(&block.parent_root) else {
            return Err(GossipError::Ignore("block's parent has not been seen"));
        };
        let parent_status = self.view.payload_status(&block.parent_root);
        if !self.view.is_imported(&block.parent_root) {
            // A parent that failed with an unvalidated payload failed for consensus reasons.
            return Err(
                if parent_status.is_none_or(|status| status == ExecutionStatus::Optimistic) {
                    GossipError::Reject("block's parent is invalid and its payload is optimistic")
                } else {
                    GossipError::Ignore("block's parent is invalid and its payload is processed")
                },
            );
        }
        if parent_status == Some(ExecutionStatus::Invalid) {
            return Err(GossipError::Ignore(
                "block's parent is valid and its payload is invalid",
            ));
        }

        let state = self.head_state()?;
        let beacon = state.beacon();
        let proposer = beacon
            .validators
            .get(block.proposer_index.as_usize())
            .ok_or(GossipError::Reject("proposer index out of range"))?;
        let domain = beacon.domain(DOMAIN_BEACON_PROPOSER, block.slot.epoch::<P>());
        if !SigningClaim::new(block, domain, &signed.signature).is_signed_by(&proposer.pubkey) {
            return Err(GossipError::Reject("invalid proposer signature"));
        }
        let expected_timestamp =
            beacon.genesis_time + block.slot.0 * self.view.config().slot_duration_ms / 1000;
        if block.body.execution_payload.timestamp != expected_timestamp {
            return Err(GossipError::Reject("incorrect execution payload timestamp"));
        }
        if block.slot <= parent.slot {
            return Err(GossipError::Reject(
                "block is not from a higher slot than its parent",
            ));
        }
        if !self.view.descends_from_finalized(block.parent_root) {
            return Err(GossipError::Reject(
                "finalized checkpoint is not an ancestor of block",
            ));
        }
        let max_blobs = self
            .view
            .config()
            .blob_parameters(block.slot.epoch::<P>())
            .max_blobs_per_block;
        if block.body.blob_kzg_commitments.len() as u64 > max_blobs {
            return Err(GossipError::Reject("too many blob kzg commitments"));
        }
        let parent_state = self.parent_state(&block.parent_root, block.slot)?;
        if block.proposer_index != parent_state.beacon().beacon_proposer_index() {
            return Err(GossipError::Reject(
                "block proposer_index does not match expected proposer",
            ));
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
        if data.index.0 != 0 {
            return Err(GossipError::Reject("aggregate data index is non-zero"));
        }
        let committees: Vec<CommitteeIndex> = aggregate.committee_indices().collect();
        let [index] = committees[..] else {
            return Err(GossipError::Reject(
                "aggregate committee bits must specify exactly one committee",
            ));
        };

        let bits: Vec<bool> = aggregate.aggregation_bits.iter().collect();
        let data_key = (data.target.epoch, data.hash_tree_root(), index);
        if self
            .seen
            .aggregate_data_roots
            .get(&data_key)
            .is_some_and(|seen| Seen::is_covered(seen, &bits))
        {
            return Err(GossipError::Ignore("already seen aggregate for this data"));
        }
        let aggregator_key = (data.target.epoch, message.aggregator_index);
        if self.seen.aggregator_epochs.contains(&aggregator_key) {
            return Err(GossipError::Ignore(
                "already seen aggregate for this epoch and aggregator",
            ));
        }
        self.voted_block_is_valid(data.beacon_block_root)?;

        let mut state = self.head_state()?;
        let committees = state.compute_committees(data.target.epoch);
        if index.0 >= committees.committees_per_slot() {
            return Err(GossipError::Reject("committee index out of range"));
        }
        if self.view.is_future_slot(data.slot, now_ms) {
            return Err(GossipError::Ignore("aggregate slot is from a future slot"));
        }
        if !self
            .view
            .is_current_or_previous_epoch(data.slot.epoch::<P>(), now_ms)
        {
            return Err(GossipError::Ignore(
                "aggregate epoch is not current or previous epoch",
            ));
        }
        if data.target.epoch != data.slot.epoch::<P>() {
            return Err(GossipError::Reject(
                "attestation epoch does not match target epoch",
            ));
        }
        let committee = committees
            .committee(data.slot, index)
            .ok_or(GossipError::Reject("committee index out of range"))?
            .to_vec();
        if bits.len() != committee.len() {
            return Err(GossipError::Reject(
                "aggregation bits length does not match committee size",
            ));
        }
        let attesters: Vec<ValidatorIndex> = committee
            .iter()
            .zip(&bits)
            .filter(|(_, bit)| **bit)
            .map(|(validator, _)| *validator)
            .collect();
        if attesters.is_empty() {
            return Err(GossipError::Reject("aggregate has no participants"));
        }
        // Threshold: about 16 aggregators per committee, picked by the hash of a slot signature.
        let modulo = (committee.len() as u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
        if !message.selection_proof.selects(modulo) {
            return Err(GossipError::Reject(
                "validator is not selected as aggregator",
            ));
        }
        if !committee.contains(&message.aggregator_index) {
            return Err(GossipError::Reject(
                "aggregator is not a member of the committee",
            ));
        }
        Signers::of(state.beacon()).verify_aggregator(signed)?;
        if !Signers::of(state.beacon()).attested(attesters, aggregate) {
            return Err(GossipError::Reject("invalid aggregate signature"));
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
        if self.seen.attestation_validator_epochs.contains(&key) {
            return Err(GossipError::Ignore(
                "already seen attestation for this epoch and validator",
            ));
        }
        if data.index.0 != 0 {
            return Err(GossipError::Reject("attestation data index is non-zero"));
        }
        self.voted_block_is_valid(data.beacon_block_root)?;

        let mut state = self.head_state()?;
        let committees = state.compute_committees(data.target.epoch);
        let per_slot = committees.committees_per_slot();
        if attestation.committee_index.0 >= per_slot {
            return Err(GossipError::Reject("committee index out of range"));
        }
        // Subnets count committees from the start of the epoch, wrapping at the subnet count.
        let expected_subnet = (per_slot * data.slot.index_in_epoch::<P>()
            + attestation.committee_index.0)
            % self.view.config().attestation_subnet_count;
        if expected_subnet != subnet.0 {
            return Err(GossipError::Reject("attestation is for wrong subnet"));
        }
        if self.view.is_future_slot(data.slot, now_ms) {
            return Err(GossipError::Ignore(
                "attestation slot is from a future slot",
            ));
        }
        if !self
            .view
            .is_current_or_previous_epoch(data.slot.epoch::<P>(), now_ms)
        {
            return Err(GossipError::Ignore(
                "attestation epoch is not current or previous epoch",
            ));
        }
        if data.target.epoch != data.slot.epoch::<P>() {
            return Err(GossipError::Reject(
                "attestation epoch does not match target epoch",
            ));
        }
        let in_committee = committees
            .committee(data.slot, attestation.committee_index)
            .is_some_and(|committee| committee.contains(&attestation.attester_index));
        if !in_committee {
            return Err(GossipError::Reject(
                "attester is not a member of the committee",
            ));
        }
        let beacon = state.beacon();
        let attester = &beacon.validators[attestation.attester_index.as_usize()];
        let domain = beacon.domain(DOMAIN_BEACON_ATTESTER, data.target.epoch);
        if !SigningClaim::new(data, domain, &attestation.signature).is_signed_by(&attester.pubkey) {
            return Err(GossipError::Reject("invalid attestation signature"));
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
        if self
            .seen
            .voluntary_exit_indices
            .contains(&exit.validator_index)
        {
            return Err(GossipError::Ignore(
                "already seen voluntary exit for this validator",
            ));
        }
        if self.view.is_future_epoch(exit.epoch, now_ms) {
            return Err(GossipError::Ignore("voluntary exit epoch is in the future"));
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        let validator = beacon
            .validators
            .get(exit.validator_index.as_usize())
            .ok_or(GossipError::Reject("validator index out of range"))?;
        let epoch = beacon.current_epoch();
        if validator.exit_epoch != Epoch::FAR_FUTURE {
            return Err(GossipError::Ignore("validator has already initiated exit"));
        }
        if !validator.is_active_at(epoch) {
            return Err(GossipError::Reject("validator is not active"));
        }
        if epoch.0
            < validator
                .activation_epoch
                .0
                .saturating_add(self.view.config().shard_committee_period)
        {
            return Err(GossipError::Reject(
                "validator has not been active long enough",
            ));
        }
        let domain = Domain::compute(
            DOMAIN_VOLUNTARY_EXIT,
            self.view.config().capella_fork_version,
            beacon.genesis_validators_root,
        );
        if !SigningClaim::new(exit, domain, &signed.signature).is_signed_by(&validator.pubkey) {
            return Err(GossipError::Reject("invalid voluntary exit signature"));
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
        if self
            .seen
            .proposer_slashing_indices
            .contains(&proposer_index)
        {
            return Err(GossipError::Ignore(
                "already seen proposer slashing for this proposer",
            ));
        }
        if header_1.slot != header_2.slot {
            return Err(GossipError::Reject("header slots do not match"));
        }
        if header_1.proposer_index != header_2.proposer_index {
            return Err(GossipError::Reject("header proposer indices do not match"));
        }
        if header_1 == header_2 {
            return Err(GossipError::Reject("headers are not different"));
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        let proposer = beacon
            .validators
            .get(proposer_index.as_usize())
            .ok_or(GossipError::Reject("proposer index out of range"))?;
        if !proposer.is_slashable_at(beacon.current_epoch()) {
            return Err(GossipError::Reject("proposer is not slashable"));
        }
        for signed in [&slashing.signed_header_1, &slashing.signed_header_2] {
            let domain = beacon.domain(DOMAIN_BEACON_PROPOSER, signed.message.slot.epoch::<P>());
            if !SigningClaim::new(&signed.message, domain, &signed.signature)
                .is_signed_by(&proposer.pubkey)
            {
                return Err(GossipError::Reject("invalid proposer slashing signature"));
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
            return Err(GossipError::Ignore(
                "all attester slashing indices already seen",
            ));
        }
        if !slashing
            .attestation_1
            .data
            .is_slashable_with(&slashing.attestation_2.data)
        {
            return Err(GossipError::Reject("attestation data is not slashable"));
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
            let count = beacon.validators.len() as u64;
            if attestation
                .attesting_indices
                .iter()
                .any(|index| index.0 >= count)
            {
                return Err(GossipError::Reject(out_of_range));
            }
            if !Signers::of(state.beacon()).is_valid_indexed_attestation(attestation) {
                return Err(GossipError::Reject(invalid));
            }
        }
        let epoch = beacon.current_epoch();
        if !both
            .iter()
            .any(|index| beacon.validators[index.as_usize()].is_slashable_at(epoch))
        {
            return Err(GossipError::Reject(
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
            return Err(GossipError::Ignore(
                "already seen contribution for this data",
            ));
        }
        let aggregator_key = (
            contribution.slot,
            message.aggregator_index,
            contribution.subcommittee_index,
        );
        if self
            .seen
            .sync_contribution_aggregator_slots
            .contains(&aggregator_key)
        {
            return Err(GossipError::Ignore(
                "already seen contribution from this aggregator",
            ));
        }
        if !self.view.is_within_slot_range(contribution.slot, 0, now_ms) {
            return Err(GossipError::Ignore(
                "contribution is not for the current slot",
            ));
        }
        if contribution.subcommittee_index >= SYNC_COMMITTEE_SUBNET_COUNT {
            return Err(GossipError::Reject("subcommittee index out of range"));
        }
        if !bits.iter().any(|bit| *bit) {
            return Err(GossipError::Reject("contribution has no participants"));
        }
        // Threshold: about 16 aggregators per subcommittee.
        let modulo = (P::SYNC_COMMITTEE_SIZE
            / SYNC_COMMITTEE_SUBNET_COUNT
            / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
            .max(1);
        if !message.selection_proof.selects(modulo) {
            return Err(GossipError::Reject(
                "validator is not selected as aggregator",
            ));
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        let aggregator = beacon
            .validators
            .get(message.aggregator_index.as_usize())
            .ok_or(GossipError::Reject("aggregator index out of range"))?;
        let subcommittee =
            Signers::of(state.beacon()).sync_subcommittee(contribution.subcommittee_index);
        if !subcommittee.contains(&aggregator.pubkey) {
            return Err(GossipError::Reject(
                "aggregator is not a member of the committee",
            ));
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
            return Err(GossipError::Reject("invalid aggregate signature"));
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
        if self.seen.sync_message_validator_slots.contains(&key) {
            return Err(GossipError::Ignore(
                "already seen message from this validator for this slot and subnet",
            ));
        }
        if !self.view.is_within_slot_range(message.slot, 0, now_ms) {
            return Err(GossipError::Ignore("message is not for the current slot"));
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        let validator = beacon
            .validators
            .get(message.validator_index.as_usize())
            .ok_or(GossipError::Reject("validator index out of range"))?;
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
            return Err(GossipError::Reject(
                "subnet_id is not valid for the validator",
            ));
        }
        let domain = beacon.domain(DOMAIN_SYNC_COMMITTEE, message.slot.epoch::<P>());
        if !SigningClaim::new(&message.beacon_block_root, domain, &message.signature)
            .is_signed_by(&validator.pubkey)
        {
            return Err(GossipError::Reject(
                "invalid sync committee message signature",
            ));
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
        if self
            .seen
            .bls_to_execution_change_indices
            .contains(&change.validator_index)
        {
            return Err(GossipError::Ignore(
                "already seen BLS to execution change for this validator",
            ));
        }
        if self
            .view
            .is_future_epoch(self.view.config().capella_fork_epoch, now_ms)
        {
            return Err(GossipError::Ignore("current epoch is pre-capella"));
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        let validator = beacon
            .validators
            .get(change.validator_index.as_usize())
            .ok_or(GossipError::Reject("validator index out of range"))?;
        let credentials = validator.withdrawal_credentials.0;
        if credentials[0] != BLS_WITHDRAWAL_PREFIX {
            return Err(GossipError::Reject(
                "validator does not have BLS withdrawal credentials",
            ));
        }
        if credentials[1..] != Root::sha256(&change.from_bls_pubkey.0).0[1..] {
            return Err(GossipError::Reject(
                "pubkey does not match validator withdrawal credentials",
            ));
        }
        let domain = Domain::compute(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            self.view.config().genesis_fork_version,
            beacon.genesis_validators_root,
        );
        if !SigningClaim::new(change, domain, &signed.signature)
            .is_signed_by(&change.from_bls_pubkey)
        {
            return Err(GossipError::Reject(
                "invalid BLS to execution change signature",
            ));
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
        if self.seen.data_column_sidecar_tuples.contains(&key) {
            return Err(GossipError::Ignore(
                "already seen sidecar from this proposer for this slot and index",
            ));
        }
        let checked = ColumnSidecar(sidecar);
        if checked.verify_structure(self.view.config()).is_err() {
            return Err(GossipError::Reject("invalid sidecar"));
        }
        if sidecar.index.0 % self.view.config().data_column_sidecar_subnet_count != subnet.0 {
            return Err(GossipError::Reject("sidecar is for wrong subnet"));
        }
        if self.view.is_future_slot(header.slot, now_ms) {
            return Err(GossipError::Ignore("sidecar is from a future slot"));
        }
        if header.slot <= self.view.finalized.epoch.start_slot::<P>() {
            return Err(GossipError::Ignore(
                "sidecar is not from a slot greater than the latest finalized slot",
            ));
        }
        let Some(parent) = self.view.block(&header.parent_root) else {
            return Err(GossipError::Ignore("sidecar's parent has not been seen"));
        };
        if !self.view.is_imported(&header.parent_root) {
            return Err(GossipError::Reject("sidecar's parent failed validation"));
        }
        let state = self.head_state()?;
        let beacon = state.beacon();
        let proposer = beacon
            .validators
            .get(header.proposer_index.as_usize())
            .ok_or(GossipError::Reject("proposer index out of range"))?;
        let domain = beacon.domain(DOMAIN_BEACON_PROPOSER, header.slot.epoch::<P>());
        if !SigningClaim::new(header, domain, &sidecar.signed_block_header.signature)
            .is_signed_by(&proposer.pubkey)
        {
            return Err(GossipError::Reject(
                "invalid proposer signature on sidecar block header",
            ));
        }
        if header.slot <= parent.slot {
            return Err(GossipError::Reject(
                "sidecar is not from a higher slot than its parent",
            ));
        }
        if !self.view.descends_from_finalized(header.parent_root) {
            return Err(GossipError::Reject(
                "finalized checkpoint is not an ancestor of sidecar's block",
            ));
        }
        if checked.verify_inclusion_proof().is_err() {
            return Err(GossipError::Reject("invalid sidecar inclusion proof"));
        }
        if ColumnSidecar(sidecar).verify_kzg_proofs(kzg).is_err() {
            return Err(GossipError::Reject("invalid sidecar kzg proofs"));
        }
        let parent_state = self.parent_state(&header.parent_root, header.slot)?;
        if header.proposer_index != parent_state.beacon().beacon_proposer_index() {
            return Err(GossipError::Reject(
                "sidecar proposer_index does not match expected proposer",
            ));
        }
        self.seen.data_column_sidecar_tuples.insert(key);
        Ok(())
    }

    /// Checks that a vote's target is on its head block's chain, which descends from finality.
    fn vote_is_on_chain(&self, data: &AttestationData) -> Verdict {
        // The target must be the checkpoint of the voted block's own chain.
        if self
            .view
            .checkpoint_block(data.beacon_block_root, data.target.epoch)
            != Some(data.target.root)
        {
            return Err(GossipError::Reject(
                "target block is not an ancestor of LMD vote block",
            ));
        }
        // A vote off the finalized chain is useless but may come from an honest lagging peer.
        if !self.view.descends_from_finalized(data.beacon_block_root) {
            return Err(GossipError::Ignore(
                "finalized checkpoint is not an ancestor of block",
            ));
        }
        Ok(())
    }

    /// Checks that the block a vote names is known and valid.
    fn voted_block_is_valid(&self, root: Root) -> Verdict {
        if self.view.block(&root).is_none() {
            return Err(GossipError::Ignore(
                "block being voted for has not been seen",
            ));
        }
        if !self.view.is_imported(&root) {
            return Err(GossipError::Reject(
                "block being voted for failed validation",
            ));
        }
        Ok(())
    }

    /// The head's post-state, which most rules read.
    fn head_state(&mut self) -> Result<State<P>, GossipError> {
        self.view
            .head_state()
            .map_err(|_| GossipError::Ignore("head state is unavailable"))
    }

    /// A parent's post-state advanced to a slot, to find that slot's proposer.
    ///
    /// When the shuffling cannot be computed, the spec says to ignore rather than reject.
    fn parent_state(&self, parent: &Root, slot: Slot) -> Result<State<P>, GossipError> {
        self.view
            .state_at(parent, slot)
            .map_err(|_| GossipError::Ignore("proposer shuffling is unavailable"))
    }
}
