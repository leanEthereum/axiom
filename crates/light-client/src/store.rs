//! The light client store, and the rules for advancing it.

use std::mem;

use axiom_bls::{PublicKey, Signature};
use axiom_ssz::{Container, GeneralizedIndex, MerkleProof, Merkleizer, Root, Ssz, Vector};
use axiom_types::{
    Bytes32, ChainConfig, Domain, ExecutionPayloadHeader, LightClientBootstrap,
    LightClientFinalityUpdate, LightClientHeader, LightClientOptimisticUpdate, LightClientUpdate,
    Preset, SigningData, Slot, SyncCommittee, constants::DOMAIN_SYNC_COMMITTEE,
};

use crate::{LightClientError, UpdateQuality};

/// Position of the execution payload in a block body's tree.
const EXECUTION_PAYLOAD_GINDEX: u64 = 25;

/// Position of the finalized checkpoint root in an Electra state's tree.
const FINALIZED_ROOT_GINDEX: u64 = 169;

/// Position of the current sync committee in an Electra state's tree.
const CURRENT_SYNC_COMMITTEE_GINDEX: u64 = 86;

/// Position of the next sync committee in an Electra state's tree.
const NEXT_SYNC_COMMITTEE_GINDEX: u64 = 87;

/// Fields of the Capella execution payload header, before Deneb appended the blob gas fields.
const CAPELLA_PAYLOAD_HEADER_FIELDS: usize = 15;

/// What a light client knows: two committees, a finalized header, and an optimistic one.
///
/// See `LightClientStore` in the Altair light client sync protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightClientStore<P: Preset> {
    /// Latest finalized header.
    pub finalized_header: LightClientHeader<P>,
    /// Sync committee of the finalized header's period.
    pub current_sync_committee: SyncCommittee<P>,
    /// Sync committee of the following period, empty until learned.
    pub next_sync_committee: SyncCommittee<P>,
    /// Best update seen since the last finalization, for a forced update after a timeout.
    pub best_valid_update: Option<LightClientUpdate<P>>,
    /// Latest header signed by a safe share of the committee.
    pub optimistic_header: LightClientHeader<P>,
    /// Most signers seen in the previous period.
    pub previous_max_active_participants: usize,
    /// Most signers seen in the current period.
    pub current_max_active_participants: usize,
}

impl<P: Preset> LightClientStore<P> {
    /// A store bootstrapped from a trusted block and the committee proven in its state.
    ///
    /// See `initialize_light_client_store` in the Altair light client sync protocol.
    ///
    /// # Errors
    ///
    /// Fails when the header is invalid, not the trusted block, or the committee is not proven.
    pub fn initialize(
        config: &ChainConfig,
        trusted_block_root: Root,
        bootstrap: &LightClientBootstrap<P>,
    ) -> Result<Self, LightClientError> {
        Self::verify_header(config, &bootstrap.header)?;
        if bootstrap.header.beacon.hash_tree_root() != trusted_block_root {
            return Err(LightClientError::UntrustedBootstrap);
        }
        Self::verify_branch(
            bootstrap.current_sync_committee.hash_tree_root(),
            &bootstrap.current_sync_committee_branch,
            CURRENT_SYNC_COMMITTEE_GINDEX,
            bootstrap.header.beacon.state_root,
        )?;
        Ok(Self {
            finalized_header: bootstrap.header.clone(),
            current_sync_committee: bootstrap.current_sync_committee.clone(),
            next_sync_committee: SyncCommittee::default(),
            best_valid_update: None,
            optimistic_header: bootstrap.header.clone(),
            previous_max_active_participants: 0,
            current_max_active_participants: 0,
        })
    }

    /// Validates an update and advances the store with it.
    ///
    /// # Algorithm
    ///
    /// - Keep the update as the best seen, if it ranks higher.
    /// - Move the optimistic header when more than the safety threshold signed.
    /// - Move the finalized header when two thirds signed a newer finalized header.
    ///
    /// See `process_light_client_update` in the Altair light client sync protocol.
    ///
    /// # Errors
    ///
    /// Fails when the update is invalid, leaving the store unchanged.
    pub fn process_update(
        &mut self,
        config: &ChainConfig,
        update: &LightClientUpdate<P>,
        current_slot: Slot,
        genesis_validators_root: Root,
    ) -> Result<(), LightClientError> {
        self.validate_update(config, update, current_slot, genesis_validators_root)?;
        let bits = &update.sync_aggregate.sync_committee_bits;
        let participants = bits.count_ones();

        let better = self
            .best_valid_update
            .as_ref()
            .is_none_or(|best| UpdateQuality::of(update) > UpdateQuality::of(best));
        if better {
            self.best_valid_update = Some(update.clone());
        }

        self.current_max_active_participants =
            self.current_max_active_participants.max(participants);

        if participants > self.safety_threshold()
            && update.attested_header.beacon.slot > self.optimistic_header.beacon.slot
        {
            self.optimistic_header = update.attested_header.clone();
        }

        let finalizes_next_committee = !self.is_next_sync_committee_known()
            && UpdateQuality::is_sync_committee_update(update)
            && UpdateQuality::is_finality_update(update)
            && Self::period(update.finalized_header.beacon.slot)
                == Self::period(update.attested_header.beacon.slot);
        // Threshold: participants * 3 >= committee * 2.
        if participants * 3 >= bits.len() * 2
            && (update.finalized_header.beacon.slot > self.finalized_header.beacon.slot
                || finalizes_next_committee)
        {
            self.apply_update(update)?;
            self.best_valid_update = None;
        }
        Ok(())
    }

    /// Applies the best update after a timeout without finality.
    ///
    /// Without finality the attested header stands in for the finalized one.
    /// The client can then keep crossing periods during a long finality outage.
    ///
    /// See `process_light_client_store_force_update` in the Altair light client sync protocol.
    ///
    /// # Errors
    ///
    /// Fails when the best update skips a period, which validation already excludes.
    pub fn force_update(&mut self, current_slot: Slot) -> Result<(), LightClientError> {
        let timed_out = current_slot.0 > self.finalized_header.beacon.slot.0 + P::UPDATE_TIMEOUT;
        if let Some(mut best) = self.best_valid_update.take() {
            if !timed_out {
                self.best_valid_update = Some(best);
                return Ok(());
            }
            if best.finalized_header.beacon.slot <= self.finalized_header.beacon.slot {
                best.finalized_header = best.attested_header.clone();
            }
            self.apply_update(&best)?;
        }
        Ok(())
    }

    /// Processes a finality update, as an update without a next committee.
    ///
    /// # Errors
    ///
    /// Fails when the update is invalid.
    pub fn process_finality_update(
        &mut self,
        config: &ChainConfig,
        update: &LightClientFinalityUpdate<P>,
        current_slot: Slot,
        genesis_validators_root: Root,
    ) -> Result<(), LightClientError> {
        let full = LightClientUpdate {
            attested_header: update.attested_header.clone(),
            next_sync_committee: SyncCommittee::default(),
            next_sync_committee_branch: Vector::default(),
            finalized_header: update.finalized_header.clone(),
            finality_branch: update.finality_branch.clone(),
            sync_aggregate: update.sync_aggregate.clone(),
            signature_slot: update.signature_slot,
        };
        self.process_update(config, &full, current_slot, genesis_validators_root)
    }

    /// Processes an optimistic update, as an update with neither committee nor finality.
    ///
    /// # Errors
    ///
    /// Fails when the update is invalid.
    pub fn process_optimistic_update(
        &mut self,
        config: &ChainConfig,
        update: &LightClientOptimisticUpdate<P>,
        current_slot: Slot,
        genesis_validators_root: Root,
    ) -> Result<(), LightClientError> {
        let full = LightClientUpdate {
            attested_header: update.attested_header.clone(),
            sync_aggregate: update.sync_aggregate.clone(),
            signature_slot: update.signature_slot,
            ..LightClientUpdate::default()
        };
        self.process_update(config, &full, current_slot, genesis_validators_root)
    }

    /// Checks every rule an update must satisfy, without changing the store.
    ///
    /// See `validate_light_client_update` in the Altair light client sync protocol.
    fn validate_update(
        &self,
        config: &ChainConfig,
        update: &LightClientUpdate<P>,
        current_slot: Slot,
        genesis_validators_root: Root,
    ) -> Result<(), LightClientError> {
        let aggregate = &update.sync_aggregate;
        if (aggregate.sync_committee_bits.count_ones() as u64) < P::MIN_SYNC_COMMITTEE_PARTICIPANTS
        {
            return Err(LightClientError::InsufficientParticipants);
        }

        Self::verify_header(config, &update.attested_header)?;
        let attested_slot = update.attested_header.beacon.slot;
        let finalized_slot = update.finalized_header.beacon.slot;
        if !(current_slot >= update.signature_slot
            && update.signature_slot > attested_slot
            && attested_slot >= finalized_slot)
        {
            return Err(LightClientError::InvalidSlots);
        }

        let store_period = Self::period(self.finalized_header.beacon.slot);
        let signature_period = Self::period(update.signature_slot);
        let next_known = self.is_next_sync_committee_known();
        let period_ok = if next_known {
            signature_period == store_period || signature_period == store_period + 1
        } else {
            signature_period == store_period
        };
        if !period_ok {
            return Err(LightClientError::SkippedPeriod);
        }

        // The update must move the finalized header, or deliver the missing next committee.
        let attested_period = Self::period(attested_slot);
        let has_next_committee = !next_known
            && UpdateQuality::is_sync_committee_update(update)
            && attested_period == store_period;
        if attested_slot <= self.finalized_header.beacon.slot && !has_next_committee {
            return Err(LightClientError::Irrelevant);
        }

        if UpdateQuality::is_finality_update(update) {
            // The genesis checkpoint's root is zero, and its header stays empty.
            let finalized_root = if finalized_slot == Slot::GENESIS {
                if update.finalized_header != LightClientHeader::default() {
                    return Err(LightClientError::UnexpectedData);
                }
                Root::ZERO
            } else {
                Self::verify_header(config, &update.finalized_header)?;
                update.finalized_header.beacon.hash_tree_root()
            };
            Self::verify_branch(
                finalized_root,
                &update.finality_branch,
                FINALIZED_ROOT_GINDEX,
                update.attested_header.beacon.state_root,
            )?;
        } else if update.finalized_header != LightClientHeader::default() {
            return Err(LightClientError::UnexpectedData);
        }

        if UpdateQuality::is_sync_committee_update(update) {
            if attested_period == store_period
                && next_known
                && update.next_sync_committee != self.next_sync_committee
            {
                return Err(LightClientError::ConflictingCommittee);
            }
            Self::verify_branch(
                update.next_sync_committee.hash_tree_root(),
                &update.next_sync_committee_branch,
                NEXT_SYNC_COMMITTEE_GINDEX,
                update.attested_header.beacon.state_root,
            )?;
        } else if update.next_sync_committee != SyncCommittee::default() {
            return Err(LightClientError::UnexpectedData);
        }

        let committee = if signature_period == store_period {
            &self.current_sync_committee
        } else {
            &self.next_sync_committee
        };
        Self::verify_signature(config, update, committee, genesis_validators_root)
    }

    /// Moves committees and headers forward with a validated update.
    ///
    /// See `apply_light_client_update` in the Altair light client sync protocol.
    fn apply_update(&mut self, update: &LightClientUpdate<P>) -> Result<(), LightClientError> {
        let store_period = Self::period(self.finalized_header.beacon.slot);
        let finalized_period = Self::period(update.finalized_header.beacon.slot);
        if !self.is_next_sync_committee_known() {
            if finalized_period != store_period {
                return Err(LightClientError::SkippedPeriod);
            }
            self.next_sync_committee = update.next_sync_committee.clone();
        } else if finalized_period == store_period + 1 {
            self.current_sync_committee = mem::replace(
                &mut self.next_sync_committee,
                update.next_sync_committee.clone(),
            );
            self.previous_max_active_participants = self.current_max_active_participants;
            self.current_max_active_participants = 0;
        }
        if update.finalized_header.beacon.slot > self.finalized_header.beacon.slot {
            self.finalized_header = update.finalized_header.clone();
            if self.finalized_header.beacon.slot > self.optimistic_header.beacon.slot {
                self.optimistic_header = self.finalized_header.clone();
            }
        }
        Ok(())
    }

    /// Whether the next sync committee is known.
    fn is_next_sync_committee_known(&self) -> bool {
        self.next_sync_committee != SyncCommittee::default()
    }

    /// Half the most signers seen recently: the bar for a safe optimistic header.
    fn safety_threshold(&self) -> usize {
        self.previous_max_active_participants
            .max(self.current_max_active_participants)
            / 2
    }

    /// Sync committee period of a slot.
    const fn period(slot: Slot) -> u64 {
        slot.epoch::<P>().0 / P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD
    }

    /// Checks a header's execution payload against its block body.
    ///
    /// See `is_valid_light_client_header` in the Deneb light client sync protocol.
    fn verify_header(
        config: &ChainConfig,
        header: &LightClientHeader<P>,
    ) -> Result<(), LightClientError> {
        let epoch = header.beacon.slot.epoch::<P>();
        if epoch < config.deneb_fork_epoch
            && (header.execution.blob_gas_used != 0 || header.execution.excess_blob_gas != 0)
        {
            return Err(LightClientError::InvalidHeader);
        }
        if epoch < config.capella_fork_epoch {
            let empty = header.execution == ExecutionPayloadHeader::default()
                && header.execution_branch.iter().all(|node| node.0 == [0; 32]);
            return if empty {
                Ok(())
            } else {
                Err(LightClientError::InvalidHeader)
            };
        }
        Self::verify_branch(
            Self::execution_root(config, header),
            &header.execution_branch,
            EXECUTION_PAYLOAD_GINDEX,
            header.beacon.body_root,
        )
        .map_err(|_| LightClientError::InvalidHeader)
    }

    /// Root of a header's execution payload header, in the shape of the header's fork.
    ///
    /// See `get_lc_execution_root` in the Deneb light client sync protocol.
    fn execution_root(config: &ChainConfig, header: &LightClientHeader<P>) -> Root {
        let epoch = header.beacon.slot.epoch::<P>();
        if epoch >= config.deneb_fork_epoch {
            return header.execution.hash_tree_root();
        }
        // Before Deneb the payload header lacked its last two fields.
        let mut merkleizer = Merkleizer::with_limit(CAPELLA_PAYLOAD_HEADER_FIELDS);
        for root in header
            .execution
            .field_roots()
            .into_iter()
            .take(CAPELLA_PAYLOAD_HEADER_FIELDS)
        {
            merkleizer.push(root);
        }
        merkleizer.finish()
    }

    /// Checks a merkle branch from a leaf to a root.
    fn verify_branch(
        leaf: Root,
        branch: &[Bytes32],
        gindex: u64,
        root: Root,
    ) -> Result<(), LightClientError> {
        let proof = MerkleProof {
            branch: branch.iter().map(|node| Root(node.0)).collect(),
        };
        if proof.verify(leaf, GeneralizedIndex::new(gindex), root) {
            Ok(())
        } else {
            Err(LightClientError::InvalidBranch)
        }
    }

    /// Checks the sync committee's aggregate signature over the attested header.
    fn verify_signature(
        config: &ChainConfig,
        update: &LightClientUpdate<P>,
        committee: &SyncCommittee<P>,
        genesis_validators_root: Root,
    ) -> Result<(), LightClientError> {
        let signers = committee
            .pubkeys
            .iter()
            .zip(update.sync_aggregate.sync_committee_bits.iter())
            .filter(|(_, bit)| *bit)
            .map(|(pubkey, _)| PublicKey::from_bytes(&pubkey.0))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LightClientError::InvalidSignature)?;
        let signers: Vec<&PublicKey> = signers.iter().collect();

        // The committee signs in the fork of the slot before the signature slot.
        let fork_version =
            config.fork_version_at(update.signature_slot.saturating_sub(1).epoch::<P>());
        let domain = Domain::compute(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root);
        let signing_root = SigningData::signing_root(&update.attested_header.beacon, domain);
        let signature = Signature::from_bytes(&update.sync_aggregate.sync_committee_signature.0)
            .map_err(|_| LightClientError::InvalidSignature)?;
        if signature.fast_aggregate_verify(&signers, &signing_root.0) {
            Ok(())
        } else {
            Err(LightClientError::InvalidSignature)
        }
    }
}
