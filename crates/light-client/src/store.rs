//! The light client store, and the rules for advancing it.

use std::mem;

use axiom_bls::{PublicKey, Signature};
use axiom_ssz::{Root, Ssz, Vector};
use axiom_types::{
    ChainConfig, Domain, LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
    LightClientOptimisticUpdate, LightClientUpdate, Preset, SigningData, Slot, SyncCommittee,
    constants::DOMAIN_SYNC_COMMITTEE,
};

use crate::{LightClientError, UpdateQuality, branch::Branch};

/// Position of the finalized checkpoint root in an Electra state's tree.
const FINALIZED_ROOT_GINDEX: u64 = 169;

/// Position of the current sync committee in an Electra state's tree.
const CURRENT_SYNC_COMMITTEE_GINDEX: u64 = 86;

/// Position of the next sync committee in an Electra state's tree.
const NEXT_SYNC_COMMITTEE_GINDEX: u64 = 87;

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
        if !bootstrap.header.is_valid(config) {
            return Err(LightClientError::InvalidHeader);
        }
        if bootstrap.header.beacon.hash_tree_root() != trusted_block_root {
            return Err(LightClientError::UntrustedBootstrap);
        }
        Branch::new(
            &bootstrap.current_sync_committee_branch,
            CURRENT_SYNC_COMMITTEE_GINDEX,
        )
        .proves(
            bootstrap.current_sync_committee.hash_tree_root(),
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
            && update.is_sync_committee_update()
            && update.is_finality_update()
            && update
                .finalized_header
                .beacon
                .slot
                .sync_committee_period::<P>()
                == update
                    .attested_header
                    .beacon
                    .slot
                    .sync_committee_period::<P>();
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

        if !update.attested_header.is_valid(config) {
            return Err(LightClientError::InvalidHeader);
        }
        let attested_slot = update.attested_header.beacon.slot;
        let finalized_slot = update.finalized_header.beacon.slot;
        if !(current_slot >= update.signature_slot
            && update.signature_slot > attested_slot
            && attested_slot >= finalized_slot)
        {
            return Err(LightClientError::InvalidSlots);
        }

        let store_period = self
            .finalized_header
            .beacon
            .slot
            .sync_committee_period::<P>();
        let signature_period = update.signature_slot.sync_committee_period::<P>();
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
        let attested_period = attested_slot.sync_committee_period::<P>();
        let has_next_committee =
            !next_known && update.is_sync_committee_update() && attested_period == store_period;
        if attested_slot <= self.finalized_header.beacon.slot && !has_next_committee {
            return Err(LightClientError::Irrelevant);
        }

        if update.is_finality_update() {
            // The genesis checkpoint's root is zero, and its header stays empty.
            let finalized_root = if finalized_slot == Slot::GENESIS {
                if update.finalized_header != LightClientHeader::default() {
                    return Err(LightClientError::UnexpectedData);
                }
                Root::ZERO
            } else {
                if !update.finalized_header.is_valid(config) {
                    return Err(LightClientError::InvalidHeader);
                }
                update.finalized_header.beacon.hash_tree_root()
            };
            Branch::new(&update.finality_branch, FINALIZED_ROOT_GINDEX)
                .proves(finalized_root, update.attested_header.beacon.state_root)?;
        } else if update.finalized_header != LightClientHeader::default() {
            return Err(LightClientError::UnexpectedData);
        }

        if update.is_sync_committee_update() {
            if attested_period == store_period
                && next_known
                && update.next_sync_committee != self.next_sync_committee
            {
                return Err(LightClientError::ConflictingCommittee);
            }
            Branch::new(
                &update.next_sync_committee_branch,
                NEXT_SYNC_COMMITTEE_GINDEX,
            )
            .proves(
                update.next_sync_committee.hash_tree_root(),
                update.attested_header.beacon.state_root,
            )?;
        } else if update.next_sync_committee != SyncCommittee::default() {
            return Err(LightClientError::UnexpectedData);
        }

        self.verify_signature(config, update, genesis_validators_root)
    }

    /// Moves committees and headers forward with a validated update.
    ///
    /// See `apply_light_client_update` in the Altair light client sync protocol.
    fn apply_update(&mut self, update: &LightClientUpdate<P>) -> Result<(), LightClientError> {
        let store_period = self
            .finalized_header
            .beacon
            .slot
            .sync_committee_period::<P>();
        let finalized_period = update
            .finalized_header
            .beacon
            .slot
            .sync_committee_period::<P>();
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

    /// Checks the sync committee's aggregate signature over the attested header.
    ///
    /// The committee is the current one, or the next one for a signature from the next period.
    fn verify_signature(
        &self,
        config: &ChainConfig,
        update: &LightClientUpdate<P>,
        genesis_validators_root: Root,
    ) -> Result<(), LightClientError> {
        let committee = if update.signature_slot.sync_committee_period::<P>()
            == self
                .finalized_header
                .beacon
                .slot
                .sync_committee_period::<P>()
        {
            &self.current_sync_committee
        } else {
            &self.next_sync_committee
        };
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
