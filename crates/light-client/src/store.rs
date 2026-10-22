//! The light client store, and the rules for advancing it.

use std::mem;

use axiom_bls::{PublicKey, Signature};
use axiom_ssz::{Root, Ssz};
use axiom_types::{
    ChainConfig, Domain, Preset, Slot,
    altair::{SigningData, SyncCommittee},
    constants::DOMAIN_SYNC_COMMITTEE,
};

use crate::{
    BootstrapData, Header, Layout, LightClientError, LightClientFork, UpdateData, UpdateQuality,
    Upgrade, branch::Branch,
};

/// What a light client knows: two committees, a finalized header, and an optimistic one.
///
/// # Overview
///
/// The store holds headers in one fork's format, the fork it was created or upgraded for.
/// Data in an earlier format is upgraded before it enters.
/// The rules are the same in every format; only the header checks and proof positions vary.
///
/// See `LightClientStore` in the Altair light client sync protocol, as modified by later forks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightClientStore<P: Preset, F: LightClientFork> {
    /// Latest finalized header.
    pub finalized_header: F::Header<P>,
    /// Sync committee of the finalized header's period.
    pub current_sync_committee: SyncCommittee<P>,
    /// Sync committee of the following period, empty until learned.
    pub next_sync_committee: SyncCommittee<P>,
    /// Best update seen since the last finalization, for a forced update after a timeout.
    pub best_valid_update: Option<UpdateData<F::Header<P>, P>>,
    /// Latest header signed by a safe share of the committee.
    pub optimistic_header: F::Header<P>,
    /// Most signers seen in the previous period.
    pub previous_max_active_participants: usize,
    /// Most signers seen in the current period.
    pub current_max_active_participants: usize,
}

impl<P: Preset, F: LightClientFork> LightClientStore<P, F> {
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
        bootstrap: F::Bootstrap<P>,
    ) -> Result<Self, LightClientError> {
        let BootstrapData {
            header,
            current_sync_committee,
            current_sync_committee_branch,
        } = F::bootstrap_data(bootstrap);
        let beacon = header.beacon();
        if !header.is_valid_at(config) {
            return Err(LightClientError::InvalidHeader(beacon.slot));
        }
        let header_root = beacon.hash_tree_root();
        if header_root != trusted_block_root {
            return Err(LightClientError::UntrustedBootstrap {
                header: header_root,
                trusted: trusted_block_root,
            });
        }
        let layout = Layout::at::<P>(config, beacon.slot);
        Branch::new(
            &current_sync_committee_branch,
            layout.current_sync_committee,
        )
        .proves(current_sync_committee.hash_tree_root(), beacon.state_root)?;
        Ok(Self {
            finalized_header: header.clone(),
            current_sync_committee,
            next_sync_committee: SyncCommittee::default(),
            best_valid_update: None,
            optimistic_header: header,
            previous_max_active_participants: 0,
            current_max_active_participants: 0,
        })
    }

    /// Validates an update and advances the store with it.
    ///
    /// # Algorithm
    ///
    /// 1. Keep the update as the best seen, if it ranks higher.
    /// 2. Move the optimistic header when more than the safety threshold signed.
    /// 3. Move the finalized header when two thirds signed a newer finalized header.
    ///
    /// See `process_light_client_update` in the Altair light client sync protocol.
    ///
    /// # Errors
    ///
    /// Fails when the update is invalid, leaving the store unchanged.
    pub fn process_update(
        &mut self,
        config: &ChainConfig,
        update: F::Update<P>,
        current_slot: Slot,
        genesis_validators_root: Root,
    ) -> Result<(), LightClientError> {
        self.process_data(
            config,
            F::update_data(update),
            current_slot,
            genesis_validators_root,
        )
    }

    /// Processes a finality update, as an update without a next committee.
    ///
    /// See `process_light_client_finality_update` in the Altair light client sync protocol.
    ///
    /// # Errors
    ///
    /// Fails when the update is invalid.
    pub fn process_finality_update(
        &mut self,
        config: &ChainConfig,
        update: F::FinalityUpdate<P>,
        current_slot: Slot,
        genesis_validators_root: Root,
    ) -> Result<(), LightClientError> {
        let data = F::finality_update_data(update);
        self.process_data(config, data, current_slot, genesis_validators_root)
    }

    /// Processes an optimistic update, as an update with neither committee nor finality.
    ///
    /// See `process_light_client_optimistic_update` in the Altair light client sync protocol.
    ///
    /// # Errors
    ///
    /// Fails when the update is invalid.
    pub fn process_optimistic_update(
        &mut self,
        config: &ChainConfig,
        update: F::OptimisticUpdate<P>,
        current_slot: Slot,
        genesis_validators_root: Root,
    ) -> Result<(), LightClientError> {
        let data = F::optimistic_update_data(update);
        self.process_data(config, data, current_slot, genesis_validators_root)
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
        let timed_out = current_slot.0 > self.finalized_slot().0 + P::UPDATE_TIMEOUT;
        if !timed_out {
            return Ok(());
        }
        if let Some(mut best) = self.best_valid_update.take() {
            if best.finalized_header.beacon().slot <= self.finalized_slot() {
                best.finalized_header = best.attested_header.clone();
            }
            self.apply_update(&best)?;
        }
        Ok(())
    }

    /// The store in the next fork's format.
    ///
    /// The upgrade may happen before that fork activates.
    /// See `upgrade_lc_store_to_*` in each fork's light client fork logic.
    ///
    /// # Errors
    ///
    /// Fails when a branch of the best update is longer than the new format's.
    pub fn upgrade<G: Upgrade<Previous = F>>(
        self,
        config: &ChainConfig,
    ) -> Result<LightClientStore<P, G>, LightClientError> {
        let best_valid_update = self
            .best_valid_update
            .map(|best| G::upgrade_data(best, config))
            .transpose()?;
        Ok(LightClientStore {
            finalized_header: G::upgrade_header_at(self.finalized_header, config),
            current_sync_committee: self.current_sync_committee,
            next_sync_committee: self.next_sync_committee,
            best_valid_update,
            optimistic_header: G::upgrade_header_at(self.optimistic_header, config),
            previous_max_active_participants: self.previous_max_active_participants,
            current_max_active_participants: self.current_max_active_participants,
        })
    }

    /// Validates an update's fields and advances the store with them.
    fn process_data(
        &mut self,
        config: &ChainConfig,
        update: UpdateData<F::Header<P>, P>,
        current_slot: Slot,
        genesis_validators_root: Root,
    ) -> Result<(), LightClientError> {
        self.validate_update(config, &update, current_slot, genesis_validators_root)?;
        let bits = &update.sync_aggregate.sync_committee_bits;
        let participants = bits.count_ones();
        let committee_size = bits.len();

        self.current_max_active_participants =
            self.current_max_active_participants.max(participants);

        if participants > self.safety_threshold()
            && update.attested_header.beacon().slot > self.optimistic_header.beacon().slot
        {
            self.optimistic_header = update.attested_header.clone();
        }

        let finalizes_next_committee = !self.is_next_sync_committee_known()
            && update.is_sync_committee_update()
            && update.is_finality_update()
            && update
                .finalized_header
                .beacon()
                .slot
                .sync_committee_period::<P>()
                == update
                    .attested_header
                    .beacon()
                    .slot
                    .sync_committee_period::<P>();
        // Threshold: participants * 3 >= committee * 2.
        let applies = participants * 3 >= committee_size * 2
            && (update.finalized_header.beacon().slot > self.finalized_slot()
                || finalizes_next_committee);

        if applies {
            self.apply_update(&update)?;
            self.best_valid_update = None;
        } else if self
            .best_valid_update
            .as_ref()
            .is_none_or(|best| UpdateQuality::of(&update) > UpdateQuality::of(best))
        {
            // The spec stores the best update first, then clears it on a normal update.
            // Ending in the same state, a normal update skips the store.
            self.best_valid_update = Some(update);
        }
        Ok(())
    }

    /// Checks every rule an update must satisfy, without changing the store.
    ///
    /// See `validate_light_client_update` in the Altair light client sync protocol.
    fn validate_update(
        &self,
        config: &ChainConfig,
        update: &UpdateData<F::Header<P>, P>,
        current_slot: Slot,
        genesis_validators_root: Root,
    ) -> Result<(), LightClientError> {
        let participants = update.participants() as u64;
        if participants < P::MIN_SYNC_COMMITTEE_PARTICIPANTS {
            return Err(LightClientError::InsufficientParticipants {
                participants,
                minimum: P::MIN_SYNC_COMMITTEE_PARTICIPANTS,
            });
        }

        let attested = update.attested_header.beacon();
        if !update.attested_header.is_valid_at(config) {
            return Err(LightClientError::InvalidHeader(attested.slot));
        }
        let finalized_slot = update.finalized_header.beacon().slot;
        if !(current_slot >= update.signature_slot
            && update.signature_slot > attested.slot
            && attested.slot >= finalized_slot)
        {
            return Err(LightClientError::InvalidSlots {
                current: current_slot,
                signature: update.signature_slot,
                attested: attested.slot,
                finalized: finalized_slot,
            });
        }

        let store_period = self.finalized_slot().sync_committee_period::<P>();
        let signature_period = update.signature_slot.sync_committee_period::<P>();
        let next_known = self.is_next_sync_committee_known();
        let period_ok = if next_known {
            signature_period == store_period || signature_period == store_period + 1
        } else {
            signature_period == store_period
        };
        if !period_ok {
            return Err(LightClientError::SkippedPeriod {
                period: signature_period,
                store_period,
            });
        }

        // The update must move the finalized header, or deliver the missing next committee.
        let attested_period = attested.slot.sync_committee_period::<P>();
        let has_next_committee =
            !next_known && update.is_sync_committee_update() && attested_period == store_period;
        if attested.slot <= self.finalized_slot() && !has_next_committee {
            return Err(LightClientError::Irrelevant {
                attested: attested.slot,
                finalized: self.finalized_slot(),
            });
        }

        // The attested block's fork fixes where its state keeps each proven field.
        let layout = Layout::at::<P>(config, attested.slot);
        if update.is_finality_update() {
            // The genesis checkpoint's root is zero, and its header stays empty.
            let finalized_root = if finalized_slot == Slot::GENESIS {
                if update.finalized_header != F::Header::<P>::default() {
                    return Err(LightClientError::UnexpectedData("finalized header"));
                }
                Root::ZERO
            } else {
                if !update.finalized_header.is_valid_at(config) {
                    return Err(LightClientError::InvalidHeader(finalized_slot));
                }
                update.finalized_header.beacon().hash_tree_root()
            };
            Branch::new(&update.finality_branch, layout.finalized_root)
                .proves(finalized_root, attested.state_root)?;
        } else if update.finalized_header != F::Header::<P>::default() {
            return Err(LightClientError::UnexpectedData("finalized header"));
        }

        if update.is_sync_committee_update() {
            if attested_period == store_period
                && next_known
                && update.next_sync_committee != self.next_sync_committee
            {
                return Err(LightClientError::ConflictingCommittee(attested_period));
            }
            Branch::new(
                &update.next_sync_committee_branch,
                layout.next_sync_committee,
            )
            .proves(
                update.next_sync_committee.hash_tree_root(),
                attested.state_root,
            )?;
        } else if update.next_sync_committee != SyncCommittee::default() {
            return Err(LightClientError::UnexpectedData("next sync committee"));
        }

        self.verify_signature(config, update, genesis_validators_root)
    }

    /// Moves committees and headers forward with a validated update.
    ///
    /// See `apply_light_client_update` in the Altair light client sync protocol.
    fn apply_update(
        &mut self,
        update: &UpdateData<F::Header<P>, P>,
    ) -> Result<(), LightClientError> {
        let store_period = self.finalized_slot().sync_committee_period::<P>();
        let finalized_slot = update.finalized_header.beacon().slot;
        let finalized_period = finalized_slot.sync_committee_period::<P>();
        if !self.is_next_sync_committee_known() {
            if finalized_period != store_period {
                return Err(LightClientError::SkippedPeriod {
                    period: finalized_period,
                    store_period,
                });
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
        if finalized_slot > self.finalized_slot() {
            self.finalized_header = update.finalized_header.clone();
            if finalized_slot > self.optimistic_header.beacon().slot {
                self.optimistic_header = self.finalized_header.clone();
            }
        }
        Ok(())
    }

    /// Slot of the finalized header.
    fn finalized_slot(&self) -> Slot {
        self.finalized_header.beacon().slot
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
        update: &UpdateData<F::Header<P>, P>,
        genesis_validators_root: Root,
    ) -> Result<(), LightClientError> {
        let committee = if update.signature_slot.sync_committee_period::<P>()
            == self.finalized_slot().sync_committee_period::<P>()
        {
            &self.current_sync_committee
        } else {
            &self.next_sync_committee
        };
        let signers = committee
            .pubkeys
            .iter()
            .zip(update.sync_aggregate.sync_committee_bits.iter())
            .enumerate()
            .filter(|(_, (_, bit))| *bit)
            .map(|(seat, (pubkey, _))| {
                PublicKey::from_bytes(&pubkey.0)
                    .map_err(|source| LightClientError::MalformedCommitteeKey { seat, source })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let signers: Vec<&PublicKey> = signers.iter().collect();

        // The committee signs in the fork of the slot before the signature slot.
        let fork_version =
            config.fork_version_at(update.signature_slot.saturating_sub(1).epoch::<P>());
        let domain = Domain::compute(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root);
        let signing_root = SigningData::signing_root(update.attested_header.beacon(), domain);
        let signature = Signature::from_bytes(&update.sync_aggregate.sync_committee_signature.0)
            .map_err(LightClientError::MalformedSignature)?;
        if signature.fast_aggregate_verify(&signers, &signing_root.0) {
            Ok(())
        } else {
            Err(LightClientError::InvalidSignature {
                signature_slot: update.signature_slot,
                participants: signers.len(),
            })
        }
    }
}
