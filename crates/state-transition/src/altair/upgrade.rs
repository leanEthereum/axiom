//! The upgrade from phase0 to Altair.

use axiom_ssz::List;
use axiom_types::{
    ChainConfig, ParticipationFlags, Preset,
    accessors::{CoreState, ParticipationState},
    altair::{BeaconState, SyncCommittee},
    phase0::{self, Fork, PendingAttestation},
};

use crate::{
    CachedState, Caches, StateError, Upgrade,
    altair::{epoch::SyncCommitteeRotation, flags::Inclusion},
};

impl<P: Preset> Upgrade for BeaconState<P> {
    type Previous = phase0::BeaconState<P>;

    /// Moves every phase0 field over, and derives Altair's participation and sync committees.
    ///
    /// # Algorithm
    ///
    /// 1. Every phase0 field moves over, and the fork version advances.
    /// 2. Participation flags and inactivity scores start at zero for every validator.
    /// 3. The previous epoch's pending attestations become previous epoch flags.
    /// 4. One sync committee is drawn, and serves as both the current and the next.
    ///
    /// See `upgrade_to_altair` in the Altair fork spec.
    fn upgrade(
        pre: phase0::BeaconState<P>,
        caches: &mut Caches,
        config: &ChainConfig,
    ) -> Result<Self, StateError> {
        let epoch = pre.current_epoch();
        let registry_size = pre.validators.len();
        let empty_flags = || {
            List::try_from(vec![ParticipationFlags::default(); registry_size]).map_err(|source| {
                StateError::Capacity {
                    list: "epoch participation",
                    source,
                }
            })
        };
        let previous_epoch_attestations = pre.previous_epoch_attestations;
        let mut post = Self {
            genesis_time: pre.genesis_time,
            genesis_validators_root: pre.genesis_validators_root,
            slot: pre.slot,
            fork: Fork {
                previous_version: pre.fork.current_version,
                current_version: config.altair_fork_version,
                epoch,
            },
            latest_block_header: pre.latest_block_header,
            block_roots: pre.block_roots,
            state_roots: pre.state_roots,
            historical_roots: pre.historical_roots,
            eth1_data: pre.eth1_data,
            eth1_data_votes: pre.eth1_data_votes,
            eth1_deposit_index: pre.eth1_deposit_index,
            validators: pre.validators,
            balances: pre.balances,
            randao_mixes: pre.randao_mixes,
            slashings: pre.slashings,
            previous_epoch_participation: empty_flags()?,
            current_epoch_participation: empty_flags()?,
            justification_bits: pre.justification_bits,
            previous_justified_checkpoint: pre.previous_justified_checkpoint,
            current_justified_checkpoint: pre.current_justified_checkpoint,
            finalized_checkpoint: pre.finalized_checkpoint,
            inactivity_scores: List::try_from(vec![0; registry_size]).map_err(|source| {
                StateError::Capacity {
                    list: "inactivity scores",
                    source,
                }
            })?,
            current_sync_committee: SyncCommittee::default(),
            next_sync_committee: SyncCommittee::default(),
        };

        let mut state = CachedState::new(&mut post, caches);
        for attestation in &previous_epoch_attestations {
            ParticipationTranslation(attestation).apply(&mut state)?;
        }
        // A duplicate committee serves as both the current and the next at the fork boundary.
        let committee = SyncCommitteeRotation::next_committee(&mut state)?;
        post.current_sync_committee = committee.clone();
        post.next_sync_committee = committee;
        Ok(post)
    }
}

/// A phase0 pending attestation, read back as the Altair flags it would have earned.
///
/// See `translate_participation` in the Altair fork spec.
#[derive(Debug)]
struct ParticipationTranslation<'a, P: Preset>(&'a PendingAttestation<P>);

impl<P: Preset> ParticipationTranslation<'_, P> {
    /// Sets the earned flags of every attester in the previous epoch's participation.
    fn apply(self, state: &mut CachedState<'_, BeaconState<P>>) -> Result<(), StateError> {
        let attestation = self.0;
        let data = &attestation.data;
        let failed = |source| StateError::PendingAttestation {
            slot: data.slot,
            source: Box::new(source),
        };
        // Altair counts a target vote only within one epoch of delay.
        let flags = Inclusion::new(&*state.beacon, data, attestation.inclusion_delay.0)
            .flags(Some(P::SLOTS_PER_EPOCH))
            .map_err(failed)?;
        let attesters = state
            .attesters(data.slot, [data.index], attestation.aggregation_bits.iter())
            .map_err(failed)?;
        let (previous, _) = state.beacon.epoch_participation_mut();
        for index in attesters {
            let participation = &mut previous[index.as_usize()];
            for flag in &flags {
                *participation = participation.with(*flag);
            }
        }
        Ok(())
    }
}
