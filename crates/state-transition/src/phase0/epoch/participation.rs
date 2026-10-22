//! Who voted what in the two epochs a phase0 state keeps pending attestations for.

use axiom_types::{
    Epoch, Gwei, Preset, Root, ValidatorIndex,
    accessors::CoreState,
    phase0::{BeaconState, PendingAttestation},
};

use crate::{ActiveBalance, CachedState, StateError, phase0::epoch::Justification};

/// One part of a vote that earns its own reward.
///
/// A vote names a source and a target checkpoint for Casper FFG, and a head block for LMD-GHOST.
/// See `get_source_deltas`, `get_target_deltas`, and `get_head_deltas` in the phase0 spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VotePart {
    /// The source, which any included vote has right: inclusion checks it.
    Source,
    /// The target: the block at the start of the vote's epoch.
    Target,
    /// The head: the block at the vote's slot.
    Head,
}

impl VotePart {
    /// Every part, in the order rewards list them.
    pub const ALL: [Self; 3] = [Self::Source, Self::Target, Self::Head];

    /// Position of the part in a validator's record.
    const fn position(self) -> usize {
        match self {
            Self::Source => 0,
            Self::Target => 1,
            Self::Head => 2,
        }
    }
}

/// The earliest inclusion of a validator's vote of the previous epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inclusion {
    /// Slots between the vote and the block that included it.
    pub delay: u64,
    /// Proposer of the including block.
    pub proposer: ValidatorIndex,
}

/// What one validator's pending attestations show.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Record {
    /// Parts of a previous epoch vote it got right, by position.
    previous: [bool; 3],
    /// Whether it voted for the current epoch's target.
    current_target: bool,
    /// The earliest inclusion of its previous epoch votes.
    earliest: Option<Inclusion>,
}

/// The participation of the ending epoch and the one before it, read from pending attestations.
///
/// # Overview
///
/// Phase0 keeps every included attestation until the end of its epoch.
/// This view walks them once and records, per validator, which parts of its vote matched.
/// Slashed validators count as absent, as the spec's unslashed attesting indices require.
///
/// See the helpers of epoch processing in the phase0 beacon chain spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingParticipation {
    /// The epoch that is ending.
    current_epoch: Epoch,
    /// The epoch before it.
    previous_epoch: Epoch,
    /// Total active balance of the ending epoch.
    total_active_balance: ActiveBalance,
    /// One record per validator.
    records: Vec<Record>,
    /// Attesting balance of each part of the previous epoch's votes, by position.
    previous_balances: [Gwei; 3],
    /// Attesting balance of the current epoch's target votes.
    current_target_balance: Gwei,
}

impl PendingParticipation {
    /// Reads the pending attestations of a state at the end of an epoch.
    ///
    /// # Errors
    ///
    /// Fails when a vote names a committee that does not exist or a block root the state lost.
    /// Block processing admitted every vote, so a valid chain never fails here.
    pub fn new<P: Preset>(
        state: &mut CachedState<'_, BeaconState<P>>,
        total_active_balance: ActiveBalance,
    ) -> Result<Self, StateError> {
        let beacon = state.beacon();
        let current_epoch = beacon.current_epoch();
        let previous_epoch = beacon.previous_epoch();
        let mut participation = Self {
            current_epoch,
            previous_epoch,
            total_active_balance,
            records: vec![Record::default(); beacon.validators.len()],
            previous_balances: [Gwei::ZERO; 3],
            current_target_balance: Gwei::ZERO,
        };

        // The lists are cloned out, since committees need the caches mutably.
        let previous = beacon.previous_epoch_attestations.clone();
        let current = beacon.current_epoch_attestations.clone();
        for attestation in &previous {
            participation.record_previous(state, attestation)?;
        }
        for attestation in &current {
            participation.record_current(state, attestation)?;
        }
        participation.drop_slashed(state.beacon());
        participation.sum_balances(state.beacon());
        Ok(participation)
    }

    /// The epoch that is ending.
    #[must_use]
    pub const fn current_epoch(&self) -> Epoch {
        self.current_epoch
    }

    /// Total active balance of the ending epoch.
    #[must_use]
    pub const fn total_active_balance(&self) -> ActiveBalance {
        self.total_active_balance
    }

    /// Whether an unslashed validator got a part of its previous epoch vote right.
    #[must_use]
    pub fn has_previous(&self, index: usize, part: VotePart) -> bool {
        self.records
            .get(index)
            .is_some_and(|record| record.previous[part.position()])
    }

    /// The earliest inclusion of an unslashed validator's previous epoch vote.
    #[must_use]
    pub fn earliest_inclusion(&self, index: usize) -> Option<Inclusion> {
        self.records
            .get(index)
            .filter(|record| record.previous[VotePart::Source.position()])
            .and_then(|record| record.earliest)
    }

    /// Balance of the unslashed validators that got a part of the previous epoch vote right.
    ///
    /// The total never falls below one increment, so it can divide.
    /// See `get_attesting_balance` in the phase0 beacon chain spec.
    #[must_use]
    pub const fn previous_balance(&self, part: VotePart) -> Gwei {
        self.previous_balances[part.position()]
    }

    /// The target votes of both epochs, ready to weigh for justification.
    ///
    /// See `process_justification_and_finalization` in the phase0 beacon chain spec.
    #[must_use]
    pub const fn justification(&self) -> Justification {
        Justification {
            current_epoch: self.current_epoch,
            previous_epoch: self.previous_epoch,
            total: self.total_active_balance.0,
            previous_target: self.previous_balance(VotePart::Target),
            current_target: self.current_target_balance,
        }
    }

    /// Records the parts a previous epoch vote got right, and its inclusion.
    fn record_previous<P: Preset>(
        &mut self,
        state: &mut CachedState<'_, BeaconState<P>>,
        attestation: &PendingAttestation<P>,
    ) -> Result<(), StateError> {
        let beacon = state.beacon();
        let target = attestation.data.target.root == Self::block_root(beacon, self.previous_epoch)?;
        // The head is checked only for votes whose target matched.
        let head =
            target && attestation.data.beacon_block_root == Self::slot_root(beacon, attestation)?;
        let inclusion = Inclusion {
            delay: attestation.inclusion_delay.0,
            proposer: attestation.proposer_index,
        };
        for index in Self::attesters(state, attestation)? {
            let record = &mut self.records[index.as_usize()];
            record.previous[VotePart::Source.position()] = true;
            record.previous[VotePart::Target.position()] |= target;
            record.previous[VotePart::Head.position()] |= head;
            // Ties go to the vote listed first, as the spec's minimum keeps the first.
            if record
                .earliest
                .is_none_or(|earliest| inclusion.delay < earliest.delay)
            {
                record.earliest = Some(inclusion);
            }
        }
        Ok(())
    }

    /// Records a current epoch vote for the current target.
    fn record_current<P: Preset>(
        &mut self,
        state: &mut CachedState<'_, BeaconState<P>>,
        attestation: &PendingAttestation<P>,
    ) -> Result<(), StateError> {
        let root = Self::block_root(state.beacon(), self.current_epoch)?;
        if attestation.data.target.root != root {
            return Ok(());
        }
        for index in Self::attesters(state, attestation)? {
            self.records[index.as_usize()].current_target = true;
        }
        Ok(())
    }

    /// Validators that set their bit in a pending attestation.
    ///
    /// See `get_pending_attesting_indices` in the phase0 beacon chain spec.
    fn attesters<P: Preset>(
        state: &mut CachedState<'_, BeaconState<P>>,
        attestation: &PendingAttestation<P>,
    ) -> Result<impl Iterator<Item = ValidatorIndex>, StateError> {
        let data = &attestation.data;
        let failed = |source| StateError::PendingAttestation {
            slot: data.slot,
            source: Box::new(source),
        };
        let attesters = state
            .attesters(data.slot, [data.index], attestation.aggregation_bits.iter())
            .map_err(failed)?;
        let registry_size = state.beacon().validators.len();
        if let Some(unknown) = attesters
            .iter()
            .find(|index| index.as_usize() >= registry_size)
        {
            return Err(StateError::UnknownValidator {
                index: *unknown,
                registry_size,
            });
        }
        Ok(attesters.into_iter())
    }

    /// Root of the block at the start of an epoch.
    fn block_root<P: Preset>(state: &BeaconState<P>, epoch: Epoch) -> Result<Root, StateError> {
        state
            .block_root(epoch)
            .ok_or_else(|| StateError::BlockRootOutOfRange {
                slot: epoch.start_slot::<P>(),
                state_slot: state.slot,
            })
    }

    /// Root of the block at a vote's slot.
    fn slot_root<P: Preset>(
        state: &BeaconState<P>,
        attestation: &PendingAttestation<P>,
    ) -> Result<Root, StateError> {
        let slot = attestation.data.slot;
        state
            .block_root_at_slot(slot)
            .ok_or(StateError::BlockRootOutOfRange {
                slot,
                state_slot: state.slot,
            })
    }

    /// Clears the records of slashed validators, which earn nothing for their votes.
    fn drop_slashed<P: Preset>(&mut self, state: &BeaconState<P>) {
        for (record, validator) in self.records.iter_mut().zip(state.validators.iter()) {
            if validator.slashed {
                *record = Record::default();
            }
        }
    }

    /// Sums the effective balance behind each part, floored at one increment.
    fn sum_balances<P: Preset>(&mut self, state: &BeaconState<P>) {
        let mut previous = [Gwei::ZERO; 3];
        let mut current = Gwei::ZERO;
        for (record, validator) in self.records.iter().zip(state.validators.iter()) {
            for (sum, voted) in previous.iter_mut().zip(record.previous) {
                if voted {
                    *sum += validator.effective_balance;
                }
            }
            if record.current_target {
                current += validator.effective_balance;
            }
        }
        let floor = P::EFFECTIVE_BALANCE_INCREMENT;
        self.previous_balances = previous.map(|sum| sum.max(floor));
        self.current_target_balance = current.max(floor);
    }
}
