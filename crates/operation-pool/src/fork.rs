//! What each fork's rules say about the operations a block may carry.

use axiom_ssz::{Length, List, ProgressiveList};
use axiom_state_transition::{
    ActiveBalance, BlockError, BlockProcessor, CachedState, Fork, altair::flags::Inclusion,
    deneb::block::Exit as DenebExit, electra::block::Exit as ElectraExit,
    gloas::block::IncludedAttestation,
};
use axiom_types::{
    ParticipationFlags, Preset, ValidatorIndex,
    accessors::{BuilderState, CoreState, ParticipationState},
    altair, bellatrix, capella,
    constants::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX},
    deneb, electra, fulu, gloas,
    phase0::{self, AttestationData, SignedVoluntaryExit},
    vote::{ConflictingVotes, IndexedVote},
};

use crate::{
    PoolError,
    packing::{Eligibility, Ledger, PackedAttestation, RewardRule},
};

/// The operation rules of one fork, implemented on that fork's state.
///
/// # Overview
///
/// The pool keeps operations in a form every fork shares.
/// At packing time, the fork of the block decides what is includable and in which container.
/// Dispatch on the fork happens once, by the caller, at the proposal's boundary.
pub trait PoolFork: Fork {
    /// The fork's block attestation.
    type Attestation;
    /// The fork's attester slashing.
    type AttesterSlashing;

    /// Most attestations a block body holds.
    const ATTESTATION_LIMIT: u64;
    /// Most attester slashings a block body holds.
    const ATTESTER_SLASHING_LIMIT: u64;
    /// Most credential changes a block body holds, none before Capella.
    const CREDENTIAL_CHANGE_LIMIT: u64;

    /// What a vote earns in a block of the state's slot, or nothing when not includable.
    ///
    /// For Gloas the state must already hold the parent's payload, as block processing applies it first.
    /// See `process_attestation` in the fork's beacon chain spec.
    fn eligibility(state: &Self, data: &AttestationData) -> Option<Eligibility>;

    /// The credits held at the state, and their pay.
    ///
    /// # Errors
    ///
    /// Fails when the committees of a recorded vote cannot be computed.
    fn ledger(state: &mut CachedState<'_, Self>) -> Result<Ledger, PoolError>;

    /// The fork's container for a packed attestation.
    ///
    /// # Errors
    ///
    /// Fails when the parts do not fit the container.
    fn attestation(packed: PackedAttestation) -> Result<Self::Attestation, PoolError>;

    /// The fork's container for two conflicting votes.
    ///
    /// # Errors
    ///
    /// Fails when a vote has more signers than the container holds.
    fn attester_slashing(votes: &ConflictingVotes) -> Result<Self::AttesterSlashing, PoolError>;

    /// Applies an attester slashing by the fork's rule.
    ///
    /// # Errors
    ///
    /// Fails when the slashing is invalid at the state.
    fn apply_attester_slashing(
        processor: &mut BlockProcessor<'_, Self>,
        slashing: &Self::AttesterSlashing,
    ) -> Result<(), BlockError>;

    /// Applies a voluntary exit by the fork's rule.
    ///
    /// # Errors
    ///
    /// Fails when the exit is invalid at the state.
    fn apply_exit(
        processor: &mut BlockProcessor<'_, Self>,
        exit: &SignedVoluntaryExit,
    ) -> Result<(), BlockError>;
}

/// The timing rule every fork shares for including a vote.
#[derive(Clone, Copy, Debug)]
struct VoteTiming;

impl VoteTiming {
    /// The inclusion delay of a vote, or nothing when the block cannot include it.
    ///
    /// The vote targets the epoch of its slot, the current or previous one.
    /// It is at least one slot old, and at most the window old when there is one.
    /// See `process_attestation` in the phase0 and Deneb beacon chain specs.
    fn delay<S: CoreState>(state: &S, data: &AttestationData, window: Option<u64>) -> Option<u64> {
        let target = data.target.epoch;
        if target != state.current_epoch() && target != state.previous_epoch() {
            return None;
        }
        if target != data.slot.epoch::<S::Preset>() {
            return None;
        }
        let delay = state.slot().0.checked_sub(data.slot.0)?;
        if delay < S::Preset::MIN_ATTESTATION_INCLUSION_DELAY {
            return None;
        }
        if window.is_some_and(|window| delay > window) {
            return None;
        }
        Some(delay)
    }

    /// The flags an Altair-style vote earns, as a set.
    fn flags<S: CoreState>(
        state: &S,
        data: &AttestationData,
        delay: u64,
        window: Option<u64>,
    ) -> Option<ParticipationFlags> {
        let flags = Inclusion::new(state, data, delay).flags(window).ok()?;
        Some(
            flags
                .into_iter()
                .fold(ParticipationFlags::default(), ParticipationFlags::with),
        )
    }

    /// Eligibility under Altair's flag rule, with a window bounding the delay.
    fn altair<S: CoreState>(
        state: &S,
        data: &AttestationData,
        window: Option<u64>,
    ) -> Option<Eligibility> {
        let delay = Self::delay(state, data, window)?;
        let flags = Self::flags(state, data, delay, window)?;
        Some(Eligibility { flags })
    }

    /// Eligibility under Electra's rule: the data names no committee.
    fn electra<S: CoreState>(state: &S, data: &AttestationData) -> Option<Eligibility> {
        if data.index.0 != 0 {
            return None;
        }
        Self::altair(state, data, None)
    }
}

/// Builds credit ledgers from the state's records.
#[derive(Clone, Copy, Debug)]
struct Ledgers;

impl Ledgers {
    /// The ledger of a state that records votes in participation flags.
    fn flags<S: ParticipationState>(state: &S) -> Ledger {
        Ledger {
            rule: RewardRule::ParticipationFlags {
                base_reward_per_increment: ActiveBalance::of(state)
                    .base_reward_per_increment::<S::Preset>(),
            },
            current_epoch: state.current_epoch(),
            previous: state
                .previous_epoch_participation()
                .iter()
                .copied()
                .collect(),
            current: state
                .current_epoch_participation()
                .iter()
                .copied()
                .collect(),
        }
    }
}

impl Ledgers {
    /// The ledger of a phase0 state, whose pending records name the votes included so far.
    fn pending<P: Preset>(
        state: &mut CachedState<'_, phase0::BeaconState<P>>,
    ) -> Result<Ledger, PoolError> {
        let validators = state.beacon().validators.len();
        let mut sides = [
            vec![ParticipationFlags::default(); validators],
            vec![ParticipationFlags::default(); validators],
        ];
        let records = [
            state.beacon().previous_epoch_attestations.clone(),
            state.beacon().current_epoch_attestations.clone(),
        ];
        for (side, records) in sides.iter_mut().zip(records) {
            for record in &records {
                let data = &record.data;
                let attesters =
                    state.attesters(data.slot, [data.index], record.aggregation_bits.iter())?;
                for attester in attesters {
                    if let Some(entry) = side.get_mut(attester.as_usize()) {
                        *entry = entry.with(TIMELY_SOURCE_FLAG_INDEX);
                    }
                }
            }
        }
        let [previous, current] = sides;
        Ok(Ledger {
            rule: RewardRule::FirstInclusion {
                total_balance_root: ActiveBalance::of(state.beacon()).0.0.isqrt(),
            },
            current_epoch: state.beacon().current_epoch(),
            previous,
            current,
        })
    }
}

/// The signers of one vote, as the list of an indexed attestation.
#[derive(Clone, Copy, Debug)]
struct Signers<'a>(&'a IndexedVote);

impl Signers<'_> {
    /// The signers in a bounded list.
    fn bounded<N: Length>(self) -> Result<List<ValidatorIndex, N>, PoolError> {
        List::try_from(self.0.indices.clone()).map_err(|_| PoolError::TooManySigners {
            count: self.0.indices.len(),
            limit: N::LEN,
        })
    }

    /// The phase0 indexed attestation of the vote.
    fn phase0<P: Preset>(self) -> Result<phase0::IndexedAttestation<P>, PoolError> {
        Ok(phase0::IndexedAttestation {
            attesting_indices: self.bounded()?,
            data: self.0.data.clone(),
            signature: self.0.signature,
        })
    }

    /// The Electra indexed attestation of the vote.
    fn electra<P: Preset>(self) -> Result<electra::IndexedAttestation<P>, PoolError> {
        Ok(electra::IndexedAttestation {
            attesting_indices: self.bounded()?,
            data: self.0.data.clone(),
            signature: self.0.signature,
        })
    }

    /// The Gloas indexed attestation of the vote, whose list is unbounded.
    fn gloas(self) -> gloas::IndexedAttestation {
        gloas::IndexedAttestation {
            attesting_indices: ProgressiveList::from(self.0.indices.clone()),
            data: self.0.data.clone(),
            signature: self.0.signature,
        }
    }
}

impl<P: Preset> PoolFork for phase0::BeaconState<P> {
    type Attestation = phase0::Attestation<P>;
    type AttesterSlashing = phase0::AttesterSlashing<P>;

    const ATTESTATION_LIMIT: u64 = P::MAX_ATTESTATIONS;
    const ATTESTER_SLASHING_LIMIT: u64 = P::MAX_ATTESTER_SLASHINGS;
    const CREDENTIAL_CHANGE_LIMIT: u64 = 0;

    /// Phase0 credits a vote once, whatever it matched, when its source is justified.
    fn eligibility(state: &Self, data: &AttestationData) -> Option<Eligibility> {
        VoteTiming::delay(state, data, Some(P::SLOTS_PER_EPOCH))?;
        let justified = if data.target.epoch == state.current_epoch() {
            state.current_justified_checkpoint
        } else {
            state.previous_justified_checkpoint
        };
        (data.source == justified).then(|| Eligibility {
            flags: ParticipationFlags::default().with(TIMELY_SOURCE_FLAG_INDEX),
        })
    }

    fn ledger(state: &mut CachedState<'_, Self>) -> Result<Ledger, PoolError> {
        Ledgers::pending(state)
    }

    fn attestation(packed: PackedAttestation) -> Result<Self::Attestation, PoolError> {
        Ok(phase0::Attestation {
            aggregation_bits: packed.sole_committee_bits()?.to_bit_list()?,
            data: packed.data,
            signature: packed.signature,
        })
    }

    fn attester_slashing(votes: &ConflictingVotes) -> Result<Self::AttesterSlashing, PoolError> {
        Ok(phase0::AttesterSlashing {
            attestation_1: Signers(&votes.first).phase0()?,
            attestation_2: Signers(&votes.second).phase0()?,
        })
    }

    fn apply_attester_slashing(
        processor: &mut BlockProcessor<'_, Self>,
        slashing: &Self::AttesterSlashing,
    ) -> Result<(), BlockError> {
        processor.apply(slashing)
    }

    fn apply_exit(
        processor: &mut BlockProcessor<'_, Self>,
        exit: &SignedVoluntaryExit,
    ) -> Result<(), BlockError> {
        processor.apply(exit)
    }
}

impl<P: Preset> PoolFork for altair::BeaconState<P> {
    type Attestation = phase0::Attestation<P>;
    type AttesterSlashing = phase0::AttesterSlashing<P>;

    const ATTESTATION_LIMIT: u64 = P::MAX_ATTESTATIONS;
    const ATTESTER_SLASHING_LIMIT: u64 = P::MAX_ATTESTER_SLASHINGS;
    const CREDENTIAL_CHANGE_LIMIT: u64 = 0;

    /// Altair credits flags, and only within one epoch of delay.
    fn eligibility(state: &Self, data: &AttestationData) -> Option<Eligibility> {
        VoteTiming::altair(state, data, Some(P::SLOTS_PER_EPOCH))
    }

    fn ledger(state: &mut CachedState<'_, Self>) -> Result<Ledger, PoolError> {
        Ok(Ledgers::flags(state.beacon()))
    }

    fn attestation(packed: PackedAttestation) -> Result<Self::Attestation, PoolError> {
        Ok(phase0::Attestation {
            aggregation_bits: packed.sole_committee_bits()?.to_bit_list()?,
            data: packed.data,
            signature: packed.signature,
        })
    }

    fn attester_slashing(votes: &ConflictingVotes) -> Result<Self::AttesterSlashing, PoolError> {
        Ok(phase0::AttesterSlashing {
            attestation_1: Signers(&votes.first).phase0()?,
            attestation_2: Signers(&votes.second).phase0()?,
        })
    }

    fn apply_attester_slashing(
        processor: &mut BlockProcessor<'_, Self>,
        slashing: &Self::AttesterSlashing,
    ) -> Result<(), BlockError> {
        processor.apply(slashing)
    }

    fn apply_exit(
        processor: &mut BlockProcessor<'_, Self>,
        exit: &SignedVoluntaryExit,
    ) -> Result<(), BlockError> {
        processor.apply(exit)
    }
}

impl<P: Preset> PoolFork for bellatrix::BeaconState<P> {
    type Attestation = phase0::Attestation<P>;
    type AttesterSlashing = phase0::AttesterSlashing<P>;

    const ATTESTATION_LIMIT: u64 = P::MAX_ATTESTATIONS;
    const ATTESTER_SLASHING_LIMIT: u64 = P::MAX_ATTESTER_SLASHINGS;
    const CREDENTIAL_CHANGE_LIMIT: u64 = 0;

    /// Altair credits flags, and only within one epoch of delay.
    fn eligibility(state: &Self, data: &AttestationData) -> Option<Eligibility> {
        VoteTiming::altair(state, data, Some(P::SLOTS_PER_EPOCH))
    }

    fn ledger(state: &mut CachedState<'_, Self>) -> Result<Ledger, PoolError> {
        Ok(Ledgers::flags(state.beacon()))
    }

    fn attestation(packed: PackedAttestation) -> Result<Self::Attestation, PoolError> {
        Ok(phase0::Attestation {
            aggregation_bits: packed.sole_committee_bits()?.to_bit_list()?,
            data: packed.data,
            signature: packed.signature,
        })
    }

    fn attester_slashing(votes: &ConflictingVotes) -> Result<Self::AttesterSlashing, PoolError> {
        Ok(phase0::AttesterSlashing {
            attestation_1: Signers(&votes.first).phase0()?,
            attestation_2: Signers(&votes.second).phase0()?,
        })
    }

    fn apply_attester_slashing(
        processor: &mut BlockProcessor<'_, Self>,
        slashing: &Self::AttesterSlashing,
    ) -> Result<(), BlockError> {
        processor.apply(slashing)
    }

    fn apply_exit(
        processor: &mut BlockProcessor<'_, Self>,
        exit: &SignedVoluntaryExit,
    ) -> Result<(), BlockError> {
        processor.apply(exit)
    }
}

impl<P: Preset> PoolFork for capella::BeaconState<P> {
    type Attestation = phase0::Attestation<P>;
    type AttesterSlashing = phase0::AttesterSlashing<P>;

    const ATTESTATION_LIMIT: u64 = P::MAX_ATTESTATIONS;
    const ATTESTER_SLASHING_LIMIT: u64 = P::MAX_ATTESTER_SLASHINGS;
    const CREDENTIAL_CHANGE_LIMIT: u64 = P::MAX_BLS_TO_EXECUTION_CHANGES;

    /// Altair credits flags, and only within one epoch of delay.
    fn eligibility(state: &Self, data: &AttestationData) -> Option<Eligibility> {
        VoteTiming::altair(state, data, Some(P::SLOTS_PER_EPOCH))
    }

    fn ledger(state: &mut CachedState<'_, Self>) -> Result<Ledger, PoolError> {
        Ok(Ledgers::flags(state.beacon()))
    }

    fn attestation(packed: PackedAttestation) -> Result<Self::Attestation, PoolError> {
        Ok(phase0::Attestation {
            aggregation_bits: packed.sole_committee_bits()?.to_bit_list()?,
            data: packed.data,
            signature: packed.signature,
        })
    }

    fn attester_slashing(votes: &ConflictingVotes) -> Result<Self::AttesterSlashing, PoolError> {
        Ok(phase0::AttesterSlashing {
            attestation_1: Signers(&votes.first).phase0()?,
            attestation_2: Signers(&votes.second).phase0()?,
        })
    }

    fn apply_attester_slashing(
        processor: &mut BlockProcessor<'_, Self>,
        slashing: &Self::AttesterSlashing,
    ) -> Result<(), BlockError> {
        processor.apply(slashing)
    }

    fn apply_exit(
        processor: &mut BlockProcessor<'_, Self>,
        exit: &SignedVoluntaryExit,
    ) -> Result<(), BlockError> {
        processor.apply(exit)
    }
}

impl<P: Preset> PoolFork for deneb::BeaconState<P> {
    type Attestation = phase0::Attestation<P>;
    type AttesterSlashing = phase0::AttesterSlashing<P>;

    const ATTESTATION_LIMIT: u64 = P::MAX_ATTESTATIONS;
    const ATTESTER_SLASHING_LIMIT: u64 = P::MAX_ATTESTER_SLASHINGS;
    const CREDENTIAL_CHANGE_LIMIT: u64 = P::MAX_BLS_TO_EXECUTION_CHANGES;

    /// Deneb lifted the one-epoch window on inclusion, see EIP-7045.
    fn eligibility(state: &Self, data: &AttestationData) -> Option<Eligibility> {
        VoteTiming::altair(state, data, None)
    }

    fn ledger(state: &mut CachedState<'_, Self>) -> Result<Ledger, PoolError> {
        Ok(Ledgers::flags(state.beacon()))
    }

    fn attestation(packed: PackedAttestation) -> Result<Self::Attestation, PoolError> {
        Ok(phase0::Attestation {
            aggregation_bits: packed.sole_committee_bits()?.to_bit_list()?,
            data: packed.data,
            signature: packed.signature,
        })
    }

    fn attester_slashing(votes: &ConflictingVotes) -> Result<Self::AttesterSlashing, PoolError> {
        Ok(phase0::AttesterSlashing {
            attestation_1: Signers(&votes.first).phase0()?,
            attestation_2: Signers(&votes.second).phase0()?,
        })
    }

    fn apply_attester_slashing(
        processor: &mut BlockProcessor<'_, Self>,
        slashing: &Self::AttesterSlashing,
    ) -> Result<(), BlockError> {
        processor.apply(slashing)
    }

    fn apply_exit(
        processor: &mut BlockProcessor<'_, Self>,
        exit: &SignedVoluntaryExit,
    ) -> Result<(), BlockError> {
        processor.apply(&DenebExit(exit))
    }
}

impl<P: Preset> PoolFork for electra::BeaconState<P> {
    type Attestation = electra::Attestation<P>;
    type AttesterSlashing = electra::AttesterSlashing<P>;

    const ATTESTATION_LIMIT: u64 = P::MAX_ATTESTATIONS_ELECTRA;
    const ATTESTER_SLASHING_LIMIT: u64 = P::MAX_ATTESTER_SLASHINGS_ELECTRA;
    const CREDENTIAL_CHANGE_LIMIT: u64 = P::MAX_BLS_TO_EXECUTION_CHANGES;

    /// Electra votes name their committees beside the data, whose index is zero, see EIP-7549.
    fn eligibility(state: &Self, data: &AttestationData) -> Option<Eligibility> {
        VoteTiming::electra(state, data)
    }

    fn ledger(state: &mut CachedState<'_, Self>) -> Result<Ledger, PoolError> {
        Ok(Ledgers::flags(state.beacon()))
    }

    fn attestation(packed: PackedAttestation) -> Result<Self::Attestation, PoolError> {
        let mut committee_bits = electra::CommitteeBits::<P>::new();
        for (committee, _) in &packed.committees {
            committee_bits.set(committee.as_usize(), true);
        }
        Ok(electra::Attestation {
            aggregation_bits: packed.joined_bits().to_bit_list()?,
            data: packed.data,
            signature: packed.signature,
            committee_bits,
        })
    }

    fn attester_slashing(votes: &ConflictingVotes) -> Result<Self::AttesterSlashing, PoolError> {
        Ok(electra::AttesterSlashing {
            attestation_1: Signers(&votes.first).electra()?,
            attestation_2: Signers(&votes.second).electra()?,
        })
    }

    fn apply_attester_slashing(
        processor: &mut BlockProcessor<'_, Self>,
        slashing: &Self::AttesterSlashing,
    ) -> Result<(), BlockError> {
        processor.apply(slashing)
    }

    fn apply_exit(
        processor: &mut BlockProcessor<'_, Self>,
        exit: &SignedVoluntaryExit,
    ) -> Result<(), BlockError> {
        processor.apply(&ElectraExit(exit))
    }
}

impl<P: Preset> PoolFork for fulu::BeaconState<P> {
    type Attestation = electra::Attestation<P>;
    type AttesterSlashing = electra::AttesterSlashing<P>;

    const ATTESTATION_LIMIT: u64 = P::MAX_ATTESTATIONS_ELECTRA;
    const ATTESTER_SLASHING_LIMIT: u64 = P::MAX_ATTESTER_SLASHINGS_ELECTRA;
    const CREDENTIAL_CHANGE_LIMIT: u64 = P::MAX_BLS_TO_EXECUTION_CHANGES;

    /// Electra votes name their committees beside the data, whose index is zero, see EIP-7549.
    fn eligibility(state: &Self, data: &AttestationData) -> Option<Eligibility> {
        VoteTiming::electra(state, data)
    }

    fn ledger(state: &mut CachedState<'_, Self>) -> Result<Ledger, PoolError> {
        Ok(Ledgers::flags(state.beacon()))
    }

    fn attestation(packed: PackedAttestation) -> Result<Self::Attestation, PoolError> {
        let mut committee_bits = electra::CommitteeBits::<P>::new();
        for (committee, _) in &packed.committees {
            committee_bits.set(committee.as_usize(), true);
        }
        Ok(electra::Attestation {
            aggregation_bits: packed.joined_bits().to_bit_list()?,
            data: packed.data,
            signature: packed.signature,
            committee_bits,
        })
    }

    fn attester_slashing(votes: &ConflictingVotes) -> Result<Self::AttesterSlashing, PoolError> {
        Ok(electra::AttesterSlashing {
            attestation_1: Signers(&votes.first).electra()?,
            attestation_2: Signers(&votes.second).electra()?,
        })
    }

    fn apply_attester_slashing(
        processor: &mut BlockProcessor<'_, Self>,
        slashing: &Self::AttesterSlashing,
    ) -> Result<(), BlockError> {
        processor.apply(slashing)
    }

    fn apply_exit(
        processor: &mut BlockProcessor<'_, Self>,
        exit: &SignedVoluntaryExit,
    ) -> Result<(), BlockError> {
        processor.apply(&ElectraExit(exit))
    }
}

impl<P: Preset> PoolFork for gloas::BeaconState<P> {
    type Attestation = gloas::Attestation<P>;
    type AttesterSlashing = gloas::AttesterSlashing;

    const ATTESTATION_LIMIT: u64 = P::MAX_ATTESTATIONS_ELECTRA;
    const ATTESTER_SLASHING_LIMIT: u64 = P::MAX_ATTESTER_SLASHINGS_ELECTRA;
    const CREDENTIAL_CHANGE_LIMIT: u64 = P::MAX_BLS_TO_EXECUTION_CHANGES;

    /// Gloas votes signal the payload in the data's index: zero empty, one full.
    ///
    /// A vote for the block of its own slot must signal zero.
    /// The head credit needs the signal to match the payload the state records.
    /// See `get_attestation_participation_flag_indices` in the Gloas beacon chain spec.
    fn eligibility(state: &Self, data: &AttestationData) -> Option<Eligibility> {
        if data.index.0 >= 2 {
            return None;
        }
        let delay = VoteTiming::delay(state, data, None)?;
        let same_slot = IncludedAttestation::is_same_slot(state, data).ok()?;
        if same_slot && data.index.0 != 0 {
            return None;
        }
        let flags = VoteTiming::flags(state, data, delay, None)?;
        // The parent's slot indexes the availability that the block's own processing reads.
        let parent_slot = state.latest_block_header.slot;
        let position = (parent_slot.0 % P::SLOTS_PER_HISTORICAL_ROOT) as usize;
        let available = state
            .execution_payload_availability()
            .get(position)
            .unwrap_or_default();
        if !same_slot && data.index.0 != u64::from(available) {
            let without_head = ParticipationFlags(flags.0 & !(1 << TIMELY_HEAD_FLAG_INDEX));
            return Some(Eligibility {
                flags: without_head,
            });
        }
        Some(Eligibility { flags })
    }

    fn ledger(state: &mut CachedState<'_, Self>) -> Result<Ledger, PoolError> {
        Ok(Ledgers::flags(state.beacon()))
    }

    fn attestation(packed: PackedAttestation) -> Result<Self::Attestation, PoolError> {
        let mut committee_bits = electra::CommitteeBits::<P>::new();
        for (committee, _) in &packed.committees {
            committee_bits.set(committee.as_usize(), true);
        }
        Ok(gloas::Attestation {
            aggregation_bits: packed.joined_bits().to_progressive_bit_list(),
            data: packed.data,
            signature: packed.signature,
            committee_bits,
        })
    }

    fn attester_slashing(votes: &ConflictingVotes) -> Result<Self::AttesterSlashing, PoolError> {
        Ok(gloas::AttesterSlashing {
            attestation_1: Signers(&votes.first).gloas(),
            attestation_2: Signers(&votes.second).gloas(),
        })
    }

    fn apply_attester_slashing(
        processor: &mut BlockProcessor<'_, Self>,
        slashing: &Self::AttesterSlashing,
    ) -> Result<(), BlockError> {
        processor.apply(slashing)
    }

    fn apply_exit(
        processor: &mut BlockProcessor<'_, Self>,
        exit: &SignedVoluntaryExit,
    ) -> Result<(), BlockError> {
        processor.apply(&ElectraExit(exit))
    }
}
