//! Rewards vectors: the per-component deltas of an epoch's accounting.

use std::marker::PhantomData;

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List};
use axiom_state_transition::{
    ActiveBalance, State,
    altair::epoch::{Deltas, Participation},
    phase0::epoch::{AttestationRewards, PendingParticipation, VotePart},
};
use axiom_types::{
    ChainConfig, Gwei, Preset,
    accessors::ParticipationState,
    constants::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX},
    phase0,
};

use crate::{Case, Failure, Runner, forks::SpecFork};

/// The deltas container of the rewards test format.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct DeltasVector<P: Preset> {
    /// Rewards per validator.
    rewards: List<Gwei, P::ValidatorRegistryLimit>,
    /// Penalties per validator.
    penalties: List<Gwei, P::ValidatorRegistryLimit>,
}

impl<P: Preset> Container for DeltasVector<P> {
    const FIELDS: &'static [Option<usize>] = &[None, None];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.rewards);
        visitor.field(&self.penalties);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            rewards: fields.field()?,
            penalties: fields.field()?,
        })
    }
}

impl<P: Preset> DeltasVector<P> {
    /// Compares computed deltas with a vector file.
    fn check(case: &Case, stem: &str, rewards: &[Gwei], penalties: &[Gwei]) -> Result<(), Failure> {
        let expected = case.ssz::<Self>(stem)?;
        if expected.rewards.as_slice() != rewards {
            return Err(Failure(format!("{stem}: rewards differ")));
        }
        if expected.penalties.as_slice() != penalties {
            return Err(Failure(format!("{stem}: penalties differ")));
        }
        Ok(())
    }
}

/// Computes every component's deltas, and compares each with its vector.
///
/// The components are Altair's participation flags, so this serves Altair and later forks.
#[derive(Debug, Default)]
pub struct Rewards<P, F>(PhantomData<(P, F)>);

impl<P: Preset, F: SpecFork> Rewards<P, F> {
    /// Compares computed deltas with a vector file.
    fn compare(case: &Case, stem: &str, computed: &Deltas) -> Result<(), Failure> {
        DeltasVector::<P>::check(case, stem, &computed.rewards, &computed.penalties)
    }
}

impl<P: Preset, F: SpecFork> Runner for Rewards<P, F>
where
    F::State<P>: ParticipationState,
{
    fn name(&self) -> &'static str {
        "rewards"
    }

    fn run_case(&self, _handler: &str, case: &Case) -> Result<(), Failure> {
        let config = ChainConfig::for_preset::<P>().with_forks_at_genesis(F::FORK);
        let state = case.ssz::<F::State<P>>("pre")?;
        let participation = Participation::new(&state, ActiveBalance::of(&state));
        Self::compare(
            case,
            "source_deltas",
            &Deltas::flag_index(&participation, TIMELY_SOURCE_FLAG_INDEX),
        )?;
        Self::compare(
            case,
            "target_deltas",
            &Deltas::flag_index(&participation, TIMELY_TARGET_FLAG_INDEX),
        )?;
        Self::compare(
            case,
            "head_deltas",
            &Deltas::flag_index(&participation, TIMELY_HEAD_FLAG_INDEX),
        )?;
        Self::compare(
            case,
            "inactivity_penalty_deltas",
            &Deltas::inactivity_penalties(&participation, &config),
        )
    }
}

/// Computes phase0's component deltas from pending attestations, and compares each with its vector.
///
/// Phase0 has no participation flags.
/// It pays the source, target, and head votes, the inclusion delay, and the inactivity leak.
#[derive(Debug, Default)]
pub struct PendingAttestationRewards<P>(PhantomData<P>);

impl<P: Preset> Runner for PendingAttestationRewards<P> {
    fn name(&self) -> &'static str {
        "rewards"
    }

    fn run_case(&self, _handler: &str, case: &Case) -> Result<(), Failure> {
        let mut state = State::new(case.ssz::<phase0::BeaconState<P>>("pre")?);
        let mut typed = state
            .of_fork::<phase0::BeaconState<P>>()
            .ok_or_else(|| Failure::new("pre-state is not a phase0 state"))?;
        let total = ActiveBalance::of(typed.beacon());
        let participation = PendingParticipation::new(&mut typed, total)
            .map_err(|error| Failure(format!("participation: {error}")))?;
        let rewards = AttestationRewards::new(typed.beacon(), &participation);
        for (stem, part) in [
            ("source_deltas", VotePart::Source),
            ("target_deltas", VotePart::Target),
            ("head_deltas", VotePart::Head),
        ] {
            let deltas = rewards.vote_deltas(part);
            DeltasVector::<P>::check(case, stem, &deltas.rewards, &deltas.penalties)?;
        }
        let inclusion = rewards
            .inclusion_delay_deltas()
            .map_err(|error| Failure(format!("inclusion delay: {error}")))?;
        DeltasVector::<P>::check(
            case,
            "inclusion_delay_deltas",
            &inclusion.rewards,
            &inclusion.penalties,
        )?;
        let inactivity = rewards.inactivity_penalty_deltas();
        DeltasVector::<P>::check(
            case,
            "inactivity_penalty_deltas",
            &inactivity.rewards,
            &inactivity.penalties,
        )
    }
}
