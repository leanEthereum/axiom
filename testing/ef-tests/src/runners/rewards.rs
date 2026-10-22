//! Rewards vectors: the per-component deltas of an epoch's accounting.

use std::marker::PhantomData;

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List};
use axiom_state_transition::{
    ActiveBalance,
    altair::epoch::{Deltas, Participation},
};
use axiom_types::{
    ChainConfig, Gwei, Preset,
    accessors::ParticipationState,
    constants::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX},
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

/// Computes every component's deltas, and compares each with its vector.
///
/// The components are Altair's participation flags, so this serves Altair and later forks.
#[derive(Debug, Default)]
pub struct Rewards<P, F>(PhantomData<(P, F)>);

impl<P: Preset, F: SpecFork> Rewards<P, F> {
    /// Compares computed deltas with a vector file.
    fn compare(case: &Case, stem: &str, computed: &Deltas) -> Result<(), Failure> {
        let expected = case.ssz::<DeltasVector<P>>(stem)?;
        if expected.rewards.as_slice() != computed.rewards.as_slice() {
            return Err(Failure(format!("{stem}: rewards differ")));
        }
        if expected.penalties.as_slice() != computed.penalties.as_slice() {
            return Err(Failure(format!("{stem}: penalties differ")));
        }
        Ok(())
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
