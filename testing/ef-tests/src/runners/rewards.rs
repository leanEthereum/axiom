//! Rewards vectors: the per-component deltas of an epoch's accounting.

use std::marker::PhantomData;

use axiom_ssz::{Container, DecodeError, FieldDecoder, FieldVisitor, List};
use axiom_state_transition::{Deltas, EpochProcessor, State};
use axiom_types::{
    BeaconState, Gwei, Preset,
    constants::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX},
};

use super::config_of;
use crate::{Case, Failure, Runner};

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
#[derive(Debug, Default)]
pub struct Rewards<P>(PhantomData<P>);

impl<P: Preset> Rewards<P> {
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

impl<P: Preset> Runner for Rewards<P> {
    fn name(&self) -> &'static str {
        "rewards"
    }

    fn run_case(&self, _handler: &str, case: &Case) -> Result<(), Failure> {
        let config = config_of::<P>();
        let mut state = State::new(case.ssz::<BeaconState<P>>("pre")?);
        let processor = EpochProcessor::new(&mut state, &config);
        Self::compare(
            case,
            "source_deltas",
            &processor.flag_index_deltas(TIMELY_SOURCE_FLAG_INDEX),
        )?;
        Self::compare(
            case,
            "target_deltas",
            &processor.flag_index_deltas(TIMELY_TARGET_FLAG_INDEX),
        )?;
        Self::compare(
            case,
            "head_deltas",
            &processor.flag_index_deltas(TIMELY_HEAD_FLAG_INDEX),
        )?;
        Self::compare(
            case,
            "inactivity_penalty_deltas",
            &processor.inactivity_penalty_deltas(),
        )
    }
}
