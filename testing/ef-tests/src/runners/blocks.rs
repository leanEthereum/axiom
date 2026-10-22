//! Block vectors: sanity, finality, and random chains of blocks, and empty slots.

use std::marker::PhantomData;

use axiom_state_transition::{KnownVerdict, State, Verification};
use axiom_types::{
    ChainConfig, Preset, Slot,
    accessors::{CoreState, ForkState},
};

use crate::{Case, Failure, Runner, forks::SpecFork};

/// Applies a chain of blocks through the full state transition.
///
/// The sanity, finality, and random runners share this format.
#[derive(Debug)]
pub struct Blocks<P, F> {
    /// The runner directory these vectors live under.
    runner: &'static str,
    /// The preset and the fork.
    marker: PhantomData<(P, F)>,
}

impl<P: Preset, F: SpecFork> Blocks<P, F> {
    /// The sanity runner, with its blocks and slots handlers.
    #[must_use]
    pub const fn sanity() -> Self {
        Self::named("sanity")
    }

    /// The finality runner.
    #[must_use]
    pub const fn finality() -> Self {
        Self::named("finality")
    }

    /// The random runner.
    #[must_use]
    pub const fn random() -> Self {
        Self::named("random")
    }

    /// A runner for a directory name.
    const fn named(runner: &'static str) -> Self {
        Self {
            runner,
            marker: PhantomData,
        }
    }

    /// Applies every block in order, and checks the outcome.
    fn run_blocks(case: &Case) -> Result<(), Failure> {
        let config = ChainConfig::for_preset::<P>().with_forks_at_genesis(F::FORK);
        let meta = case.meta()?;
        let verification = if meta.bls_ignored() {
            Verification::Skip
        } else {
            Verification::Verify
        };
        let mut state = State::new(case.ssz::<F::State<P>>("pre")?.into_any());
        let expected = case.ssz_if_present::<F::State<P>>("post")?;

        let mut outcome = Ok(());
        for index in 0..meta.blocks_count {
            let block = match case.ssz::<F::SignedBeaconBlock<P>>(&format!("blocks_{index}")) {
                Ok(block) => block,
                Err(failure) => {
                    outcome = Err(failure.to_string());
                    break;
                }
            };
            if let Err(error) =
                state.state_transition(&config, &block, verification, &KnownVerdict(true))
            {
                outcome = Err(format!("block {index}: {error}"));
                break;
            }
        }

        match (outcome, expected) {
            (Ok(()), Some(expected)) => Self::check(&expected, &state),
            (Err(_), None) => Ok(()),
            (Ok(()), None) => Err(Failure::new("blocks accepted, the vector rejects them")),
            (Err(error), Some(_)) => Err(Failure(error)),
        }
    }

    /// Advances through empty slots, and checks the post-state.
    fn run_slots(case: &Case) -> Result<(), Failure> {
        let config = ChainConfig::for_preset::<P>().with_forks_at_genesis(F::FORK);
        let slots = case
            .yaml("slots.yaml")?
            .as_u64()
            .ok_or_else(|| Failure::new("slots.yaml is not a number"))?;
        let mut state = State::new(case.ssz::<F::State<P>>("pre")?.into_any());
        let target = Slot(state.beacon().slot().0 + slots);
        state
            .process_slots(&config, target)
            .map_err(|error| Failure(format!("slot processing failed: {error}")))?;
        let expected = case.ssz::<F::State<P>>("post")?;
        Self::check(&expected, &state)
    }

    /// Compares a post-state of the case's fork with the expected one, field by field.
    fn check(expected: &F::State<P>, state: &State<P>) -> Result<(), Failure> {
        let actual = F::State::<P>::from_any(state.beacon()).ok_or_else(|| {
            Failure(format!(
                "post-state is {}, the vector's is {}",
                state.fork_name(),
                F::FORK
            ))
        })?;
        F::STATE_FIELDS.check(expected, actual)
    }
}

impl<P: Preset, F: SpecFork> Runner for Blocks<P, F> {
    fn name(&self) -> &'static str {
        self.runner
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        match handler {
            "blocks" | "finality" | "random" => Self::run_blocks(case),
            "slots" => Self::run_slots(case),
            other => Err(Failure(format!("unsupported handler {other}"))),
        }
    }
}
