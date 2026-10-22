//! Epoch processing vectors: one sub-transition, and optionally the whole epoch.

use std::marker::PhantomData;

use axiom_state_transition::{EpochProcessor, EpochStep, State, Verification};
use axiom_types::{ChainConfig, Preset, accessors::ForkState};

use crate::{Case, Failure, Runner, forks::SpecFork};

/// Runs the handler's sub-transition, then the full transition when the case provides one.
///
/// The fork's own rules decide each step, so one runner serves every fork.
#[derive(Debug, Default)]
pub struct EpochProcessing<P, F>(PhantomData<(P, F)>);

impl<P: Preset, F: SpecFork> EpochProcessing<P, F> {
    /// Runs one step, or the whole transition, on a state file.
    fn run(
        case: &Case,
        stem: &str,
        config: &ChainConfig,
        verification: Verification,
        step: Option<EpochStep>,
    ) -> Result<Option<Result<State<P>, String>>, Failure> {
        let Some(pre) = case.ssz_if_present::<F::State<P>>(stem)? else {
            return Ok(None);
        };
        let mut state = State::new(pre.into_any());
        state.set_verification(verification);
        let typed = state
            .of_fork::<F::State<P>>()
            .ok_or_else(|| Failure::new("pre-state is not of the case's fork"))?;
        let mut processor = EpochProcessor::new(typed, config);
        let outcome = match step {
            Some(step) => processor.run(step),
            None => processor.process(),
        };
        Ok(Some(
            outcome.map(|()| state).map_err(|error| error.to_string()),
        ))
    }

    /// Compares an outcome with the expected state file, or with its absence.
    fn compare(case: &Case, stem: &str, outcome: Result<State<P>, String>) -> Result<(), Failure> {
        match (outcome, case.ssz_if_present::<F::State<P>>(stem)?) {
            (Ok(state), Some(expected)) => {
                let actual = F::State::<P>::from_any(state.beacon())
                    .ok_or_else(|| Failure::new("post-state left the case's fork"))?;
                F::STATE_FIELDS.check(&expected, actual)
            }
            (Err(_), None) => Ok(()),
            (Ok(_), None) => Err(Failure(format!("{stem}: succeeded, the vector rejects it"))),
            (Err(error), Some(_)) => Err(Failure(format!("{stem}: failed: {error}"))),
        }
    }
}

impl<P: Preset, F: SpecFork> Runner for EpochProcessing<P, F> {
    fn name(&self) -> &'static str {
        "epoch_processing"
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        let step = EpochStep::from_name(handler)
            .ok_or_else(|| Failure(format!("unsupported epoch step {handler}")))?;
        let config = ChainConfig::for_preset::<P>().with_forks_at_genesis(F::FORK);
        let verification = if case.meta()?.bls_ignored() {
            Verification::Skip
        } else {
            Verification::Verify
        };

        // Phase 1: the sub-transition on its own.
        let outcome = Self::run(case, "pre", &config, verification, Some(step))?
            .ok_or_else(|| Failure::new("case has no pre-state"))?;
        Self::compare(case, "post", outcome)?;

        // Phase 2: the whole epoch transition, when the case carries its endpoints.
        if let Some(outcome) = Self::run(case, "pre_epoch", &config, verification, None)? {
            Self::compare(case, "post_epoch", outcome)?;
        }
        Ok(())
    }
}
