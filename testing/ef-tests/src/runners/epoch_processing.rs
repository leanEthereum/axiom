//! Epoch processing vectors: one sub-transition, and optionally the whole epoch.

use std::marker::PhantomData;

use axiom_state_transition::{EpochProcessor, EpochStep, State, Verification};
use axiom_types::{BeaconState, ChainConfig, Preset};

use super::BEACON_STATE_FIELDS;
use crate::{Case, Failure, Runner};

/// Runs the handler's sub-transition, then the full transition when the case provides one.
#[derive(Debug, Default)]
pub struct EpochProcessing<P>(PhantomData<P>);

impl<P: Preset> Runner for EpochProcessing<P> {
    fn name(&self) -> &'static str {
        "epoch_processing"
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        let step = EpochStep::from_name(handler)
            .ok_or_else(|| Failure(format!("unsupported epoch step {handler}")))?;
        let config = ChainConfig::for_preset::<P>().with_forks_at_genesis();
        let verification = if case.meta()?.bls_ignored() {
            Verification::Skip
        } else {
            Verification::Verify
        };

        // Phase 1: the sub-transition on its own.
        let mut state = State::new(case.ssz::<BeaconState<P>>("pre")?);
        state.set_verification(verification);
        let outcome = EpochProcessor::new(&mut state, &config).run(step);
        match (outcome, case.ssz_if_present::<BeaconState<P>>("post")?) {
            (Ok(()), Some(expected)) => {
                BEACON_STATE_FIELDS.check(&expected, state.beacon())?;
            }
            (Err(_), None) => {}
            (Ok(()), None) => return Err(Failure::new("step succeeded, the vector rejects it")),
            (Err(error), Some(_)) => return Err(Failure(format!("step failed: {error}"))),
        }

        // Phase 2: the whole epoch transition, when the case carries its endpoints.
        if let Some(pre_epoch) = case.ssz_if_present::<BeaconState<P>>("pre_epoch")? {
            let mut state = State::new(pre_epoch);
            state.set_verification(verification);
            let outcome = EpochProcessor::new(&mut state, &config).process();
            match (
                outcome,
                case.ssz_if_present::<BeaconState<P>>("post_epoch")?,
            ) {
                (Ok(()), Some(expected)) => {
                    BEACON_STATE_FIELDS
                        .check(&expected, state.beacon())
                        .map_err(|failure| Failure(format!("full epoch: {failure}")))?;
                }
                (Err(_), None) => {}
                (Ok(()), None) => {
                    return Err(Failure::new("full epoch succeeded, the vector rejects it"));
                }
                (Err(error), Some(_)) => {
                    return Err(Failure(format!("full epoch failed: {error}")));
                }
            }
        }
        Ok(())
    }
}
