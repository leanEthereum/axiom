//! Block vectors: sanity, finality, and random chains of blocks, and empty slots.

use std::marker::PhantomData;

use axiom_state_transition::{KnownVerdict, State, Verification};
use axiom_types::{
    ChainConfig, Preset, Slot,
    fulu::{BeaconState, SignedBeaconBlock},
};

use super::BEACON_STATE_FIELDS;
use crate::{Case, Failure, Runner};

/// Applies a chain of blocks through the full state transition.
///
/// The sanity, finality, and random runners share this format.
#[derive(Debug)]
pub struct Blocks<P> {
    /// The runner directory these vectors live under.
    runner: &'static str,
    /// The preset.
    preset: PhantomData<P>,
}

impl<P: Preset> Blocks<P> {
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
            preset: PhantomData,
        }
    }

    /// Applies every block in order, and checks the outcome.
    fn run_blocks(case: &Case) -> Result<(), Failure> {
        let config = ChainConfig::for_preset::<P>().with_forks_at_genesis();
        let meta = case.meta()?;
        let verification = if meta.bls_ignored() {
            Verification::Skip
        } else {
            Verification::Verify
        };
        let mut state = State::new(case.ssz::<BeaconState<P>>("pre")?);
        let expected = case.ssz_if_present::<BeaconState<P>>("post")?;

        let mut outcome = Ok(());
        for index in 0..meta.blocks_count {
            let block = match case.ssz::<SignedBeaconBlock<P>>(&format!("blocks_{index}")) {
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
            (Ok(()), Some(expected)) => BEACON_STATE_FIELDS.check(&expected, state.beacon()),
            (Err(_), None) => Ok(()),
            (Ok(()), None) => Err(Failure::new("blocks accepted, the vector rejects them")),
            (Err(error), Some(_)) => Err(Failure(error)),
        }
    }

    /// Advances through empty slots, and checks the post-state.
    fn run_slots(case: &Case) -> Result<(), Failure> {
        let config = ChainConfig::for_preset::<P>().with_forks_at_genesis();
        let slots = case
            .yaml("slots.yaml")?
            .as_u64()
            .ok_or_else(|| Failure::new("slots.yaml is not a number"))?;
        let mut state = State::new(case.ssz::<BeaconState<P>>("pre")?);
        let target = Slot(state.beacon().slot.0 + slots);
        state
            .process_slots(&config, target)
            .map_err(|error| Failure(format!("slot processing failed: {error}")))?;
        let expected = case.ssz::<BeaconState<P>>("post")?;
        BEACON_STATE_FIELDS.check(&expected, state.beacon())
    }
}

impl<P: Preset> Runner for Blocks<P> {
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
