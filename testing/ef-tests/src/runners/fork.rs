//! Fork vectors: the irregular state change at a fork boundary.

use std::marker::PhantomData;

use axiom_state_transition::State;
use axiom_types::{ChainConfig, Preset, electra, fulu::BeaconState};
use axiom_yaml::Yaml;

use super::BEACON_STATE_FIELDS;
use crate::{Case, Failure, Runner};

/// Upgrades the pre-fork state, and compares with the post-fork state.
#[derive(Debug, Default)]
pub struct Fork<P>(PhantomData<P>);

impl<P: Preset> Runner for Fork<P> {
    fn name(&self) -> &'static str {
        "fork"
    }

    fn run_case(&self, _handler: &str, case: &Case) -> Result<(), Failure> {
        let fork = case
            .yaml("meta.yaml")?
            .get("fork")
            .and_then(Yaml::as_str)
            .map(str::to_owned);
        if fork.as_deref() != Some("fulu") {
            return Err(Failure(format!("unsupported fork {fork:?}")));
        }
        let pre = case.ssz::<electra::BeaconState<P>>("pre")?;
        let state = State::upgrade_from_electra(
            pre,
            &ChainConfig::for_preset::<P>().with_forks_at_genesis(),
        )
        .map_err(|error| Failure(format!("upgrade failed: {error}")))?;
        let expected = case.ssz::<BeaconState<P>>("post")?;
        BEACON_STATE_FIELDS.check(&expected, state.beacon())
    }
}
