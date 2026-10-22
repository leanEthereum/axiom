//! Fork vectors: the irregular state change at a fork boundary.

use std::marker::PhantomData;

use axiom_state_transition::{State, Upgrade, Verification};
use axiom_types::{ChainConfig, Preset, accessors::ForkState};
use axiom_yaml::Yaml;

use crate::{Case, Failure, Runner, forks::SpecFork};

/// Upgrades the pre-fork state, and compares with the post-fork state.
///
/// The upgrade runs through the state wrapper, the same path slot processing takes.
#[derive(Debug, Default)]
pub struct Fork<P, F>(PhantomData<(P, F)>);

impl<P: Preset, F: SpecFork> Runner for Fork<P, F>
where
    F::State<P>: Upgrade,
{
    fn name(&self) -> &'static str {
        "fork"
    }

    fn run_case(&self, _handler: &str, case: &Case) -> Result<(), Failure> {
        let fork = case
            .yaml("meta.yaml")?
            .get("fork")
            .and_then(Yaml::as_str)
            .map(str::to_owned);
        if fork.as_deref() != Some(F::FORK.as_str()) {
            return Err(Failure(format!(
                "case upgrades to {fork:?}, the runner to {}",
                F::FORK
            )));
        }
        let config = ChainConfig::for_preset::<P>().with_forks_at_genesis(F::FORK);
        let pre = case.ssz::<<F::State<P> as Upgrade>::Previous>("pre")?;
        let mut state = State::new(pre.into_any());
        if case.meta()?.bls_ignored() {
            state.set_verification(Verification::Skip);
        }
        state
            .upgrade(&config)
            .map_err(|error| Failure(format!("upgrade failed: {error}")))?;

        let expected = case.ssz::<F::State<P>>("post")?;
        let actual = F::State::<P>::from_any(state.beacon()).ok_or_else(|| {
            Failure(format!(
                "upgraded state is {}, the vector's is {}",
                state.fork_name(),
                F::FORK
            ))
        })?;
        F::STATE_FIELDS.check(&expected, actual)
    }
}
