//! Genesis vectors: the candidate state from eth1 deposits, and its validity.

use std::marker::PhantomData;

use axiom_state_transition::phase0::Genesis as Eth1Genesis;
use axiom_types::{ChainConfig, ForkName, Hash32, Preset, phase0};
use axiom_yaml::Yaml;

use crate::{
    Case, Failure, Runner,
    forks::{Phase0, SpecFork},
};

/// Builds genesis states from deposits, and judges candidate states.
///
/// Only phase0 ships these vectors, since genesis never changed with later forks.
#[derive(Debug, Default)]
pub struct Genesis<P>(PhantomData<P>);

impl<P: Preset> Genesis<P> {
    /// Builds the state from the case's eth1 block and deposits, and compares it.
    fn initialization(case: &Case, config: &ChainConfig) -> Result<(), Failure> {
        let eth1 = case.yaml("eth1.yaml")?;
        let eth1_block_hash = eth1
            .get("eth1_block_hash")
            .and_then(Yaml::as_hex_array::<32>)
            .map(Hash32)
            .ok_or_else(|| Failure::new("eth1.yaml has no block hash"))?;
        let eth1_timestamp = eth1
            .get("eth1_timestamp")
            .and_then(Yaml::as_u64)
            .ok_or_else(|| Failure::new("eth1.yaml has no timestamp"))?;
        let count = case
            .yaml("meta.yaml")?
            .get("deposits_count")
            .and_then(Yaml::as_u64)
            .ok_or_else(|| Failure::new("meta.yaml has no deposit count"))?;
        let deposits = (0..count)
            .map(|index| case.ssz::<phase0::Deposit>(&format!("deposits_{index}")))
            .collect::<Result<Vec<_>, _>>()?;

        let genesis = Eth1Genesis {
            eth1_block_hash,
            eth1_timestamp,
        };
        let state = genesis
            .initialize::<P>(&deposits, config)
            .map_err(|error| Failure(format!("genesis failed: {error}")))?;
        let expected = case.ssz::<phase0::BeaconState<P>>("state")?;
        Phase0::STATE_FIELDS.check(&expected, &state)
    }

    /// Judges the case's candidate state, and compares the verdict.
    fn validity(case: &Case, config: &ChainConfig) -> Result<(), Failure> {
        let state = case.ssz::<phase0::BeaconState<P>>("genesis")?;
        let expected = case
            .yaml("is_valid.yaml")?
            .as_bool()
            .ok_or_else(|| Failure::new("is_valid.yaml is not a boolean"))?;
        let actual = Eth1Genesis::is_valid(&state, config);
        if actual != expected {
            return Err(Failure(format!(
                "genesis validity is {actual}, the vector says {expected}"
            )));
        }
        Ok(())
    }
}

impl<P: Preset> Runner for Genesis<P> {
    fn name(&self) -> &'static str {
        "genesis"
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        let config = ChainConfig::for_preset::<P>().with_forks_at_genesis(ForkName::Phase0);
        match handler {
            "initialization" => Self::initialization(case, &config),
            "validity" => Self::validity(case, &config),
            other => Err(Failure(format!("unsupported genesis handler {other}"))),
        }
    }
}
