//! Light client vectors: sync, update ranking, proofs, and full node data collection.

mod context;
mod data_collection;
mod sync;

use std::marker::PhantomData;

use axiom_light_client::{UpdateQuality, combined::LightClientUpdate};
use axiom_ssz::Root;
use axiom_types::Preset;
use axiom_yaml::Yaml;
use context::ForkContext;
use data_collection::DataCollection;
use sync::SyncCase;

use super::MerkleProofs;
use crate::{Case, Failure, Runner, forks::SpecFork};

/// Runs every light client handler of one fork's vectors.
#[derive(Debug, Default)]
pub struct LightClient<P, F>(PhantomData<(P, F)>);

impl<P: Preset, F: SpecFork> LightClient<P, F> {
    /// Checks that updates rank in the order the files list them, best first.
    fn update_ranking(case: &Case) -> Result<(), Failure> {
        let count = number(&case.yaml("meta.yaml")?, "updates_count")?;
        let qualities = (0..count)
            .map(|index| {
                let bytes = case.ssz_bytes(&format!("updates_{index}"))?;
                let update = LightClientUpdate::<P>::decode(&bytes, F::FORK)
                    .map_err(|error| Failure(error.to_string()))?;
                Ok(UpdateQuality::of(&update.into_data()))
            })
            .collect::<Result<Vec<_>, Failure>>()?;
        for (index, pair) in qualities.windows(2).enumerate() {
            if pair[1] > pair[0] {
                return Err(Failure(format!(
                    "update {} ranks above update {index}",
                    index + 1
                )));
            }
        }
        Ok(())
    }
}

impl<P: Preset, F: SpecFork> Runner for LightClient<P, F> {
    fn name(&self) -> &'static str {
        "light_client"
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        match handler {
            "sync" => SyncCase::<P>::new(case, F::FORK)?.run(),
            "update_ranking" => Self::update_ranking(case),
            "single_merkle_proof" => MerkleProofs::<P, F>::light_client().run_case(handler, case),
            "data_collection" => DataCollection::<P>::new(case, F::FORK)?.run(),
            other => Err(Failure(format!("unsupported handler {other}"))),
        }
    }
}

/// A number field of a mapping.
fn number(value: &Yaml, key: &str) -> Result<u64, Failure> {
    value
        .get(key)
        .and_then(Yaml::as_u64)
        .ok_or_else(|| Failure(format!("missing number {key}")))
}

/// A root field of a mapping.
fn root(value: &Yaml, key: &str) -> Result<Root, Failure> {
    value
        .get(key)
        .and_then(Yaml::as_hex_array::<32>)
        .map(Root)
        .ok_or_else(|| Failure(format!("missing root {key}")))
}
