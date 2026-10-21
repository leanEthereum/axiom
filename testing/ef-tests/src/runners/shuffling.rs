//! Shuffling vectors: the swap-or-not permutation.

use std::marker::PhantomData;

use axiom_state_transition::SwapOrNot;
use axiom_types::{Bytes32, Preset};
use axiom_yaml::Yaml;

use crate::{Case, Failure, Runner};

/// Checks the permutation, and each index of it, against the vector's mapping.
#[derive(Debug, Default)]
pub struct Shuffling<P>(PhantomData<P>);

impl<P: Preset> Runner for Shuffling<P> {
    fn name(&self) -> &'static str {
        "shuffling"
    }

    fn run_case(&self, _handler: &str, case: &Case) -> Result<(), Failure> {
        let yaml = case.yaml("mapping.yaml")?;
        let seed = yaml
            .get("seed")
            .and_then(|seed| seed.as_hex_array::<32>())
            .ok_or_else(|| Failure::new("mapping.yaml has no seed"))?;
        let count = yaml
            .get("count")
            .and_then(Yaml::as_u64)
            .ok_or_else(|| Failure::new("mapping.yaml has no count"))?;
        let mapping: Vec<u64> = yaml
            .get("mapping")
            .and_then(Yaml::as_sequence)
            .ok_or_else(|| Failure::new("mapping.yaml has no mapping"))?
            .iter()
            .map(|entry| {
                entry
                    .as_u64()
                    .ok_or_else(|| Failure::new("mapping entry is not a number"))
            })
            .collect::<Result<_, _>>()?;

        let shuffle = SwapOrNot::new(Bytes32(seed), P::SHUFFLE_ROUND_COUNT);
        if shuffle.permutation(count) != mapping {
            return Err(Failure::new("permutation differs"));
        }
        for (index, image) in mapping.iter().enumerate() {
            if shuffle.shuffled_index(index as u64, count) != *image {
                return Err(Failure(format!("index {index} maps elsewhere")));
            }
        }
        Ok(())
    }
}
