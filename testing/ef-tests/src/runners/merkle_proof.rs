//! Merkle proof vectors: single-leaf proofs into containers.

use std::marker::PhantomData;

use axiom_ssz::{GeneralizedIndex, Root, Ssz};
use axiom_types::{BeaconBlockBody, BeaconState, Preset};
use axiom_yaml::Yaml;

use crate::{Case, Failure, Runner};

/// Builds the proof the vector names, and checks the leaf, the branch, and the root.
///
/// The merkle_proof runner and the light client runner's single_merkle_proof handler share it.
#[derive(Debug)]
pub struct MerkleProofs<P> {
    /// The runner directory these vectors live under.
    runner: &'static str,
    /// The preset.
    preset: PhantomData<P>,
}

impl<P: Preset> MerkleProofs<P> {
    /// The merkle_proof runner.
    #[must_use]
    pub const fn merkle_proof() -> Self {
        Self {
            runner: "merkle_proof",
            preset: PhantomData,
        }
    }

    /// The single_merkle_proof handler of the light client runner.
    #[must_use]
    pub const fn light_client() -> Self {
        Self {
            runner: "light_client",
            preset: PhantomData,
        }
    }

    /// Proves the vector's index in an object, and compares with the vector.
    fn check<T: Ssz>(case: &Case) -> Result<(), Failure> {
        let object = case.ssz::<T>("object")?;
        let proof = case.yaml("proof.yaml")?;
        let leaf = proof
            .get("leaf")
            .and_then(Yaml::as_hex_array::<32>)
            .map(Root)
            .ok_or_else(|| Failure::new("proof.yaml has no leaf"))?;
        let index = proof
            .get("leaf_index")
            .and_then(Yaml::as_u64)
            .map(GeneralizedIndex::new)
            .ok_or_else(|| Failure::new("proof.yaml has no leaf_index"))?;
        let branch: Vec<Root> = proof
            .get("branch")
            .and_then(Yaml::as_sequence)
            .ok_or_else(|| Failure::new("proof.yaml has no branch"))?
            .iter()
            .map(|node| {
                node.as_hex_array::<32>()
                    .map(Root)
                    .ok_or_else(|| Failure::new("branch node is not hex"))
            })
            .collect::<Result<_, _>>()?;

        let (computed_leaf, computed) = object
            .prove(index)
            .ok_or_else(|| Failure::new("index is not provable"))?;
        if computed_leaf != leaf {
            return Err(Failure(format!("leaf {computed_leaf} is not {leaf}")));
        }
        if computed.branch != branch {
            return Err(Failure::new("branch differs"));
        }
        if !computed.verify(leaf, index, object.hash_tree_root()) {
            return Err(Failure::new("proof does not verify"));
        }
        Ok(())
    }
}

impl<P: Preset> Runner for MerkleProofs<P> {
    fn name(&self) -> &'static str {
        self.runner
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        if handler != "single_merkle_proof" {
            return Err(Failure(format!("unsupported handler {handler}")));
        }
        // The object type is the directory above the suite: tests/.../single_merkle_proof/<type>/<case>.
        let object_type = case
            .path()
            .parent()
            .and_then(|parent| parent.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        match object_type.as_str() {
            "BeaconBlockBody" => Self::check::<BeaconBlockBody<P>>(case),
            "BeaconState" => Self::check::<BeaconState<P>>(case),
            other => Err(Failure(format!("unsupported object type {other}"))),
        }
    }
}
