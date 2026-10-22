//! Networking vectors: custody assignment, and gossip validation, for one fork.

use std::marker::PhantomData;

use axiom_das::{CustodyGroup, NodeId};
use axiom_ssz::U256;
use axiom_types::{ChainConfig, Preset};
use axiom_yaml::Yaml;

use super::gossip::GossipCase;
use crate::{Case, Failure, Runner, forks::SpecFork};

/// Checks custody assignment and gossip validation against one fork's vectors.
#[derive(Debug, Default)]
pub struct Networking<P, F>(PhantomData<(P, F)>);

impl<P: Preset, F: SpecFork> Networking<P, F> {
    /// The expected result list of a case.
    fn result(meta: &Yaml) -> Result<Vec<u64>, Failure> {
        meta.get("result")
            .and_then(Yaml::as_sequence)
            .ok_or_else(|| Failure::new("meta.yaml has no result"))?
            .iter()
            .map(|entry| {
                entry
                    .as_u64()
                    .ok_or_else(|| Failure::new("result entry is not a number"))
            })
            .collect()
    }
}

impl<P: Preset, F: SpecFork> Runner for Networking<P, F> {
    fn name(&self) -> &'static str {
        "networking"
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        let config = ChainConfig::for_preset::<P>().with_forks_at_genesis(F::FORK);
        let meta = case.yaml("meta.yaml")?;
        match handler {
            "get_custody_groups" => {
                let node_id = meta
                    .get("node_id")
                    .and_then(Yaml::as_str)
                    .and_then(U256::from_decimal)
                    .ok_or_else(|| Failure::new("meta.yaml has no node_id"))?;
                let count = meta
                    .get("custody_group_count")
                    .and_then(Yaml::as_u64)
                    .ok_or_else(|| Failure::new("meta.yaml has no custody_group_count"))?;
                let groups = NodeId(node_id)
                    .custody_groups(count, &config)
                    .map_err(|error| Failure(error.to_string()))?;
                let groups: Vec<u64> = groups.into_iter().map(|group| group.0).collect();
                if groups != Self::result(&meta)? {
                    return Err(Failure::new("custody groups differ"));
                }
                Ok(())
            }
            "compute_columns_for_custody_group" => {
                let group = meta
                    .get("custody_group")
                    .and_then(Yaml::as_u64)
                    .ok_or_else(|| Failure::new("meta.yaml has no custody_group"))?;
                let columns = CustodyGroup(group)
                    .columns::<P>(&config)
                    .map_err(|error| Failure(error.to_string()))?;
                let columns: Vec<u64> = columns.into_iter().map(|column| column.0).collect();
                if columns != Self::result(&meta)? {
                    return Err(Failure::new("custody columns differ"));
                }
                Ok(())
            }
            gossip if gossip.starts_with("gossip_") => GossipCase::<P, F>::new(case)?.run(),
            other => Err(Failure(format!("unsupported handler {other}"))),
        }
    }
}
