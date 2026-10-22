//! Light client vectors: sync, update ranking, and proofs.

use std::marker::PhantomData;

use axiom_light_client::{LightClientStore, UpdateQuality};
use axiom_ssz::{Root, Ssz};
use axiom_types::{LightClientBootstrap, LightClientHeader, LightClientUpdate, Preset, Slot};
use axiom_yaml::Yaml;

use super::{MerkleProofs, config_of};
use crate::{Case, Failure, Runner};

/// Fork version of a light client store whose types Axiom implements.
///
/// Fulu reuses the Electra light client containers, so its vectors run Electra stores.
const ELECTRA_STORE_SUFFIX: u8 = 0x05;

/// Drives a light client store through the vectors' steps, and ranks updates.
#[derive(Debug, Default)]
pub struct LightClient<P>(PhantomData<P>);

impl<P: Preset> LightClient<P> {
    /// Runs a sync case: bootstrap, then updates and forced updates with checks.
    fn sync(case: &Case) -> Result<(), Failure> {
        let config = config_of::<P>();
        let meta = case.yaml("meta.yaml")?;
        let hex = |key: &str| {
            meta.get(key)
                .and_then(Yaml::as_hex_array::<32>)
                .map(Root)
                .ok_or_else(|| Failure(format!("meta.yaml has no {key}")))
        };
        let genesis_validators_root = hex("genesis_validators_root")?;
        let bootstrap = case.ssz::<LightClientBootstrap<P>>("bootstrap")?;
        let mut store =
            LightClientStore::initialize(&config, hex("trusted_block_root")?, &bootstrap)
                .map_err(|error| Failure(format!("bootstrap rejected: {error}")))?;

        let steps = case.yaml("steps.yaml")?;
        for (number, step) in steps.as_sequence().unwrap_or_default().iter().enumerate() {
            let (body, outcome) = if let Some(body) = step.get("force_update") {
                let slot = Slot(Self::number(body, "current_slot")?);
                (
                    body,
                    store.force_update(slot).map_err(|error| error.to_string()),
                )
            } else if let Some(body) = step.get("process_update") {
                let name = body
                    .get("update")
                    .and_then(Yaml::as_str)
                    .ok_or_else(|| Failure::new("update without a name"))?;
                let update = case.ssz::<LightClientUpdate<P>>(name)?;
                let slot = Slot(Self::number(body, "current_slot")?);
                let outcome = store
                    .process_update(&config, &update, slot, genesis_validators_root)
                    .map_err(|error| error.to_string());
                (body, outcome)
            } else {
                return Err(Failure(format!("step {number}: unsupported step")));
            };
            outcome.map_err(|error| Failure(format!("step {number}: {error}")))?;
            if let Some(checks) = body.get("checks") {
                Self::check_header(checks, "finalized_header", &store.finalized_header)
                    .and_then(|()| {
                        Self::check_header(checks, "optimistic_header", &store.optimistic_header)
                    })
                    .map_err(|failure| Failure(format!("step {number}: {failure}")))?;
            }
        }
        Ok(())
    }

    /// Checks that updates rank in the order the files list them, best first.
    fn update_ranking(case: &Case) -> Result<(), Failure> {
        let count = Self::number(&case.yaml("meta.yaml")?, "updates_count")?;
        let updates = (0..count)
            .map(|index| case.ssz::<LightClientUpdate<P>>(&format!("updates_{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        for pair in updates.windows(2) {
            if UpdateQuality::of(&pair[1]) > UpdateQuality::of(&pair[0]) {
                return Err(Failure::new("a later update ranks above an earlier one"));
            }
        }
        Ok(())
    }

    /// Compares a header with its check.
    fn check_header(
        checks: &Yaml,
        key: &str,
        header: &LightClientHeader<P>,
    ) -> Result<(), Failure> {
        let Some(expected) = checks.get(key) else {
            return Ok(());
        };
        let slot = Self::number(expected, "slot")?;
        let root = expected
            .get("beacon_root")
            .and_then(Yaml::as_hex_array::<32>)
            .map(Root)
            .ok_or_else(|| Failure(format!("{key} has no beacon_root")))?;
        if header.beacon.slot.0 != slot || header.beacon.hash_tree_root() != root {
            return Err(Failure(format!(
                "{key}: expected slot {slot} root {root}, got slot {} root {}",
                header.beacon.slot,
                header.beacon.hash_tree_root()
            )));
        }
        Ok(())
    }

    /// A number field of a mapping.
    fn number(value: &Yaml, key: &str) -> Result<u64, Failure> {
        value
            .get(key)
            .and_then(Yaml::as_u64)
            .ok_or_else(|| Failure(format!("missing number {key}")))
    }
}

impl<P: Preset> Runner for LightClient<P> {
    fn name(&self) -> &'static str {
        "light_client"
    }

    fn run_case(&self, handler: &str, case: &Case) -> Result<(), Failure> {
        match handler {
            "sync" => Self::sync(case),
            "update_ranking" => Self::update_ranking(case),
            "single_merkle_proof" => MerkleProofs::<P>::light_client().run_case(handler, case),
            other => Err(Failure(format!("unsupported handler {other}"))),
        }
    }

    fn skip_handler(&self, handler: &str) -> Option<&'static str> {
        (handler == "data_collection")
            .then_some("light client data collection by a full node is not implemented")
    }

    fn skip_case(&self, handler: &str, case: &Case) -> Option<&'static str> {
        // Stores of a later fork than Electra hold Gloas containers, which Axiom does not implement.
        let gloas_store = handler == "sync"
            && case
                .yaml("meta.yaml")
                .ok()
                .and_then(|meta| {
                    meta.get("store_fork_version")
                        .and_then(Yaml::as_hex_array::<4>)
                })
                .is_some_and(|version| version[0] > ELECTRA_STORE_SUFFIX);
        // A store upgrade crosses into Gloas, the only later fork.
        let upgrades_store = handler == "sync"
            && case
                .yaml("steps.yaml")
                .ok()
                .and_then(|steps| steps.as_sequence().map(<[Yaml]>::to_vec))
                .is_some_and(|steps| steps.iter().any(|step| step.get("upgrade_store").is_some()));
        (gloas_store || upgrades_store).then_some("Gloas light client stores are not implemented")
    }
}
