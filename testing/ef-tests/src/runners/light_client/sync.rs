//! Light client sync vectors: a store bootstrapped, then driven by updates and upgrades.

use std::marker::PhantomData;

use axiom_light_client::{
    Header,
    combined::{LightClientBootstrap, LightClientHeader, LightClientStore, LightClientUpdate},
};
use axiom_types::{ForkName, Preset, Slot};
use axiom_yaml::Yaml;

use super::{ForkContext, number, root};
use crate::{Case, Failure};

/// One sync case: its chain, its metadata, and its files.
#[derive(Debug)]
pub(super) struct SyncCase<'c, P> {
    /// The case directory.
    case: &'c Case,
    /// The chain the case runs on.
    context: ForkContext,
    /// The case metadata.
    meta: Yaml,
    /// The preset.
    preset: PhantomData<P>,
}

impl<'c, P: Preset> SyncCase<'c, P> {
    /// A case ready to run, on the configuration of its directory's fork.
    pub(super) fn new(case: &'c Case, fork: ForkName) -> Result<Self, Failure> {
        let meta = case.yaml("meta.yaml")?;
        let genesis_validators_root = root(&meta, "genesis_validators_root")?;
        Ok(Self {
            case,
            context: ForkContext {
                config: case.config::<P>(fork)?,
                genesis_validators_root,
            },
            meta,
            preset: PhantomData,
        })
    }

    /// Bootstraps the store, then runs each step and its checks.
    pub(super) fn run(&self) -> Result<(), Failure> {
        let config = &self.context.config;
        let bootstrap_fork = self
            .context
            .fork_of_digest(&self.meta, "bootstrap_fork_digest")?;
        let bootstrap =
            LightClientBootstrap::<P>::decode(&self.case.ssz_bytes("bootstrap")?, bootstrap_fork)
                .map_err(|error| Failure(error.to_string()))?;
        let format = self
            .context
            .format_of_version(&self.meta, "store_fork_version")?;
        let trusted = root(&self.meta, "trusted_block_root")?;
        let mut store = LightClientStore::initialize(format, config, trusted, bootstrap)
            .map_err(|error| Failure(format!("bootstrap rejected: {error}")))?;

        let steps = self.case.yaml("steps.yaml")?;
        for (index, step) in steps.as_sequence().unwrap_or_default().iter().enumerate() {
            let fail = |message: String| Failure(format!("step {index}: {message}"));
            let body = if let Some(body) = step.get("force_update") {
                let slot = Slot(number(body, "current_slot")?);
                store
                    .force_update(slot)
                    .map_err(|error| fail(error.to_string()))?;
                body
            } else if let Some(body) = step.get("process_update") {
                self.process_update(&mut store, body)
                    .map_err(|failure| fail(failure.0))?;
                body
            } else if let Some(body) = step.get("upgrade_store") {
                let target = self.context.format_of_version(body, "store_fork_version")?;
                store = store
                    .upgrade_to(target, config)
                    .map_err(|error| fail(error.to_string()))?;
                body
            } else {
                return Err(fail("unsupported step".to_owned()));
            };
            if let Some(checks) = body.get("checks") {
                self.check_header(checks, "finalized_header", &store.finalized_header())
                    .and_then(|()| {
                        self.check_header(checks, "optimistic_header", &store.optimistic_header())
                    })
                    .map_err(|failure| fail(failure.0))?;
            }
        }
        Ok(())
    }

    /// Decodes a step's update in its own format and processes it.
    fn process_update(&self, store: &mut LightClientStore<P>, body: &Yaml) -> Result<(), Failure> {
        let name = body
            .get("update")
            .and_then(Yaml::as_str)
            .ok_or_else(|| Failure::new("update without a name"))?;
        let fork = self.context.fork_of_digest(body, "update_fork_digest")?;
        let update = LightClientUpdate::<P>::decode(&self.case.ssz_bytes(name)?, fork)
            .map_err(|error| Failure(error.to_string()))?;
        let slot = Slot(number(body, "current_slot")?);
        store
            .process_update(
                &self.context.config,
                update,
                slot,
                self.context.genesis_validators_root,
            )
            .map_err(|error| Failure(error.to_string()))
    }

    /// Compares a store header with its check: slot, beacon root, and execution root.
    fn check_header(
        &self,
        checks: &Yaml,
        key: &str,
        header: &LightClientHeader<P>,
    ) -> Result<(), Failure> {
        let Some(expected) = checks.get(key) else {
            return Ok(());
        };
        let slot = Slot(number(expected, "slot")?);
        let beacon_root = root(expected, "beacon_root")?;
        let actual_slot = Header::<P>::beacon(header).slot;
        if actual_slot != slot || header.beacon_root() != beacon_root {
            return Err(Failure(format!(
                "{key}: expected slot {slot} root {beacon_root}, got slot {actual_slot} root {}",
                header.beacon_root()
            )));
        }
        // Execution roots appear from Capella onward.
        if expected.get("execution_root").is_some() {
            let expected_root = root(expected, "execution_root")?;
            let actual_root = header.execution_root_at(&self.context.config);
            if actual_root != expected_root {
                return Err(Failure(format!(
                    "{key}: execution root {actual_root} is not {expected_root}"
                )));
            }
        }
        Ok(())
    }
}
