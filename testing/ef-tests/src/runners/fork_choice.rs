//! Fork choice vectors: a store driven through ticks, blocks, and votes, with checks between.

use std::{fmt::Debug, marker::PhantomData};

use axiom_das::ColumnSidecar;
use axiom_fork_choice::{DataAvailability, FastConfirmation, Store};
use axiom_state_transition::{KnownVerdict, Verification};
use axiom_types::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconState, Checkpoint, DataColumnSidecar, Epoch,
    Preset, Root, SignedBeaconBlock, Slot,
};
use axiom_yaml::Yaml;

use super::config_of;
use crate::{Case, Failure, Runner};

/// Check keys that belong to the fast confirmation rule rather than the store.
const FAST_CONFIRMATION_KEYS: [&str; 7] = [
    "previous_epoch_observed_justified_checkpoint",
    "current_epoch_observed_justified_checkpoint",
    "previous_epoch_greatest_unrealized_checkpoint",
    "previous_slot_head",
    "current_slot_head",
    "confirmed_root",
    "safe_execution_block_hash",
];

/// Replays the case's steps on a store, and checks it wherever the case asks.
///
/// The fork choice and fast confirmation runners share this format.
#[derive(Debug)]
pub struct StoreReplay<P> {
    /// The runner directory these vectors live under.
    runner: &'static str,
    /// The preset.
    preset: PhantomData<P>,
}

impl<P: Preset> StoreReplay<P> {
    /// The fork choice runner.
    #[must_use]
    pub const fn fork_choice() -> Self {
        Self {
            runner: "fork_choice",
            preset: PhantomData,
        }
    }

    /// The fast confirmation runner.
    #[must_use]
    pub const fn fast_confirmation() -> Self {
        Self {
            runner: "fast_confirmation",
            preset: PhantomData,
        }
    }

    /// Runs the fast confirmation rule when a check asks for its outputs, then compares them.
    ///
    /// The vector generator runs the rule once per slot and records its outputs right after.
    fn fast_confirmation_checks(
        store: &mut Store<P>,
        confirmation: &mut FastConfirmation,
        checks: &Yaml,
    ) -> Result<(), Failure> {
        if !FAST_CONFIRMATION_KEYS
            .iter()
            .any(|key| checks.get(key).is_some())
        {
            return Ok(());
        }
        confirmation
            .on_fast_confirmation(store)
            .map_err(|error| Failure(format!("fast confirmation failed: {error}")))?;
        let checkpoints = [
            (
                "previous_epoch_observed_justified_checkpoint",
                confirmation.previous_epoch_observed_justified_checkpoint,
            ),
            (
                "current_epoch_observed_justified_checkpoint",
                confirmation.current_epoch_observed_justified_checkpoint,
            ),
            (
                "previous_epoch_greatest_unrealized_checkpoint",
                confirmation.previous_epoch_greatest_unrealized_checkpoint,
            ),
        ];
        for (key, actual) in checkpoints {
            if let Some(expected) = checks.get(key) {
                Self::expect_eq(key, &Self::checkpoint(expected)?, &actual)?;
            }
        }
        let roots = [
            ("previous_slot_head", confirmation.previous_slot_head),
            ("current_slot_head", confirmation.current_slot_head),
            ("confirmed_root", confirmation.confirmed_root),
            (
                "safe_execution_block_hash",
                Root(confirmation.safe_execution_block_hash(store).0),
            ),
        ];
        for (key, actual) in roots {
            if let Some(expected) = checks.get(key) {
                let expected = expected
                    .as_hex_array::<32>()
                    .map(Root)
                    .ok_or_else(|| Failure(format!("{key} is not hex")))?;
                Self::expect_eq(key, &expected, &actual)?;
            }
        }
        Ok(())
    }

    /// Applies one block step, deciding data availability from the step's columns.
    fn block_step(
        store: &mut Store<P>,
        case: &Case,
        step: &Yaml,
        verification: Verification,
    ) -> Result<Result<(), String>, Failure> {
        let name = step
            .get("block")
            .and_then(Yaml::as_str)
            .ok_or_else(|| Failure::new("block step without a name"))?;
        let block = case.ssz::<SignedBeaconBlock<P>>(name)?;
        let config = config_of::<P>();

        // No columns listed means nothing to sample; an empty list means sampling failed.
        let availability = match step.get("columns").and_then(Yaml::as_sequence) {
            None => DataAvailability::Available,
            Some([]) => DataAvailability::Unavailable,
            Some(names) => {
                let mut available = true;
                for name in names {
                    let name = name
                        .as_str()
                        .ok_or_else(|| Failure::new("column name is not a string"))?;
                    let sidecar = case.ssz::<DataColumnSidecar<P>>(name)?;
                    available &= ColumnSidecar(&sidecar).verify_structure(&config).is_ok();
                }
                if available {
                    DataAvailability::Available
                } else {
                    DataAvailability::Unavailable
                }
            }
        };

        let outcome = store
            .on_block(&block, availability, verification, &KnownVerdict(true))
            .map_err(|error| error.to_string());
        if outcome.is_ok() {
            // Votes and slashings inside the block feed the fork choice too.
            for attestation in &block.message.body.attestations {
                let _ = store.on_attestation(attestation, true, verification);
            }
            for slashing in &block.message.body.attester_slashings {
                let _ = store.on_attester_slashing(slashing, verification);
            }
        }
        Ok(outcome)
    }

    /// Compares the store with every check of a checks step.
    fn checks(store: &mut Store<P>, checks: &Yaml) -> Result<(), Failure> {
        let Some(mapping) = checks.as_mapping() else {
            return Err(Failure::new("checks step is not a mapping"));
        };
        for (key, expected) in mapping {
            match key {
                "head" => {
                    let head = store
                        .head()
                        .map_err(|error| Failure(format!("head failed: {error}")))?;
                    let slot = store
                        .blocks()
                        .get(&head)
                        .map_or(Slot::GENESIS, |node| node.slot);
                    Self::expect_eq("head root", &Self::root(expected, "root")?, &head)?;
                    Self::expect_eq("head slot", &Self::number(expected, "slot")?, &slot.0)?;
                }
                "time" => {
                    Self::expect_eq("time", &Self::scalar(expected)?, &(store.time_ms() / 1000))?;
                }
                "genesis_time" => {
                    Self::expect_eq(
                        "genesis time",
                        &Self::scalar(expected)?,
                        &(store.genesis_time_ms() / 1000),
                    )?;
                }
                "justified_checkpoint" => {
                    Self::expect_eq(
                        "justified checkpoint",
                        &Self::checkpoint(expected)?,
                        &store.justified_checkpoint(),
                    )?;
                }
                "finalized_checkpoint" => {
                    Self::expect_eq(
                        "finalized checkpoint",
                        &Self::checkpoint(expected)?,
                        &store.finalized_checkpoint(),
                    )?;
                }
                "proposer_boost_root" => {
                    let root = expected
                        .as_hex_array::<32>()
                        .ok_or_else(|| Failure::new("proposer boost root is not hex"))?;
                    Self::expect_eq(
                        "proposer boost root",
                        &Root(root),
                        &store.proposer_boost_root(),
                    )?;
                }
                "get_proposer_head" => {
                    let expected = expected
                        .as_hex_array::<32>()
                        .ok_or_else(|| Failure::new("proposer head is not hex"))?;
                    let head = store
                        .head()
                        .map_err(|error| Failure(format!("head failed: {error}")))?;
                    let slot = store.current_slot();
                    let proposer_head = store
                        .proposer_head(head, slot)
                        .map_err(|error| Failure(format!("proposer head failed: {error}")))?;
                    Self::expect_eq("proposer head", &Root(expected), &proposer_head)?;
                }
                key if FAST_CONFIRMATION_KEYS.contains(&key) => {}
                other => return Err(Failure(format!("unsupported check {other}"))),
            }
        }
        Ok(())
    }

    /// Fails unless two values are equal.
    fn expect_eq<T: PartialEq + Debug>(
        what: &str,
        expected: &T,
        actual: &T,
    ) -> Result<(), Failure> {
        if expected == actual {
            Ok(())
        } else {
            Err(Failure(format!(
                "{what}: expected {expected:?}, got {actual:?}"
            )))
        }
    }

    /// A number scalar.
    fn scalar(value: &Yaml) -> Result<u64, Failure> {
        value
            .as_u64()
            .ok_or_else(|| Failure::new("expected a number"))
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

    /// A checkpoint mapping.
    fn checkpoint(value: &Yaml) -> Result<Checkpoint, Failure> {
        Ok(Checkpoint {
            epoch: Epoch(Self::number(value, "epoch")?),
            root: Self::root(value, "root")?,
        })
    }
}

impl<P: Preset> Runner for StoreReplay<P> {
    fn name(&self) -> &'static str {
        self.runner
    }

    fn run_case(&self, _handler: &str, case: &Case) -> Result<(), Failure> {
        let meta = case.meta()?;
        let verification = if meta.bls_ignored() {
            Verification::Skip
        } else {
            Verification::Verify
        };
        let anchor_state = case.ssz::<BeaconState<P>>("anchor_state")?;
        let anchor_block = case.ssz::<BeaconBlock<P>>("anchor_block")?;
        let mut store = Store::new(config_of::<P>(), anchor_state, &anchor_block)
            .map_err(|error| Failure(format!("anchor rejected: {error}")))?;
        let mut confirmation = FastConfirmation::new(&store);

        let steps = case.yaml("steps.yaml")?;
        let steps = steps
            .as_sequence()
            .ok_or_else(|| Failure::new("steps.yaml is not a sequence"))?;
        for (number, step) in steps.iter().enumerate() {
            let expected_valid = step.get("valid").and_then(Yaml::as_bool).unwrap_or(true);
            let accepted = if let Some(tick) = step.get("tick") {
                store.on_tick(Self::scalar(tick)?.saturating_mul(1000));
                true
            } else if step.get("block").is_some() {
                let outcome = Self::block_step(&mut store, case, step, verification)?;
                if let Err(error) = &outcome
                    && expected_valid
                {
                    return Err(Failure(format!("step {number}: block rejected: {error}")));
                }
                outcome.is_ok()
            } else if let Some(name) = step.get("attestation").and_then(Yaml::as_str) {
                let attestation = case.ssz::<Attestation<P>>(name)?;
                store
                    .on_attestation(&attestation, false, verification)
                    .is_ok()
            } else if let Some(name) = step.get("attester_slashing").and_then(Yaml::as_str) {
                let slashing = case.ssz::<AttesterSlashing<P>>(name)?;
                store.on_attester_slashing(&slashing, verification).is_ok()
            } else if let Some(checks) = step.get("checks") {
                Self::fast_confirmation_checks(&mut store, &mut confirmation, checks)
                    .and_then(|()| Self::checks(&mut store, checks))
                    .map_err(|failure| Failure(format!("step {number}: {failure}")))?;
                true
            } else {
                return Err(Failure(format!("step {number}: unsupported step")));
            };
            if accepted != expected_valid {
                return Err(Failure(format!(
                    "step {number}: expected {}, got {}",
                    if expected_valid {
                        "acceptance"
                    } else {
                        "rejection"
                    },
                    if accepted { "acceptance" } else { "rejection" }
                )));
            }
        }
        Ok(())
    }
}
