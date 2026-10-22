//! Light client data collection vectors: a full node's data, checked at every new head.
//!
//! The vectors replay blocks on competing branches and pick heads by an external signal.
//! After each head, the node's bootstraps, best updates, and latest updates must match.
//! See the light client data collection test format and its generator's helpers.

mod collector;
mod history;

use std::{collections::HashMap, fmt::Debug};

use axiom_light_client::combined::{
    LightClientBootstrap, LightClientFinalityUpdate, LightClientOptimisticUpdate, LightClientUpdate,
};
use axiom_state_transition::{KnownVerdict, State, Verification};
use axiom_types::{
    Epoch, ForkName, Preset,
    combined::{BeaconState, SignedBeaconBlock},
};
use axiom_yaml::Yaml;
use collector::Collector;
use history::{BlockId, BlockRecord, History};

use super::{ForkContext, number, root};
use crate::{Case, Failure};

/// One data collection case: its chain, and the light client data collected on it.
#[derive(Debug)]
pub(super) struct DataCollection<'c, P: Preset> {
    /// The case directory.
    case: &'c Case,
    /// The chain the case runs on.
    context: ForkContext,
    /// Blocks, states, and finality seen so far.
    history: History<P>,
    /// The light client data collected so far.
    collector: Collector<P>,
}

impl<'c, P: Preset> DataCollection<'c, P> {
    /// A case started from its initial state, on the configuration of its directory's fork.
    ///
    /// See `setup_lc_data_collection_test` in the spec's data collection helpers.
    pub(super) fn new(case: &'c Case, fork: ForkName) -> Result<Self, Failure> {
        let config = case.config::<P>(fork)?;
        let beacon = BeaconState::<P>::decode_at(&case.ssz_bytes("initial_state")?, &config)
            .map_err(|error| Failure(format!("initial_state: {error}")))?;
        let state = State::new(beacon);
        let core = state.beacon().as_core();
        let genesis_validators_root = core.genesis_validators_root();
        let finalized = core.finalized_checkpoint();
        let slot = core.slot();
        let altair_slot = config.fork_epoch(ForkName::Altair).start_slot::<P>();
        let state_root = state.hash_tree_root();

        let genesis = BlockRecord::genesis(&state);
        let id = BlockId::of_state(&state);
        let mut history = History {
            blocks: HashMap::new(),
            post_states: HashMap::new(),
            cells: Vec::new(),
            states: HashMap::new(),
            finalized_block_roots: HashMap::from([(id.slot, id.root)]),
            finalized_checkpoint_states: Vec::new(),
            latest_finalized_epoch: finalized.epoch,
            latest_finalized: BlockId {
                slot: finalized.epoch.start_slot::<P>(),
                root: finalized.root,
            },
            tail_slot: slot,
        };
        // The generator files the genesis block under the root its state's header implies.
        history
            .blocks
            .insert(id.root, BlockRecord { id, ..genesis });
        history.post_states.insert(id.root, state.clone());
        // The generator wraps the start state twice, so the two maps do not share it.
        let cell = history.new_cell(state.clone());
        history.states.insert(state_root, cell);
        let cell = history.new_cell(state.clone());
        history.keep_checkpoint_state(state_root, cell);

        let mut collector = Collector::new(config.clone(), slot.max(altair_slot));
        collector.start(&mut history, &state, id)?;
        Ok(Self {
            case,
            context: ForkContext {
                config,
                genesis_validators_root,
            },
            history,
            collector,
        })
    }

    /// Runs each step, checking the collected data at each new head.
    pub(super) fn run(mut self) -> Result<(), Failure> {
        let steps = self.case.yaml("steps.yaml")?;
        for (index, step) in steps.as_sequence().unwrap_or_default().iter().enumerate() {
            let outcome = if let Some(body) = step.get("new_block") {
                self.new_block(body)
            } else if let Some(body) = step.get("new_head") {
                self.new_head(body)
            } else {
                Err(Failure::new("unsupported step"))
            };
            outcome.map_err(|failure| Failure(format!("step {index}: {}", failure.0)))?;
        }
        Ok(())
    }

    /// Imports a block on top of its parent's post-state.
    ///
    /// See `add_new_block` in the helpers.
    fn new_block(&mut self, body: &Yaml) -> Result<(), Failure> {
        let fork = self.context.fork_of_digest(body, "fork_digest")?;
        let name = body
            .get("data")
            .and_then(Yaml::as_str)
            .ok_or_else(|| Failure::new("new block without data"))?;
        let block = SignedBeaconBlock::<P>::decode(&self.case.ssz_bytes(name)?, fork)
            .map_err(|error| Failure(format!("{name}: {error}")))?;
        let mut state = self
            .history
            .post_states
            .get(&block.parent_root())
            .cloned()
            .ok_or_else(|| Failure(format!("parent of {name} is unknown")))?;
        let parent = BlockId::of_state(&state);
        // The generator signed every block; the data, not the signatures, is under test.
        state
            .state_transition(
                &self.context.config,
                &block,
                Verification::Skip,
                &KnownVerdict(true),
            )
            .map_err(|error| Failure(format!("{name} failed to import: {error}")))?;
        let record = BlockRecord::of(&block);
        let id = record.id;
        self.history.blocks.insert(id.root, record);
        self.history.post_states.insert(id.root, state.clone());
        let cell = self.history.new_cell(state.clone());
        self.history.states.insert(state.hash_tree_root(), cell);
        self.collector.on_block(&self.history, &state, id, parent)
    }

    /// Makes a block the head, follows its finality, and checks the collected data.
    ///
    /// See `select_new_head` in the helpers.
    fn new_head(&mut self, body: &Yaml) -> Result<(), Failure> {
        let head_root = root(body, "head_block_root")?;
        let head = self.history.block(&head_root)?.id;
        let old_finalized = self.history.latest_finalized;
        self.collector.on_head(&self.history, head, old_finalized)?;
        self.follow_finality(head)?;
        let checks = body
            .get("checks")
            .ok_or_else(|| Failure::new("new head without checks"))?;
        self.check(checks, head)
    }

    /// Records the head state's finalized checkpoint and everything it finalizes.
    fn follow_finality(&mut self, head: BlockId) -> Result<(), Failure> {
        let state_root = self.history.block(&head.root)?.state_root;
        let cell = self.history.state_cell(&state_root)?;
        let finalized = self.history.cells[cell]
            .beacon()
            .as_core()
            .finalized_checkpoint();
        if finalized.epoch == Epoch::GENESIS {
            return Ok(());
        }
        let old_finalized = self.history.latest_finalized;
        let new_finalized = self.history.block(&finalized.root)?.id;
        if new_finalized.slot <= old_finalized.slot {
            return Ok(());
        }

        // Walk back to the previous finalized block, keeping each epoch's boundary state.
        let mut id = new_finalized;
        let mut previous_epoch = None;
        while id.slot > self.history.latest_finalized.slot {
            self.history.finalized_block_roots.insert(id.slot, id.root);
            let epoch = (id.slot + (P::SLOTS_PER_EPOCH - 1)).epoch::<P>();
            let record = self.history.block(&id.root)?.clone();
            if previous_epoch != Some(epoch) {
                let cell = self.history.state_cell(&record.state_root)?;
                self.history.keep_checkpoint_state(record.state_root, cell);
                previous_epoch = Some(epoch);
            }
            id = self.history.block(&record.parent_root)?.id;
        }
        self.history.latest_finalized_epoch = finalized.epoch;
        self.history.latest_finalized = new_finalized;
        self.collector
            .on_finalization(&mut self.history, new_finalized, old_finalized)?;
        self.history
            .blocks
            .retain(|_, block| block.id.slot >= new_finalized.slot);
        Ok(())
    }

    /// Compares the collected data with a new head's checks.
    fn check(&self, checks: &Yaml, head: BlockId) -> Result<(), Failure> {
        let finalized = checks
            .get("latest_finalized_checkpoint")
            .ok_or_else(|| Failure::new("checks without latest_finalized_checkpoint"))?;
        let epoch = Epoch(number(finalized, "epoch")?);
        let finalized_root = root(finalized, "root")?;
        if (epoch, finalized_root)
            != (
                self.history.latest_finalized_epoch,
                self.history.latest_finalized.root,
            )
        {
            return Err(Failure(format!(
                "finalized checkpoint {epoch} {finalized_root} is not {} {}",
                self.history.latest_finalized_epoch, self.history.latest_finalized.root
            )));
        }

        // One bootstrap entry per finalized checkpoint state, in the order they were kept.
        let bootstraps = sequence(checks, "bootstraps")?;
        let states = &self.history.finalized_checkpoint_states;
        if bootstraps.len() != states.len() {
            return Err(Failure(format!(
                "{} bootstrap entries expected, {} collected",
                bootstraps.len(),
                states.len()
            )));
        }
        for (entry, (_, cell)) in bootstraps.iter().zip(states) {
            let id = BlockId::of_state(&self.history.cells[*cell]);
            let expected_root = root(entry, "block_root")?;
            if expected_root != id.root {
                return Err(Failure(format!(
                    "bootstrap entry for {expected_root}, collected {}",
                    id.root
                )));
            }
            let collected = self.collector.bootstrap(&id.root)?;
            self.compare(
                entry.get("bootstrap"),
                collected.as_ref(),
                LightClientBootstrap::decode,
            )
            .map_err(|failure| Failure(format!("bootstrap of {}: {}", id.root, failure.0)))?;
        }

        // One best update entry per period from the tail to the head.
        let low_period = self.collector.tail_slot.sync_committee_period::<P>();
        let head_period = head.slot.sync_committee_period::<P>();
        let best_updates = sequence(checks, "best_updates")?;
        let periods = head_period + 1 - low_period;
        if best_updates.len() as u64 != periods {
            return Err(Failure(format!(
                "{} best update entries expected, {periods} periods collected",
                best_updates.len()
            )));
        }
        for (entry, period) in best_updates.iter().zip(low_period..) {
            let collected = self
                .collector
                .best_updates
                .get(&period)
                .cloned()
                .map(LightClientUpdate::from_data)
                .transpose()
                .map_err(|error| Failure(error.to_string()))?;
            self.compare(
                entry.get("update"),
                collected.as_ref(),
                LightClientUpdate::decode,
            )
            .map_err(|failure| Failure(format!("best update of period {period}: {}", failure.0)))?;
        }

        // The latest finality update, and the optimistic update it implies.
        let latest = self.collector.latest.clone();
        let finality = latest
            .clone()
            .map(LightClientFinalityUpdate::from_data)
            .transpose()
            .map_err(|error| Failure(error.to_string()))?;
        self.compare(
            checks.get("latest_finality_update"),
            finality.as_ref(),
            LightClientFinalityUpdate::decode,
        )
        .map_err(|failure| Failure(format!("latest finality update: {}", failure.0)))?;
        let optimistic = latest
            .map(LightClientOptimisticUpdate::from_data)
            .transpose()
            .map_err(|error| Failure(error.to_string()))?;
        self.compare(
            checks.get("latest_optimistic_update"),
            optimistic.as_ref(),
            LightClientOptimisticUpdate::decode,
        )
        .map_err(|failure| Failure(format!("latest optimistic update: {}", failure.0)))
    }

    /// Compares collected light client data with the file a check names, if any.
    fn compare<T: PartialEq + Debug, E: ToString>(
        &self,
        expected: Option<&Yaml>,
        collected: Option<&T>,
        decode: impl Fn(&[u8], ForkName) -> Result<T, E>,
    ) -> Result<(), Failure> {
        match (expected, collected) {
            (None, None) => Ok(()),
            (Some(_), None) => Err(Failure::new("expected data, collected none")),
            (None, Some(_)) => Err(Failure::new("expected no data, collected some")),
            (Some(expected), Some(collected)) => {
                let fork = self.context.fork_of_digest(expected, "fork_digest")?;
                let name = expected
                    .get("data")
                    .and_then(Yaml::as_str)
                    .ok_or_else(|| Failure::new("data without a file name"))?;
                let expected = decode(&self.case.ssz_bytes(name)?, fork)
                    .map_err(|error| Failure(format!("{name}: {}", error.to_string())))?;
                if expected == *collected {
                    Ok(())
                } else {
                    Err(Failure(format!(
                        "{name} differs from the collected data: {collected:?}"
                    )))
                }
            }
        }
    }
}

/// A sequence field of a mapping.
fn sequence<'y>(value: &'y Yaml, key: &str) -> Result<&'y [Yaml], Failure> {
    value
        .get(key)
        .and_then(Yaml::as_sequence)
        .ok_or_else(|| Failure(format!("missing sequence {key}")))
}
