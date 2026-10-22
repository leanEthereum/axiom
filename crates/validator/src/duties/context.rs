//! What every duty reaches: the validators, the beacon nodes, the schedule, and the clock.

use std::{
    marker::PhantomData,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use axiom_types::{ChainConfig, Epoch, ForkName, Preset, Slot};

use crate::{
    beacon::BeaconNodes,
    duties::{DutyBook, SlotTimer},
    metrics::ValidatorMetrics,
    validators::ValidatorStore,
};

/// How the client behaves, beyond what each validator configures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientSettings {
    /// Epochs a new key waits, watching for another instance of itself, before it signs.
    ///
    /// Zero turns doppelganger detection off.
    pub doppelganger_epochs: u64,
    /// Slots a beacon node may lag before it counts as syncing.
    pub sync_tolerance: u64,
    /// Whether attestation and sync committee duties are skipped, leaving proposals only.
    pub disable_attesting: bool,
    /// Whether keys are shares of a distributed validator, whose selection proofs a middleware combines.
    ///
    /// See `submitBeaconCommitteeSelections` and `submitSyncCommitteeSelections` in the beacon API.
    pub distributed: bool,
    /// Whether the node must use the graffiti as given, without appending client versions.
    pub preserve_graffiti: bool,
    /// The timestamp every builder registration carries, instead of the time it is signed.
    pub registration_timestamp: Option<u64>,
    /// Registrations sent per request to the beacon node.
    pub registration_batch_size: usize,
}

impl ClientSettings {
    /// Registrations per request when none is configured, small enough for slow builders.
    pub const DEFAULT_REGISTRATION_BATCH_SIZE: usize = 500;
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            doppelganger_epochs: 2,
            sync_tolerance: 8,
            disable_attesting: false,
            distributed: false,
            preserve_graffiti: false,
            registration_timestamp: None,
            registration_batch_size: Self::DEFAULT_REGISTRATION_BATCH_SIZE,
        }
    }
}

/// Everything a duty reaches, cheap to clone into each duty's task.
#[derive(Debug)]
pub struct DutyContext<P: Preset> {
    /// The validators and their signing guard.
    pub(crate) store: Arc<ValidatorStore>,
    /// The beacon nodes.
    pub(crate) nodes: Arc<BeaconNodes>,
    /// Nodes that build and publish blocks first, before the others are tried.
    pub(crate) proposer_nodes: Option<Arc<BeaconNodes>>,
    /// The fork schedule and timing.
    pub(crate) config: Arc<ChainConfig>,
    /// The wall clock, through the slot schedule.
    pub(crate) timer: SlotTimer,
    /// The duties known so far.
    pub(crate) book: Arc<Mutex<DutyBook>>,
    /// The client's behaviour.
    pub(crate) settings: ClientSettings,
    /// The exported metrics.
    pub(crate) metrics: ValidatorMetrics,
    /// The preset the chain uses.
    pub(crate) preset: PhantomData<P>,
}

impl<P: Preset> Clone for DutyContext<P> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            nodes: Arc::clone(&self.nodes),
            proposer_nodes: self.proposer_nodes.clone(),
            config: Arc::clone(&self.config),
            timer: self.timer.clone(),
            book: Arc::clone(&self.book),
            settings: self.settings,
            metrics: self.metrics.clone(),
            preset: PhantomData,
        }
    }
}

impl<P: Preset> DutyContext<P> {
    /// A context over its parts, with an empty duty book.
    #[must_use]
    pub fn new(
        store: Arc<ValidatorStore>,
        nodes: Arc<BeaconNodes>,
        config: Arc<ChainConfig>,
        timer: SlotTimer,
        settings: ClientSettings,
    ) -> Self {
        Self {
            store,
            nodes,
            proposer_nodes: None,
            config,
            timer,
            book: Arc::new(Mutex::new(DutyBook::default())),
            settings,
            metrics: ValidatorMetrics::detached(),
            preset: PhantomData,
        }
    }

    /// Builds and publishes blocks through these nodes first.
    #[must_use]
    pub fn with_proposer_nodes(mut self, nodes: Arc<BeaconNodes>) -> Self {
        self.proposer_nodes = Some(nodes);
        self
    }

    /// Records duty and node gauges in exported metrics.
    #[must_use]
    pub fn with_metrics(mut self, metrics: ValidatorMetrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// The validators.
    #[must_use]
    pub const fn store(&self) -> &Arc<ValidatorStore> {
        &self.store
    }

    /// The beacon nodes.
    #[must_use]
    pub const fn nodes(&self) -> &Arc<BeaconNodes> {
        &self.nodes
    }

    /// The timer.
    #[must_use]
    pub const fn timer(&self) -> &SlotTimer {
        &self.timer
    }

    /// The fork in force at a slot.
    pub(crate) fn fork(&self, slot: Slot) -> ForkName {
        self.config.fork_at(slot.epoch::<P>())
    }

    /// The fork in force at an epoch.
    pub(crate) fn fork_at(&self, epoch: Epoch) -> ForkName {
        self.config.fork_at(epoch)
    }

    /// The duty book, under its lock.
    pub(crate) fn book(&self) -> MutexGuard<'_, DutyBook> {
        // Every change to the book is one map insertion, so a poisoned book is still consistent.
        self.book.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
