//! What every duty reaches: the validators, the beacon nodes, the schedule, and the clock.

use std::{
    marker::PhantomData,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use axiom_types::{ChainConfig, Epoch, ForkName, Preset, Slot};

use crate::{
    beacon::BeaconNodes,
    duties::{DutyBook, SlotTimer},
    validators::ValidatorStore,
};

/// How the client behaves, beyond what each validator configures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientSettings {
    /// The boost factor sent with block requests; zero asks for a local payload.
    ///
    /// See `produceBlockV3` in the beacon API.
    pub builder_boost_factor: Option<u64>,
    /// Epochs a new key waits, watching for another instance of itself, before it signs.
    ///
    /// Zero turns doppelganger detection off.
    pub doppelganger_epochs: u64,
    /// Slots a beacon node may lag before it counts as syncing.
    pub sync_tolerance: u64,
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            builder_boost_factor: None,
            doppelganger_epochs: 2,
            sync_tolerance: 8,
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
    /// The fork schedule and timing.
    pub(crate) config: Arc<ChainConfig>,
    /// The wall clock, through the slot schedule.
    pub(crate) timer: SlotTimer,
    /// The duties known so far.
    pub(crate) book: Arc<Mutex<DutyBook>>,
    /// The client's behaviour.
    pub(crate) settings: ClientSettings,
    /// The preset the chain uses.
    pub(crate) preset: PhantomData<P>,
}

impl<P: Preset> Clone for DutyContext<P> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            nodes: Arc::clone(&self.nodes),
            config: Arc::clone(&self.config),
            timer: self.timer.clone(),
            book: Arc::clone(&self.book),
            settings: self.settings,
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
            config,
            timer,
            book: Arc::new(Mutex::new(DutyBook::default())),
            settings,
            preset: PhantomData,
        }
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
