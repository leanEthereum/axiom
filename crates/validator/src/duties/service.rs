//! The validator client's main loop: one round of duties per slot.

use std::{future::Future, sync::Arc};

use axiom_types::{Preset, Slot};
use tokio::task;
use tracing::{debug, info};

use crate::duties::{
    Attester, BlockProposer, Doppelganger, DutyContext, DutyScheduler, PayloadTimeliness,
    Preparation, SyncCommittee,
};

/// The validator client's services, driven slot by slot.
///
/// # Overview
///
/// At the start of every slot, the client runs these steps:
///
/// 1. Rank the beacon nodes by health.
/// 2. Refresh duties for this epoch and the next.
/// 3. On an epoch's first slot, check for doppelgangers and send preparations.
/// 4. Start the slot's duties, each in its own task, each waiting for its deadline.
///
/// A slow duty never delays the next slot: the loop moves on as soon as the tasks start.
#[derive(Debug)]
pub struct ValidatorClient<P: Preset> {
    /// What every service reaches.
    context: DutyContext<P>,
    /// The doppelganger detector, which keeps state across epochs.
    doppelganger: Arc<Doppelganger<P>>,
    /// The preparation service, which keeps signed registrations across epochs.
    preparation: Arc<Preparation<P>>,
}

impl<P: Preset> ValidatorClient<P> {
    /// A client over a context.
    #[must_use]
    pub fn new(context: DutyContext<P>) -> Self {
        Self {
            doppelganger: Arc::new(Doppelganger::new(context.clone())),
            preparation: Arc::new(Preparation::new(context.clone())),
            context,
        }
    }

    /// The context the services share, for the keymanager API.
    #[must_use]
    pub const fn context(&self) -> &DutyContext<P> {
        &self.context
    }

    /// Runs duties until the shutdown future completes.
    ///
    /// The slot loop runs in its own task, aborted at shutdown; duties already started finish on their own.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let slots = task::spawn(self.slots());
        shutdown.await;
        info!("validator client stopping");
        slots.abort();
        let _aborted = slots.await;
    }

    /// The slot loop, which never ends on its own.
    async fn slots(self) {
        let mut slot = self.context.timer.current_slot();
        let mut first = true;
        loop {
            self.context.timer.wait_until(slot, 0).await;
            self.on_slot(slot, first).await;
            first = false;
            // A clock that jumped forward skips the missed slots rather than replaying them late.
            slot = Slot(slot.0.max(self.context.timer.current_slot().0) + 1);
        }
    }

    /// Runs the start-of-slot work and starts the slot's duties.
    async fn on_slot(&self, slot: Slot, first: bool) {
        let context = &self.context;
        let epoch = slot.epoch::<P>();
        let epoch_start = slot == epoch.start_slot::<P>();
        debug!(slot = slot.0, "slot");
        context
            .nodes
            .check_health(context.settings.sync_tolerance)
            .await;

        // New keys are watched from the epoch they appear in, before any duty runs for them.
        if context.settings.doppelganger_epochs > 0 {
            self.doppelganger.watch_new(epoch);
        }
        DutyScheduler::new(context.clone()).refresh(epoch).await;
        if epoch_start || first {
            if context.settings.doppelganger_epochs > 0 {
                self.doppelganger.check(epoch).await;
            }
            let preparation = Arc::clone(&self.preparation);
            task::spawn(async move { preparation.run(epoch).await });
        }

        let proposer = BlockProposer::new(context.clone());
        task::spawn(async move { proposer.propose(slot).await });
        let attester = Attester::new(context.clone());
        task::spawn(async move { attester.run(slot).await });
        let sync = SyncCommittee::new(context.clone());
        task::spawn(async move { sync.run(slot).await });
        let ptc = PayloadTimeliness::new(context.clone());
        task::spawn(async move { ptc.run(slot).await });
    }
}
