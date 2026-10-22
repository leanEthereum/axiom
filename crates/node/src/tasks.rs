//! The node's background loops: the clock, payload preparation, sync watching, and the engine.

use std::{future, sync::Arc, time::Duration};

use axiom_types::{ChainConfig, Preset, Slot, SlotClock};
use tokio::{
    sync::broadcast::{self, error::RecvError},
    time,
};
use tracing::{info, warn};

use crate::{ChainEvent, ChainHandle, Clock, ExecutionLayer, ProposerService};

/// How many times per slot the fork choice clock advances.
///
/// Twelve ticks a slot is one a second on mainnet.
/// That is fine enough for every deadline inside a slot, and cheap.
const TICKS_PER_SLOT: u64 = 12;

/// Tick boundaries: every slot start, then a fixed period apart within the slot.
///
/// Counting from each slot start puts a tick on it, whatever the genesis time.
/// Counted from the Unix epoch, ticks miss slot starts when the period does not divide genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TickSchedule {
    /// The slots ticks are counted in.
    slots: SlotClock,
    /// Time between ticks inside a slot, never zero.
    period_ms: u64,
}

impl TickSchedule {
    /// The boundaries of a slot clock, a fixed number per slot.
    fn new(slots: SlotClock) -> Self {
        Self {
            slots,
            period_ms: (slots.slot_duration_ms() / TICKS_PER_SLOT).max(1),
        }
    }

    /// The first boundary after a time; before genesis, genesis itself.
    fn next(self, now_ms: u64) -> u64 {
        let genesis_ms = self.slots.genesis_ms();
        if now_ms < genesis_ms {
            return genesis_ms;
        }
        let slot = self.slots.slot_at(now_ms);
        let start = self.slots.slot_start_ms(slot);
        let tick = start + ((now_ms - start) / self.period_ms + 1) * self.period_ms;
        tick.min(self.slots.slot_start_ms(slot + 1))
    }
}

/// Advances the fork choice clock at a fixed fraction of the slot.
#[derive(Debug)]
pub(crate) struct Ticker<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The wall clock.
    clock: Arc<dyn Clock>,
    /// When to tick.
    schedule: TickSchedule,
}

impl<P: Preset> Ticker<P> {
    /// A ticker for a chain, ticking a fixed number of times per slot.
    pub(crate) fn new(chain: ChainHandle<P>, clock: Arc<dyn Clock>, slots: SlotClock) -> Self {
        Self {
            chain,
            clock,
            schedule: TickSchedule::new(slots),
        }
    }

    /// Ticks until the chain thread stops.
    pub(crate) async fn run(self) {
        loop {
            let now = self.clock.now_ms();
            match self.chain.run(move |chain| chain.on_tick(now)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "tick failed"),
                Err(_) => return,
            }
            // Sleep to the next boundary, so ticks stay aligned with slot starts.
            let next = self.schedule.next(now);
            time::sleep(Duration::from_millis(
                next.saturating_sub(self.clock.now_ms()),
            ))
            .await;
        }
    }
}

/// Tells the engine about every new head and feeds its verdicts back.
/// Default lead of payload preparation, as a fraction of a slot: one third.
///
/// Two thirds in, the slot's block and votes have arrived, so the head is settled.
/// Proposers that build ahead give the engine the last third to fill the payload.
const DEFAULT_LEAD_DENOMINATOR: u64 = 3;

/// When each slot's payload is prepared: a fixed lead before the slot starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PreparationSchedule {
    /// Genesis and the slot length.
    slots: SlotClock,
    /// How long before each slot its payload is prepared, at most a slot.
    lead_ms: u64,
}

impl PreparationSchedule {
    /// A schedule leading each slot by a lookahead, or by a third of a slot without one.
    fn new(slots: SlotClock, lookahead: Option<Duration>) -> Self {
        let slot_ms = slots.slot_duration_ms();
        let lead_ms = lookahead.map_or(slot_ms / DEFAULT_LEAD_DENOMINATOR, |lookahead| {
            u64::try_from(lookahead.as_millis()).unwrap_or(u64::MAX)
        });
        Self {
            slots,
            // A lead past one slot would aim at the slot after next.
            lead_ms: lead_ms.min(slot_ms),
        }
    }

    /// The next moment to prepare at, after a time, and the slot it prepares.
    fn next(self, now_ms: u64) -> (u64, Slot) {
        let next = self.slots.slot_at(now_ms) + 1;
        let at = self.slots.slot_start_ms(next).saturating_sub(self.lead_ms);
        // Past this slot's moment, aim at the following slot's.
        if now_ms < at {
            (at, next)
        } else {
            let after = next + 1;
            (
                self.slots.slot_start_ms(after).saturating_sub(self.lead_ms),
                after,
            )
        }
    }
}

/// Starts the engine building each prepared proposer's payload before its slot.
#[derive(Debug)]
pub(crate) struct PayloadPreparer<P: Preset> {
    /// The proposal desk.
    proposer: Arc<ProposerService<P>>,
    /// The wall clock.
    clock: Arc<dyn Clock>,
    /// When to prepare.
    schedule: PreparationSchedule,
}

impl<P: Preset> PayloadPreparer<P> {
    /// A preparer leading each slot by a lookahead, or by a third of a slot without one.
    pub(crate) fn new(
        proposer: Arc<ProposerService<P>>,
        clock: Arc<dyn Clock>,
        slots: SlotClock,
        lookahead: Option<Duration>,
    ) -> Self {
        Self {
            proposer,
            clock,
            schedule: PreparationSchedule::new(slots, lookahead),
        }
    }

    /// Before each slot, by the lead, prepares that slot's payload.
    pub(crate) async fn run(self) {
        loop {
            let now = self.clock.now_ms();
            let (at, slot) = self.schedule.next(now);
            time::sleep(Duration::from_millis(at.saturating_sub(now))).await;
            self.proposer.prepare_next(slot).await;
        }
    }
}

/// Completes once the head is within a slot of the wall clock, for a node that stops when synced.
#[derive(Debug)]
pub(crate) struct SyncWatcher<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// Genesis and the slot length.
    slots: SlotClock,
}

impl<P: Preset> SyncWatcher<P> {
    /// A watcher of a chain.
    pub(crate) const fn new(chain: ChainHandle<P>, slots: SlotClock) -> Self {
        Self { chain, slots }
    }

    /// Completes once synced when asked to stop then, and never otherwise.
    pub(crate) async fn stop(self, when_synced: bool) {
        if when_synced {
            self.synced().await;
            info!("synced; stopping as asked");
        } else {
            future::pending::<()>().await;
        }
    }

    /// Waits, checking twice a slot, until the head is synced or the chain thread stops.
    async fn synced(self) {
        let period = Duration::from_millis((self.slots.slot_duration_ms() / 2).max(1));
        loop {
            match self.chain.run(|chain| chain.is_synced()).await {
                Ok(true) | Err(_) => return,
                Ok(false) => time::sleep(period).await,
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct EngineFollower<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The chain's events.
    events: broadcast::Receiver<ChainEvent>,
    /// The engine.
    execution: Arc<ExecutionLayer>,
    /// The fork schedule, which picks the engine method version of each head.
    config: ChainConfig,
}

impl<P: Preset> EngineFollower<P> {
    /// A follower of a chain's heads.
    pub(crate) const fn new(
        chain: ChainHandle<P>,
        events: broadcast::Receiver<ChainEvent>,
        execution: Arc<ExecutionLayer>,
        config: ChainConfig,
    ) -> Self {
        Self {
            chain,
            events,
            execution,
            config,
        }
    }

    /// Follows until the chain thread or its events stop.
    pub(crate) async fn run(mut self) {
        loop {
            match self.events.recv().await {
                Ok(ChainEvent::Head(head)) => {
                    let fork = self.config.fork_at(head.slot.epoch::<P>());
                    let Some(verdict) = self
                        .execution
                        .update_forkchoice::<P>(fork, head.execution)
                        .await
                    else {
                        continue;
                    };
                    let root = head.root;
                    let applied = self
                        .chain
                        .run(move |chain| chain.on_payload_verdict(root, verdict))
                        .await;
                    match applied {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => warn!(%error, "engine verdict not applied"),
                        Err(_) => return,
                    }
                }
                Ok(ChainEvent::Reorg { .. } | ChainEvent::Finalized(_)) => {}
                // Falling behind skips stale heads; the next one supersedes them anyway.
                Err(RecvError::Lagged(skipped)) => warn!(skipped, "engine follower lagged"),
                Err(RecvError::Closed) => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Slot;

    use super::*;

    #[test]
    fn a_tick_falls_on_every_slot_start() {
        // Fixture state: genesis at 1_000 ms and slots of 2_000 ms, so ticks 166 ms apart.
        // Slot 1 starts at 3_000, which no multiple of 166 counted from the Unix epoch hits.
        let slots = SlotClock::new(1_000, 2_000);
        let schedule = TickSchedule::new(slots);
        assert_eq!(slots.slot_start_ms(Slot(1)), 3_000);

        // Before genesis, the first tick is genesis itself.
        assert_eq!(schedule.next(0), 1_000);

        // Inside slot 0, ticks are a period apart from its start.
        assert_eq!(schedule.next(1_000), 1_166);
        assert_eq!(schedule.next(1_200), 1_332);

        // Twelve periods make 1_992 ms, so the last tick of slot 0 is at 2_992.
        // The next one is slot 1's start, not 3_158.
        assert_eq!(schedule.next(2_900), 2_992);
        assert_eq!(schedule.next(2_992), 3_000);
        assert_eq!(schedule.next(3_000), 3_166);
    }

    #[test]
    fn payloads_are_prepared_a_lead_before_their_slot() {
        // Fixture state: genesis at 0 and slots of 12_000 ms, so slot 1 starts at 12_000.
        let slots = SlotClock::new(0, 12_000);

        // The default lead is a third of a slot: slot 1 is prepared at 8_000.
        let default = PreparationSchedule::new(slots, None);
        assert_eq!(default.next(0), (8_000, Slot(1)));
        // At or past that moment, the next aim is slot 2, at 20_000.
        assert_eq!(default.next(8_000), (20_000, Slot(2)));

        // A 2 second lookahead prepares slot 1 at 10_000.
        let short = PreparationSchedule::new(slots, Some(Duration::from_secs(2)));
        assert_eq!(short.next(9_999), (10_000, Slot(1)));

        // A lead longer than a slot is cut to one slot: slot 2 is prepared at slot 1's start.
        let long = PreparationSchedule::new(slots, Some(Duration::from_secs(30)));
        assert_eq!(long.next(5_000), (12_000, Slot(2)));
    }
}
