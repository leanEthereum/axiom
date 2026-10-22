//! The node's background loops: the fork choice clock and the engine follower.

use std::{sync::Arc, time::Duration};

use axiom_types::{ChainConfig, Preset, SlotClock};
use tokio::{
    sync::broadcast::{self, error::RecvError},
    time,
};
use tracing::warn;

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
/// When, as a fraction of a slot, the engine starts building the next slot's payload.
///
/// Two thirds in, the slot's block and votes have arrived, so the head is settled.
/// Proposers that build ahead give the engine the last third to fill the payload.
const PREPARE_AT_NUMERATOR: u64 = 2;

/// The denominator of the fraction above.
const PREPARE_AT_DENOMINATOR: u64 = 3;

/// Starts the engine building each prepared proposer's payload before its slot.
#[derive(Debug)]
pub(crate) struct PayloadPreparer<P: Preset> {
    /// The proposal desk.
    proposer: Arc<ProposerService<P>>,
    /// The wall clock.
    clock: Arc<dyn Clock>,
    /// Genesis and the slot length.
    slots: SlotClock,
}

impl<P: Preset> PayloadPreparer<P> {
    pub(crate) fn new(
        proposer: Arc<ProposerService<P>>,
        clock: Arc<dyn Clock>,
        slots: SlotClock,
    ) -> Self {
        Self {
            proposer,
            clock,
            slots,
        }
    }

    /// Each slot, two thirds in, prepares the next slot's payload.
    pub(crate) async fn run(self) {
        loop {
            let now = self.clock.now_ms();
            let slot = self.slots.slot_at(now);
            let start = self.slots.slot_start_ms(slot);
            let at = start
                + self.slots.slot_duration_ms() * PREPARE_AT_NUMERATOR / PREPARE_AT_DENOMINATOR;
            // Past this slot's moment, aim at the next slot's.
            let at = if now < at {
                at
            } else {
                at + self.slots.slot_duration_ms()
            };
            time::sleep(Duration::from_millis(at.saturating_sub(now))).await;
            let next = self.slots.slot_at(self.clock.now_ms()) + 1;
            self.proposer.prepare_next(next).await;
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
}
