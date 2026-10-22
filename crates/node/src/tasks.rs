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

/// Advances the fork choice clock at a fixed fraction of the slot.
#[derive(Debug)]
pub(crate) struct Ticker<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The wall clock.
    clock: Arc<dyn Clock>,
    /// Time between ticks, never zero.
    period_ms: u64,
}

impl<P: Preset> Ticker<P> {
    /// A ticker for a chain, ticking a fixed number of times per slot.
    pub(crate) fn new(chain: ChainHandle<P>, clock: Arc<dyn Clock>, slots: SlotClock) -> Self {
        Self {
            chain,
            clock,
            period_ms: (slots.slot_duration_ms() / TICKS_PER_SLOT).max(1),
        }
    }

    /// Ticks until the chain thread stops.
    pub(crate) async fn run(self) {
        let period = self.period_ms;
        loop {
            let now = self.clock.now_ms();
            match self.chain.run(move |chain| chain.on_tick(now)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "tick failed"),
                Err(_) => return,
            }
            // Sleep to the next boundary, so ticks stay aligned with slot starts.
            let next = (now / period + 1) * period;
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
