//! The node's background loops: the fork choice clock and the engine follower.

use std::{sync::Arc, time::Duration};

use axiom_types::{Preset, SlotClock};
use tokio::{
    sync::broadcast::{self, error::RecvError},
    time,
};
use tracing::warn;

use crate::{ChainEvent, ChainHandle, Clock, ExecutionLayer};

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
#[derive(Debug)]
pub(crate) struct EngineFollower<P: Preset> {
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The chain's events.
    events: broadcast::Receiver<ChainEvent>,
    /// The engine.
    execution: Arc<ExecutionLayer>,
}

impl<P: Preset> EngineFollower<P> {
    /// A follower of a chain's heads.
    pub(crate) const fn new(
        chain: ChainHandle<P>,
        events: broadcast::Receiver<ChainEvent>,
        execution: Arc<ExecutionLayer>,
    ) -> Self {
        Self {
            chain,
            events,
            execution,
        }
    }

    /// Follows until the chain thread or its events stop.
    pub(crate) async fn run(mut self) {
        loop {
            match self.events.recv().await {
                Ok(ChainEvent::Head(head)) => {
                    let Some(verdict) = self.execution.update_forkchoice::<P>(head.execution).await
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
