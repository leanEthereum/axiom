//! The bounded queue of events from the swarm to the node.
//!
//! # Overview
//!
//! Events fall into two classes.
//!
//! - Traffic: gossip messages and inbound requests, which peers originate at will.
//! - Control: connections, disconnections, identify, and responses to this node's own requests.
//!
//! Control events are bounded by the number of connections and requests in flight.
//! They are always queued, so the node never misses a lifecycle change.
//!
//! Traffic is bounded twice.
//!
//! ```text
//! push traffic from peer P
//!   ├─ P already holds the per-peer limit  → Flooding: refused, P is disconnected
//!   ├─ the queue holds the total limit     → Dropped: refused, the node is overloaded
//!   └─ otherwise                           → Queued
//! ```
//!
//! A refused gossip message is ignored without penalty, and a refused request gets an error.
//! The swarm never waits on the node, so a slow node cannot stall the network.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, PoisonError},
};

use tokio::sync::Notify;

use super::NetworkEvent;
use crate::identity::PeerId;

/// How much peer traffic may wait for the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventLimits {
    /// Most traffic events queued across all peers.
    pub total: usize,
    /// Most traffic events queued from one peer.
    pub per_peer: usize,
}

impl Default for EventLimits {
    fn default() -> Self {
        // Threshold: one peer may take a quarter of the queue before it counts as flooding.
        Self {
            total: 4096,
            per_peer: 1024,
        }
    }
}

/// What became of a traffic event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Admission {
    /// The event waits for the node.
    Queued,
    /// The queue is full; the event was discarded.
    Dropped,
    /// The peer exceeded its share; the event was discarded and the peer should go.
    Flooding,
}

/// One queued event and the peer its slot is charged to.
#[derive(Debug)]
struct Entry {
    /// The event.
    event: NetworkEvent,
    /// The peer whose traffic share it uses, for traffic events.
    charged: Option<PeerId>,
}

/// The queue's bookkeeping, free of any synchronization.
#[derive(Debug)]
pub(super) struct EventBuffer {
    /// Events in arrival order.
    entries: VecDeque<Entry>,
    /// Traffic events queued in all.
    traffic: usize,
    /// Traffic events queued per peer.
    per_peer: BTreeMap<PeerId, usize>,
    /// The bounds.
    limits: EventLimits,
    /// Whether the swarm stopped: no more events will come.
    finished: bool,
    /// Whether the node dropped its receiver: events are discarded.
    abandoned: bool,
}

impl EventBuffer {
    /// An empty buffer under limits.
    pub(super) const fn new(limits: EventLimits) -> Self {
        Self {
            entries: VecDeque::new(),
            traffic: 0,
            per_peer: BTreeMap::new(),
            limits,
            finished: false,
            abandoned: false,
        }
    }

    /// Queues a control event unconditionally.
    pub(super) fn push_control(&mut self, event: NetworkEvent) {
        if !self.abandoned {
            self.entries.push_back(Entry {
                event,
                charged: None,
            });
        }
    }

    /// Queues a traffic event if both bounds allow it.
    pub(super) fn push_traffic(&mut self, peer: &PeerId, event: NetworkEvent) -> Admission {
        // The per-peer check comes first: a flooder is named even when the queue is full.
        let held = self.per_peer.get(peer).copied().unwrap_or(0);
        if held >= self.limits.per_peer {
            return Admission::Flooding;
        }
        if self.traffic >= self.limits.total {
            return Admission::Dropped;
        }
        // With nobody listening, accepting is harmless: the event is just discarded.
        if self.abandoned {
            return Admission::Queued;
        }
        self.traffic += 1;
        self.per_peer.insert(peer.clone(), held + 1);
        self.entries.push_back(Entry {
            event,
            charged: Some(peer.clone()),
        });
        Admission::Queued
    }

    /// Takes the oldest event and releases its slot.
    pub(super) fn pop(&mut self) -> Option<NetworkEvent> {
        let Entry { event, charged } = self.entries.pop_front()?;
        if let Some(peer) = charged {
            self.traffic -= 1;
            // Forget a peer with nothing queued, so the map stays as small as the queue.
            if let Some(count) = self.per_peer.get_mut(&peer) {
                *count -= 1;
                if *count == 0 {
                    self.per_peer.remove(&peer);
                }
            }
        }
        Some(event)
    }
}

/// The buffer shared by the swarm and the node, with a wake-up signal.
#[derive(Debug)]
pub(super) struct EventQueue {
    /// The bookkeeping.
    buffer: Mutex<EventBuffer>,
    /// Wakes the node when an event arrives or the swarm stops.
    ready: Notify,
}

impl EventQueue {
    /// An empty queue under limits.
    pub(super) fn new(limits: EventLimits) -> Arc<Self> {
        Arc::new(Self {
            buffer: Mutex::new(EventBuffer::new(limits)),
            ready: Notify::new(),
        })
    }

    /// Queues a control event and wakes the node.
    pub(super) fn push_control(&self, event: NetworkEvent) {
        self.with(|buffer| buffer.push_control(event));
        self.ready.notify_one();
    }

    /// Queues a traffic event if the bounds allow, waking the node when it does.
    pub(super) fn push_traffic(&self, peer: &PeerId, event: NetworkEvent) -> Admission {
        let admission = self.with(|buffer| buffer.push_traffic(peer, event));
        if admission == Admission::Queued {
            self.ready.notify_one();
        }
        admission
    }

    /// Marks the end of the stream: the node drains what is left, then sees the end.
    pub(super) fn finish(&self) {
        self.with(|buffer| buffer.finished = true);
        self.ready.notify_one();
    }

    /// Runs a closure on the locked buffer.
    fn with<T>(&self, action: impl FnOnce(&mut EventBuffer) -> T) -> T {
        // Every update leaves the buffer consistent, so a poisoned lock is still sound.
        action(&mut self.buffer.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// The stream of network events.
#[derive(Debug)]
pub struct NetworkEvents {
    /// The queue the swarm fills.
    queue: Arc<EventQueue>,
}

impl NetworkEvents {
    /// The node's end of a queue.
    pub(super) const fn new(queue: Arc<EventQueue>) -> Self {
        Self { queue }
    }

    /// The next event, or nothing once the swarm has stopped and the queue is drained.
    pub async fn next(&mut self) -> Option<NetworkEvent> {
        loop {
            // Phase 1: take an event, or learn that none will ever come.
            let (event, finished) = self.queue.with(|buffer| (buffer.pop(), buffer.finished));
            if event.is_some() || finished {
                return event;
            }
            // Phase 2: sleep until the swarm pushes.
            // A push between the check and here leaves a permit, so no wake-up is lost.
            self.queue.ready.notified().await;
        }
    }
}

impl Drop for NetworkEvents {
    fn drop(&mut self) {
        // Nobody will read: stop holding events.
        self.queue.with(|buffer| {
            buffer.abandoned = true;
            buffer.entries.clear();
            buffer.traffic = 0;
            buffer.per_peer.clear();
        });
    }
}

#[cfg(test)]
mod tests {
    use std::iter::from_fn;

    use tokio::runtime::Builder;

    use super::*;
    use crate::identity::PublicKey;

    /// A peer identifier from a seed byte.
    fn peer(seed: u8) -> PeerId {
        let mut key = [seed; 33];
        key[0] = 0x02;
        PeerId::from_public_key(&PublicKey::secp256k1(key))
    }

    /// A traffic-shaped event from a peer.
    fn disconnected(seed: u8) -> NetworkEvent {
        NetworkEvent::PeerDisconnected { peer: peer(seed) }
    }

    #[test]
    fn per_peer_bound_names_the_flooder() {
        // Fixture state: 10 slots in all, 2 per peer.
        let mut buffer = EventBuffer::new(EventLimits {
            total: 10,
            per_peer: 2,
        });

        // Peer 1 fills its 2 slots; its third event is flooding.
        assert_eq!(
            buffer.push_traffic(&peer(1), disconnected(1)),
            Admission::Queued
        );
        assert_eq!(
            buffer.push_traffic(&peer(1), disconnected(1)),
            Admission::Queued
        );
        assert_eq!(
            buffer.push_traffic(&peer(1), disconnected(1)),
            Admission::Flooding
        );

        // Peer 2 is unaffected.
        assert_eq!(
            buffer.push_traffic(&peer(2), disconnected(2)),
            Admission::Queued
        );

        // Popping one of peer 1's events frees one of its slots.
        assert_eq!(buffer.pop(), Some(disconnected(1)));
        assert_eq!(
            buffer.push_traffic(&peer(1), disconnected(1)),
            Admission::Queued
        );
    }

    #[test]
    fn total_bound_drops_without_blame() {
        // Fixture state: 3 slots in all, 2 per peer.
        let mut buffer = EventBuffer::new(EventLimits {
            total: 3,
            per_peer: 2,
        });
        assert_eq!(
            buffer.push_traffic(&peer(1), disconnected(1)),
            Admission::Queued
        );
        assert_eq!(
            buffer.push_traffic(&peer(2), disconnected(2)),
            Admission::Queued
        );
        assert_eq!(
            buffer.push_traffic(&peer(3), disconnected(3)),
            Admission::Queued
        );

        // Peer 4 holds nothing, but the queue is full: dropped, not flooding.
        assert_eq!(
            buffer.push_traffic(&peer(4), disconnected(4)),
            Admission::Dropped
        );

        // Control events bypass the bound and keep their place in line.
        buffer.push_control(disconnected(9));
        let order: Vec<_> = from_fn(|| buffer.pop()).collect();
        assert_eq!(
            order,
            [
                disconnected(1),
                disconnected(2),
                disconnected(3),
                disconnected(9)
            ]
        );
        assert_eq!(buffer.traffic, 0);
        assert!(buffer.per_peer.is_empty());
    }

    #[test]
    fn dropped_receiver_discards_events() {
        let queue = EventQueue::new(EventLimits::default());
        let events = NetworkEvents::new(Arc::clone(&queue));
        queue.push_control(disconnected(1));
        drop(events);

        // With nobody listening, nothing accumulates.
        queue.push_control(disconnected(2));
        assert_eq!(
            queue.push_traffic(&peer(3), disconnected(3)),
            Admission::Queued
        );
        assert_eq!(queue.with(|buffer| buffer.entries.len()), 0);
    }

    #[test]
    fn node_drains_then_sees_the_end() {
        let runtime = Builder::new_current_thread().build().unwrap();
        runtime.block_on(async {
            let queue = EventQueue::new(EventLimits::default());
            let mut events = NetworkEvents::new(Arc::clone(&queue));
            // One event, then the swarm stops: the event still comes out first.
            queue.push_control(disconnected(1));
            queue.finish();
            assert_eq!(events.next().await, Some(disconnected(1)));
            assert_eq!(events.next().await, None);
        });
    }
}
