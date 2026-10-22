//! The event hub: one queue in from every producer, one bounded buffer out per subscriber.

use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use axiom_http::BodyStream;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::debug;

use super::{ApiEvent, EventTopic, TopicSet};
use crate::race::Either;

/// Events waiting for the hub, across every producer.
///
/// Producers never wait: past this many, new events are dropped and logged.
const HUB_QUEUE: usize = 4096;

/// Rendered events buffered for one subscriber.
///
/// A subscriber further behind than this is cut off, so a slow client never holds memory hostage.
const SUBSCRIBER_BUFFER: usize = 256;

/// Subscriptions waiting for the hub to take them in.
const JOIN_QUEUE: usize = 64;

/// The producers' end: publishes events without ever waiting.
///
/// # Overview
///
/// The chain thread and the network publish through it.
/// A send never blocks and never takes a lock.
///
/// - The hub publishes the union of every subscriber's topics in an atomic word.
/// - A producer checks it first, so an event nobody wants costs one load.
/// - A full queue drops the event rather than stalling consensus work.
#[derive(Clone, Debug)]
pub struct EventSender {
    /// The hub's queue, absent for a sender with no hub.
    events: Option<mpsc::Sender<ApiEvent>>,
    /// The topics some subscriber wants.
    wanted: Arc<AtomicU32>,
}

impl EventSender {
    /// A sender with no hub behind it, which nobody ever listens to.
    #[must_use]
    pub fn detached() -> Self {
        Self {
            events: None,
            wanted: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Whether some subscriber wants a topic, so building its event is worth the work.
    #[must_use]
    pub fn wants(&self, topic: EventTopic) -> bool {
        TopicSet::from_bits(self.wanted.load(Ordering::Relaxed)).contains(topic)
    }

    /// Publishes an event, dropping it when nobody wants it or the hub is behind.
    pub fn publish(&self, event: ApiEvent) {
        let Some(events) = &self.events else {
            return;
        };
        if !self.wants(event.topic()) {
            return;
        }
        if let Err(error) = events.try_send(event) {
            debug!(%error, "event dropped");
        }
    }
}

impl Default for EventSender {
    fn default() -> Self {
        Self::detached()
    }
}

/// The API's end: opens a stream of the events of some topics.
#[derive(Clone, Debug)]
pub struct EventSubscriptions {
    /// The hub's queue of new subscribers.
    joins: mpsc::Sender<Subscriber>,
}

/// The hub has stopped, so no stream can open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("event hub stopped")]
pub struct HubStopped;

impl EventSubscriptions {
    /// A stream of the rendered events of some topics, from now on.
    ///
    /// # Errors
    ///
    /// Fails when the hub has stopped.
    pub async fn subscribe(&self, topics: TopicSet) -> Result<BodyStream, HubStopped> {
        let (sender, stream) = BodyStream::channel(SUBSCRIBER_BUFFER);
        self.joins
            .send(Subscriber { topics, sender })
            .await
            .map_err(|_| HubStopped)?;
        Ok(stream)
    }
}

/// One open stream.
#[derive(Debug)]
struct Subscriber {
    /// The topics it asked for.
    topics: TopicSet,
    /// Its buffer of rendered events.
    sender: mpsc::Sender<Vec<u8>>,
}

/// The task that fans every event out to the subscribers of its topic.
///
/// Each event is rendered once, however many subscribers it reaches.
#[derive(Debug)]
pub struct EventHub {
    /// Events from every producer.
    events: mpsc::Receiver<ApiEvent>,
    /// New subscribers.
    joins: mpsc::Receiver<Subscriber>,
    /// Open streams.
    subscribers: Vec<Subscriber>,
    /// The union of the open streams' topics, shared with producers.
    wanted: Arc<AtomicU32>,
}

impl EventHub {
    /// A hub, its producers' sender, and its subscription handle.
    #[must_use]
    pub fn new() -> (Self, EventSender, EventSubscriptions) {
        let (events_in, events) = mpsc::channel(HUB_QUEUE);
        let (joins_in, joins) = mpsc::channel(JOIN_QUEUE);
        let wanted = Arc::new(AtomicU32::new(0));
        let hub = Self {
            events,
            joins,
            subscribers: Vec::new(),
            wanted: Arc::clone(&wanted),
        };
        let sender = EventSender {
            events: Some(events_in),
            wanted,
        };
        (hub, sender, EventSubscriptions { joins: joins_in })
    }

    /// Fans events out until every producer is gone.
    pub async fn run(mut self) {
        // Phase 1: take both new subscribers and events.
        // Joins are polled first, so an event right after a subscription reaches it.
        loop {
            match Either::race(self.joins.recv(), self.events.recv()).await {
                Either::Left(Some(subscriber)) => {
                    self.subscribers.push(subscriber);
                    self.refresh();
                }
                // The subscription handle is gone: no stream can open any more.
                Either::Left(None) => break,
                Either::Right(Some(event)) => self.deliver(&event),
                Either::Right(None) => return,
            }
        }
        // Phase 2: serve the streams already open until the producers stop.
        while let Some(event) = self.events.recv().await {
            self.deliver(&event);
        }
    }

    /// Hands an event to every subscriber of its topic, cutting off the closed and the slow.
    fn deliver(&mut self, event: &ApiEvent) {
        let topic = event.topic();
        let mut rendered = None;
        let before = self.subscribers.len();
        self.subscribers.retain(|subscriber| {
            if subscriber.sender.is_closed() {
                return false;
            }
            if !subscriber.topics.contains(topic) {
                return true;
            }
            let bytes = rendered.get_or_insert_with(|| event.render());
            // A full buffer means the client reads slower than events arrive.
            subscriber.sender.try_send(bytes.clone()).is_ok()
        });
        if self.subscribers.len() != before {
            self.refresh();
        }
    }

    /// Publishes the union of the open streams' topics to producers.
    fn refresh(&self) {
        let union = self
            .subscribers
            .iter()
            .fold(TopicSet::EMPTY, |union, subscriber| {
                union.union(subscriber.topics)
            });
        self.wanted.store(union.bits(), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use axiom_json::Json;

    use super::*;

    fn event(topic: EventTopic, value: &str) -> ApiEvent {
        ApiEvent::json(topic, Json::from(value))
    }

    #[test]
    fn events_reach_only_their_topics_subscribers() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (hub, sender, subscriptions) = EventHub::new();
            let hub = tokio::spawn(hub.run());

            // No subscriber yet: producers see nothing wanted.
            assert!(!sender.wants(EventTopic::Head));

            // One stream for heads, one for heads and blocks.
            let mut heads = subscriptions
                .subscribe(TopicSet::EMPTY.with(EventTopic::Head))
                .await
                .unwrap();
            let mut both = subscriptions
                .subscribe(
                    TopicSet::EMPTY
                        .with(EventTopic::Head)
                        .with(EventTopic::Block),
                )
                .await
                .unwrap();
            while !sender.wants(EventTopic::Block) {
                tokio::task::yield_now().await;
            }
            assert!(!sender.wants(EventTopic::ChainReorg));

            // A block reaches only the second stream; a head reaches both, rendered alike.
            sender.publish(event(EventTopic::Block, "b"));
            sender.publish(event(EventTopic::Head, "h"));
            assert_eq!(
                heads.next().await,
                Some(b"event: head\ndata: \"h\"\n\n".to_vec())
            );
            assert_eq!(
                both.next().await,
                Some(b"event: block\ndata: \"b\"\n\n".to_vec())
            );
            assert_eq!(
                both.next().await,
                Some(b"event: head\ndata: \"h\"\n\n".to_vec())
            );

            // A closed stream is dropped at the next event, and its topics go with it.
            drop(both);
            sender.publish(event(EventTopic::Head, "h2"));
            assert_eq!(
                heads.next().await,
                Some(b"event: head\ndata: \"h2\"\n\n".to_vec())
            );
            while sender.wants(EventTopic::Block) {
                tokio::task::yield_now().await;
            }

            // The hub stops once every producer and handle is gone.
            drop((sender, subscriptions));
            hub.await.unwrap();
            assert_eq!(heads.next().await, None);
        });
    }

    #[test]
    fn a_slow_subscriber_is_cut_off() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (hub, sender, subscriptions) = EventHub::new();
            tokio::spawn(hub.run());
            let mut stream = subscriptions
                .subscribe(TopicSet::EMPTY.with(EventTopic::Head))
                .await
                .unwrap();
            while !sender.wants(EventTopic::Head) {
                tokio::task::yield_now().await;
            }

            // Mutation: 300 events against a buffer of 256, with the reader asleep.
            for index in 0..300 {
                sender.publish(event(EventTopic::Head, &index.to_string()));
                tokio::task::yield_now().await;
            }

            // The first 256 arrive, then the stream ends: the reader fell too far behind.
            let mut received = 0;
            while stream.next().await.is_some() {
                received += 1;
            }
            assert_eq!(received, SUBSCRIBER_BUFFER);
            assert!(!sender.wants(EventTopic::Head));
        });
    }
}
