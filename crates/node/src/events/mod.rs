//! The beacon API's event stream: what the chain and the network tell subscribed clients.
//!
//! # Overview
//!
//! 1. The chain thread and the network publish events through a sender that never waits.
//! 2. One hub task renders each event once and copies it to every subscriber of its topic.
//! 3. Each subscriber's stream has a bounded buffer; a client that falls behind is cut off.
//!
//! No lock guards consensus data: the chain thread only touches an atomic and a queue.

mod event;
mod hub;
mod topic;

pub use event::ApiEvent;
pub use hub::{EventHub, EventSender, EventSubscriptions, HubStopped};
pub use topic::{EventTopic, TopicSet, UnknownTopic};
