//! Several beacon nodes behind one interface, ranked by health, with fallback.

use std::{
    collections::BTreeSet,
    future::Future,
    sync::{Arc, Mutex, PoisonError},
};

use axiom_beacon_json::api::SyncStatus;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::beacon::{ApiTopic, BeaconClient, BeaconError};

/// How fit a beacon node is to serve duties, best first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Health {
    /// At the head, with a validated payload and an engine online.
    Synced,
    /// At the head, but its head rests on a payload not yet validated, or its engine is offline.
    ///
    /// Duties may still be served, but blocks it builds may be invalid.
    Degraded,
    /// Behind the head by more than the tolerance.
    Syncing,
    /// Unreachable, or not yet checked.
    Offline,
}

impl Health {
    /// The health a sync status shows, behind the head by at most some slots.
    #[must_use]
    pub const fn of(status: &SyncStatus, tolerance: u64) -> Self {
        if status.is_syncing || status.sync_distance > tolerance {
            Self::Syncing
        } else if status.is_optimistic || status.el_offline {
            Self::Degraded
        } else {
            Self::Synced
        }
    }
}

/// The beacon nodes a validator client uses, in order of preference.
///
/// # Overview
///
/// Each request goes to the healthiest node first, then down the list until one answers.
/// A publication of a broadcast topic goes to every node that is not offline.
/// The message then spreads from several peers at once.
/// Other publications go to the healthiest node that accepts them.
/// A node's health comes from its sync status, refreshed by a periodic check.
///
/// Any node may lie, so nothing a node says bypasses slashing protection.
/// Fallback only buys liveness: a dead or lagging node does not stop the duties.
#[derive(Debug)]
pub struct BeaconNodes {
    /// The nodes, in configured order.
    nodes: Vec<Arc<BeaconClient>>,
    /// Each node's latest health, in the same order.
    health: Mutex<Vec<Health>>,
    /// The topics published on every node rather than the healthiest one.
    broadcast: BTreeSet<ApiTopic>,
}

impl BeaconNodes {
    /// A set of nodes in order of preference, all unchecked.
    ///
    /// # Errors
    ///
    /// Fails when the set is empty.
    pub fn new(nodes: Vec<BeaconClient>) -> Result<Self, BeaconError> {
        if nodes.is_empty() {
            return Err(BeaconError::NoNodes);
        }
        let health = vec![Health::Offline; nodes.len()];
        Ok(Self {
            nodes: nodes.into_iter().map(Arc::new).collect(),
            health: Mutex::new(health),
            broadcast: ApiTopic::defaults(),
        })
    }

    /// Publishes these topics on every node, and the others on the healthiest one.
    #[must_use]
    pub fn with_broadcast(mut self, topics: BTreeSet<ApiTopic>) -> Self {
        self.broadcast = topics;
        self
    }

    /// Asks every node for its sync status and ranks it.
    ///
    /// A node more than the tolerance behind the wall clock counts as syncing.
    pub async fn check_health(&self, tolerance: u64) {
        let mut checks = JoinSet::new();
        for (position, node) in self.nodes.iter().enumerate() {
            let node = Arc::clone(node);
            checks.spawn(async move { (position, node.node().syncing().await) });
        }
        let mut health = vec![Health::Offline; self.nodes.len()];
        while let Some(joined) = checks.join_next().await {
            let Ok((position, status)) = joined else {
                continue;
            };
            health[position] = match status {
                Ok(status) => Health::of(&status, tolerance),
                Err(error) => {
                    warn!(node = self.nodes[position].url(), %error, "beacon node offline");
                    Health::Offline
                }
            };
        }
        *self.health.lock().unwrap_or_else(PoisonError::into_inner) = health;
    }

    /// Each node's URL and latest health, in configured order.
    #[must_use]
    pub fn health(&self) -> Vec<(String, Health)> {
        let health = self.health.lock().unwrap_or_else(PoisonError::into_inner);
        self.nodes
            .iter()
            .zip(health.iter())
            .map(|(node, health)| (node.url().to_owned(), *health))
            .collect()
    }

    /// The nodes, healthiest first, configured order breaking ties.
    fn ranked(&self) -> Vec<Arc<BeaconClient>> {
        let health = self
            .health
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut order: Vec<usize> = (0..self.nodes.len()).collect();
        // A stable sort keeps the configured order among equally healthy nodes.
        order.sort_by_key(|position| health[*position]);
        order
            .into_iter()
            .map(|position| Arc::clone(&self.nodes[position]))
            .collect()
    }

    /// Runs a request on the healthiest node, falling back down the ranking until one answers.
    ///
    /// No content is an answer, not a failure, so it is returned at once.
    ///
    /// # Errors
    ///
    /// Fails with the last node's error when every node fails.
    pub async fn first<T, F, Fut>(&self, request: F) -> Result<T, BeaconError>
    where
        F: Fn(Arc<BeaconClient>) -> Fut,
        Fut: Future<Output = Result<T, BeaconError>>,
    {
        let mut last = BeaconError::NoNodes;
        for node in self.ranked() {
            match request(Arc::clone(&node)).await {
                Ok(answer) => return Ok(answer),
                Err(BeaconError::NoContent) => return Err(BeaconError::NoContent),
                Err(error) => {
                    debug!(node = node.url(), %error, "beacon node failed, trying the next");
                    last = error;
                }
            }
        }
        Err(last)
    }

    /// Sends a publication of a topic, to every node or to the healthiest that accepts it.
    ///
    /// # Errors
    ///
    /// Fails with one node's error when no node accepted it.
    pub async fn publish<F, Fut>(&self, topic: ApiTopic, publish: F) -> Result<(), BeaconError>
    where
        F: Fn(Arc<BeaconClient>) -> Fut,
        Fut: Future<Output = Result<(), BeaconError>> + Send + 'static,
    {
        if self.broadcast.contains(&topic) {
            self.broadcast(publish).await
        } else {
            self.first(publish).await
        }
    }

    /// Sends a publication to every node that is not offline, or to all when none is up.
    async fn broadcast<F, Fut>(&self, publish: F) -> Result<(), BeaconError>
    where
        F: Fn(Arc<BeaconClient>) -> Fut,
        Fut: Future<Output = Result<(), BeaconError>> + Send + 'static,
    {
        let health = self
            .health
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let any_up = health.iter().any(|health| *health != Health::Offline);
        let mut sends = JoinSet::new();
        for (node, health) in self.nodes.iter().zip(health) {
            if any_up && health == Health::Offline {
                continue;
            }
            sends.spawn(publish(Arc::clone(node)));
        }
        let mut last = BeaconError::NoNodes;
        let mut accepted = false;
        while let Some(joined) = sends.join_next().await {
            match joined {
                Ok(Ok(())) => accepted = true,
                Ok(Err(error)) => last = error,
                Err(_) => {}
            }
        }
        if accepted { Ok(()) } else { Err(last) }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Slot;

    use super::*;

    #[test]
    fn health_ranks_a_lagging_node_below_an_optimistic_one() {
        let status = |distance, optimistic| SyncStatus {
            head_slot: Slot(100),
            sync_distance: distance,
            is_syncing: false,
            is_optimistic: optimistic,
            el_offline: false,
        };
        // Within 2 slots and validated: synced; optimistic: degraded; 3 behind: syncing.
        assert_eq!(Health::of(&status(2, false), 2), Health::Synced);
        assert_eq!(Health::of(&status(0, true), 2), Health::Degraded);
        assert_eq!(Health::of(&status(3, false), 2), Health::Syncing);
        assert!(Health::Synced < Health::Degraded && Health::Degraded < Health::Syncing);
        assert!(Health::Syncing < Health::Offline);
    }
}
