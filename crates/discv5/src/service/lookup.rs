//! The iterative search for the nodes closest to a target.
//!
//! See discv5-theory.md, "Lookup" and "Lookup Protocol".

use std::collections::BTreeMap;

use axiom_types::ChainConfig;

use super::EnrFilter;
use crate::{
    distance::{Distance, LogDistance},
    enr::Enr,
    node_id::NodeId,
};

/// Identifies one lookup among those running.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LookupId(pub u64);

/// What the search knows of one peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerState {
    /// Heard of, not asked yet.
    Fresh,
    /// Asked, answer pending.
    Waiting,
    /// Answered.
    Responded,
    /// Did not answer.
    Failed,
}

/// The next move of a lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Send FINDNODE to these peers.
    Query(Vec<Enr>),
    /// Wait for answers in flight.
    Wait,
    /// The search is over.
    Done,
}

/// An iterative Kademlia lookup with bounded concurrency.
///
/// # Algorithm
///
/// ```text
/// seed with the closest nodes in the local table
/// loop:
///     closest = the k nearest peers that have not failed
///     if all of closest answered: done
///     ask unasked peers of closest until alpha requests are in flight
///     merge every answer into the peer set
/// ```
#[derive(Clone, Debug)]
pub(crate) struct Lookup {
    /// The id searched for.
    target: NodeId,
    /// The condition results must meet.
    filter: EnrFilter,
    /// Most results to return.
    wanted: usize,
    /// Whether the service started it for itself, so no event reports it.
    internal: bool,
    /// Every peer heard of, keyed by distance to the target.
    peers: BTreeMap<Distance, (Enr, PeerState)>,
}

impl Lookup {
    /// A lookup seeded with known records.
    pub(crate) fn new(
        target: NodeId,
        filter: EnrFilter,
        wanted: usize,
        internal: bool,
        seeds: Vec<Enr>,
    ) -> Self {
        let mut lookup = Self {
            target,
            filter,
            wanted,
            internal,
            peers: BTreeMap::new(),
        };
        for enr in seeds {
            lookup.add(enr);
        }
        lookup
    }

    /// The id searched for.
    pub(crate) const fn target(&self) -> NodeId {
        self.target
    }

    /// Whether the service started it for itself.
    pub(crate) const fn is_internal(&self) -> bool {
        self.internal
    }

    /// Adds a peer heard of, keeping the newest record of a known one.
    pub(crate) fn add(&mut self, enr: Enr) {
        // Distinct ids sit at distinct distances, so the distance is a unique key.
        let distance = enr.node_id().distance(&self.target);
        match self.peers.get_mut(&distance) {
            Some((known, _)) if known.seq() < enr.seq() => *known = enr,
            Some(_) => {}
            None => {
                self.peers.insert(distance, (enr, PeerState::Fresh));
            }
        }
    }

    /// Records a peer's answer.
    pub(crate) fn on_response(&mut self, node: &NodeId) {
        self.set_state(node, PeerState::Responded);
    }

    /// Records a peer's silence.
    pub(crate) fn on_failure(&mut self, node: &NodeId) {
        self.set_state(node, PeerState::Failed);
    }

    /// Sets the state of a known peer.
    fn set_state(&mut self, node: &NodeId, state: PeerState) {
        if let Some((_, current)) = self.peers.get_mut(&node.distance(&self.target)) {
            *current = state;
        }
    }

    /// Picks the next peers to ask and marks them as asked.
    pub(crate) fn next(&mut self, alpha: usize, k: usize) -> Step {
        // Phase 1: the k nearest peers still in the running.
        let closest: Vec<Distance> = self
            .peers
            .iter()
            .filter(|(_, (_, state))| *state != PeerState::Failed)
            .take(k)
            .map(|(distance, _)| *distance)
            .collect();
        let state = |distance: &Distance| self.peers.get(distance).map(|(_, state)| *state);
        if closest
            .iter()
            .all(|distance| state(distance) == Some(PeerState::Responded))
        {
            return Step::Done;
        }

        // Phase 2: top up the requests in flight to alpha, nearest first.
        let waiting = self
            .peers
            .values()
            .filter(|(_, state)| *state == PeerState::Waiting)
            .count();
        let fresh: Vec<Distance> = closest
            .into_iter()
            .filter(|distance| state(distance) == Some(PeerState::Fresh))
            .take(alpha.saturating_sub(waiting))
            .collect();
        if fresh.is_empty() {
            return if waiting == 0 { Step::Done } else { Step::Wait };
        }
        let mut queries = Vec::with_capacity(fresh.len());
        for distance in fresh {
            if let Some((enr, state)) = self.peers.get_mut(&distance) {
                *state = PeerState::Waiting;
                queries.push(enr.clone());
            }
        }
        Step::Query(queries)
    }

    /// The distances to ask a peer for: its distance to the target, then the neighbours.
    ///
    /// A peer files the target's neighbourhood in the bucket at that distance.
    /// The adjacent buckets catch it when that bucket is thin.
    pub(crate) fn distances(&self, peer: &NodeId, count: usize) -> Vec<LogDistance> {
        // Alternate outward from the centre: d, d + 1, d - 1, d + 2, ...
        let centre = i32::from(peer.log_distance(&self.target).get().max(1));
        let mut distances = Vec::with_capacity(count);
        let mut offset = 0_i32;
        while distances.len() < count && offset <= 256 {
            for candidate in [centre + offset, centre - offset] {
                // Distances outside 1..=256 name no bucket.
                let Ok(value) = u16::try_from(candidate) else {
                    continue;
                };
                let Ok(distance) = LogDistance::new(value) else {
                    continue;
                };
                if value >= 1 && distances.len() < count && !distances.contains(&distance) {
                    distances.push(distance);
                }
            }
            offset += 1;
        }
        distances
    }

    /// The results: peers that did not fail and meet the filter, nearest first.
    pub(crate) fn results(&self, chain: &ChainConfig) -> Vec<Enr> {
        self.peers
            .values()
            .filter(|(enr, state)| *state != PeerState::Failed && self.filter.matches(enr, chain))
            .take(self.wanted)
            .map(|(enr, _)| enr.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::secp256k1::SecretKey;

    use super::*;

    /// A record with a given key seed.
    fn record(seed: u8) -> Enr {
        let mut secret = [1; 32];
        secret[31] = seed;
        Enr::builder()
            .build(&SecretKey::from_bytes(&secret).expect("valid key"))
            .expect("record fits")
    }

    #[test]
    fn concurrency_and_termination() {
        // Five seeds, alpha 3, k 4: three queries go out first.
        let target = NodeId([0; 32]);
        let seeds: Vec<Enr> = (1..=5).map(record).collect();
        let mut lookup = Lookup::new(target, EnrFilter::Any, 16, false, seeds);
        let Step::Query(first) = lookup.next(3, 4) else {
            panic!("expected queries");
        };
        assert_eq!(first.len(), 3);
        // Nothing more while three are in flight.
        assert_eq!(lookup.next(3, 4), Step::Wait);
        // One answers: the fourth closest goes out.
        lookup.on_response(&first[0].node_id());
        let Step::Query(second) = lookup.next(3, 4) else {
            panic!("expected a query");
        };
        assert_eq!(second.len(), 1);
        // One fails: the fifth peer enters the closest four and goes out.
        lookup.on_failure(&first[1].node_id());
        let Step::Query(third) = lookup.next(3, 4) else {
            panic!("expected a query");
        };
        assert_eq!(third.len(), 1);
        // The rest answer: the closest four have all answered, so the search ends.
        lookup.on_response(&first[2].node_id());
        lookup.on_response(&second[0].node_id());
        lookup.on_response(&third[0].node_id());
        assert_eq!(lookup.next(3, 4), Step::Done);
        // Results skip the failed peer.
        assert_eq!(lookup.results(&ChainConfig::mainnet()).len(), 4);
    }

    #[test]
    fn distances_fan_out_from_the_centre() {
        // A peer at distance 256 from the target: 256, then 255, 254.
        let target = NodeId([0; 32]);
        let lookup = Lookup::new(target, EnrFilter::Any, 16, false, Vec::new());
        let far = NodeId([0x80; 32]);
        let values: Vec<u16> = lookup.distances(&far, 3).iter().map(|d| d.get()).collect();
        assert_eq!(values, [256, 255, 254]);
        // A peer at distance 9: 9, 10, 8.
        let mut mid = [0; 32];
        mid[30] = 1;
        let values: Vec<u16> = lookup
            .distances(&NodeId(mid), 3)
            .iter()
            .map(|d| d.get())
            .collect();
        assert_eq!(values, [9, 10, 8]);
        // The target itself: distances start at 1.
        let values: Vec<u16> = lookup
            .distances(&target, 3)
            .iter()
            .map(|d| d.get())
            .collect();
        assert_eq!(values, [1, 2, 3]);
    }

    #[test]
    fn empty_lookups_end_at_once() {
        let mut lookup = Lookup::new(NodeId([0; 32]), EnrFilter::Any, 16, true, Vec::new());
        assert_eq!(lookup.next(3, 16), Step::Done);
        assert!(lookup.is_internal());
    }
}
