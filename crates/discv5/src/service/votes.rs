//! Votes on the local external address, from the endpoint each PONG reports.
//!
//! # Overview
//!
//! A node behind a NAT does not know the address the internet sees.
//! Every PONG names the endpoint its sender saw the PING come from.
//! Many independent peers naming the same endpoint make it the node's external address.
//!
//! # Invariants
//!
//! A peer may lie about the endpoint it saw, to make the node advertise an address it does not own.
//! An eclipse attacker gains from that: a node that advertises a dead address receives no inbound peers.
//! Four rules make a lie expensive:
//!
//! - Votes come only from PONGs that answer this node's own PINGs.
//!   The node picks whom it pings from its routing table, whose subnet caps bound any one operator.
//! - Node identifiers cost nothing to mint, so votes count per network, not per node.
//!   Every voter in one public IPv4 /24 or IPv6 /48 counts once.
//! - An address needs a minimum number of agreeing networks, and strictly more than any rival.
//!   A tie never moves the confirmed address, so a minority can only stall, never flip it.
//! - Votes expire, so a lie stops counting once its sender stops answering.
//!
//! An attacker must therefore answer from more public networks than the honest peers the node pings.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use crate::node_id::NodeId;

/// How address voting decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoteConfig {
    /// Distinct voter networks that must agree before an address is confirmed.
    pub threshold: usize,
    /// How long a vote counts after it is cast.
    pub lifetime: Duration,
    /// Most votes kept at once; past it, the oldest vote goes.
    pub capacity: usize,
}

impl Default for VoteConfig {
    fn default() -> Self {
        Self {
            // Threshold: ten public networks must agree.
            // An attacker must answer from ten distinct /24s the node chose to ping.
            // At one liveness PING every 10 s, a node with a healthy table gets there in minutes.
            threshold: 10,
            // Timing: twenty minutes span about 120 liveness checks at one every 10 s.
            // That is far more than the threshold needs, yet a stale address fades within the hour.
            lifetime: Duration::from_secs(20 * 60),
            // A routing table holds at most 256 buckets of 16; votes come only from pinged peers.
            capacity: 512,
        }
    }
}

/// An external address that enough peers agreed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmedAddress {
    /// The IPv4 endpoint peers see.
    pub address: SocketAddrV4,
    /// Distinct voter networks behind it when it was confirmed.
    pub votes: usize,
}

/// The network a voter speaks for: hosts in one public prefix count once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum VoterNetwork {
    /// A public IPv4 /24.
    Ipv4([u8; 3]),
    /// A public IPv6 /48.
    Ipv6([u8; 6]),
    /// A host on a private, loopback, or link-local network, which counts alone.
    Local(IpAddr),
}

impl VoterNetwork {
    /// The network a voter's address belongs to.
    fn of(ip: IpAddr) -> Self {
        // Hosts on a local network are told apart: a test network may share one /24.
        // An internet attacker cannot hold such an address, since the session answers there.
        match ip {
            IpAddr::V4(ip) if ip.is_private() || ip.is_loopback() || ip.is_link_local() => {
                Self::Local(ip.into())
            }
            IpAddr::V4(ip) => {
                let [a, b, c, _] = ip.octets();
                Self::Ipv4([a, b, c])
            }
            IpAddr::V6(ip) if Self::is_local_v6(ip) => Self::Local(ip.into()),
            IpAddr::V6(ip) => {
                let [a, b, c, d, e, f, ..] = ip.octets();
                Self::Ipv6([a, b, c, d, e, f])
            }
        }
    }

    /// Whether an IPv6 address is loopback, unique local, or link-local.
    ///
    /// Unique local is fc00::/7, per RFC 4193; link-local is fe80::/10, per RFC 4291.
    fn is_local_v6(ip: Ipv6Addr) -> bool {
        let first = ip.segments()[0];
        ip.is_loopback() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
    }
}

/// One peer's latest statement of the local endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Vote {
    /// The endpoint the peer saw.
    address: SocketAddrV4,
    /// The network the peer speaks for.
    network: VoterNetwork,
    /// When the vote was cast.
    cast: Duration,
}

/// The votes peers cast on the local external address, and the address they confirmed.
///
/// The type is pure: the caller passes the time, so equal inputs give equal outputs.
#[derive(Clone, Debug)]
pub struct AddressVotes {
    /// The decision rule.
    config: VoteConfig,
    /// Each peer's latest vote; a new vote replaces the peer's old one.
    votes: BTreeMap<NodeId, Vote>,
    /// The address the votes last confirmed.
    confirmed: Option<SocketAddrV4>,
}

impl AddressVotes {
    /// No votes and no confirmed address.
    #[must_use]
    pub const fn new(config: VoteConfig) -> Self {
        Self {
            config,
            votes: BTreeMap::new(),
            confirmed: None,
        }
    }

    /// The address the votes last confirmed.
    ///
    /// It stays confirmed after its votes expire, until another address wins.
    #[must_use]
    pub const fn confirmed(&self) -> Option<SocketAddrV4> {
        self.confirmed
    }

    /// Counts a peer's statement of the local endpoint.
    ///
    /// # Arguments
    ///
    /// - `now`: the caller's monotonic time.
    /// - `voter`: the peer, so each peer holds one vote.
    /// - `from`: the peer's own address, which places it in a network.
    /// - `observed`: the local endpoint as the peer saw it.
    ///
    /// # Returns
    ///
    /// The newly confirmed address, when this vote changed it.
    pub fn record(
        &mut self,
        now: Duration,
        voter: NodeId,
        from: IpAddr,
        observed: SocketAddr,
    ) -> Option<ConfirmedAddress> {
        // Only IPv4 endpoints feed the record's address entry.
        let SocketAddr::V4(address) = observed else {
            return None;
        };
        // An endpoint no packet can come from is a lie or a bug, never a vote.
        let ip = *address.ip();
        if address.port() == 0 || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
            return None;
        }
        self.expire(now);
        self.votes.insert(
            voter,
            Vote {
                address,
                network: VoterNetwork::of(from),
                cast: now,
            },
        );
        self.evict();
        self.decide()
    }

    /// Drops votes older than their lifetime.
    fn expire(&mut self, now: Duration) {
        let lifetime = self.config.lifetime;
        self.votes
            .retain(|_, vote| now.saturating_sub(vote.cast) < lifetime);
    }

    /// Drops the oldest votes past the capacity.
    fn evict(&mut self) {
        while self.votes.len() > self.config.capacity {
            // The oldest vote goes; equal times fall back to the identifier, so the choice is fixed.
            let oldest = self
                .votes
                .iter()
                .min_by_key(|(node, vote)| (vote.cast, **node))
                .map(|(node, _)| *node);
            let Some(oldest) = oldest else {
                return;
            };
            self.votes.remove(&oldest);
        }
    }

    /// Confirms the address with a strict plurality of networks, once it clears the threshold.
    fn decide(&mut self) -> Option<ConfirmedAddress> {
        // Each address counts the distinct networks that name it.
        let mut tally: BTreeMap<SocketAddrV4, BTreeSet<VoterNetwork>> = BTreeMap::new();
        for vote in self.votes.values() {
            tally.entry(vote.address).or_default().insert(vote.network);
        }
        let most = tally.values().map(BTreeSet::len).max()?;
        let mut leaders = tally
            .iter()
            .filter(|(_, networks)| networks.len() == most)
            .map(|(address, _)| *address);
        let leader = leaders.next()?;
        // Invariant: a tie decides nothing, so no ordering of addresses can pick a winner.
        if leaders.next().is_some() || most < self.config.threshold {
            return None;
        }
        if self.confirmed == Some(leader) {
            return None;
        }
        self.confirmed = Some(leader);
        Some(ConfirmedAddress {
            address: leader,
            votes: most,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use proptest::prelude::*;

    use super::*;

    /// A small rule: three networks, ten minutes, sixteen votes.
    const CONFIG: VoteConfig = VoteConfig {
        threshold: 3,
        lifetime: Duration::from_secs(600),
        capacity: 16,
    };

    /// The endpoint honest peers see.
    const HOME: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 9000);

    /// The endpoint an attacker claims.
    const FAKE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 66), 9000);

    /// Peer i, alone in the public /24 of 1.0.i.0.
    fn peer(i: u8) -> (NodeId, IpAddr) {
        (NodeId([i; 32]), IpAddr::V4(Ipv4Addr::new(1, 0, i, 1)))
    }

    /// Records peer i's vote for an endpoint at a time in seconds.
    fn vote(
        votes: &mut AddressVotes,
        seconds: u64,
        i: u8,
        observed: SocketAddrV4,
    ) -> Option<ConfirmedAddress> {
        let (node, from) = peer(i);
        votes.record(Duration::from_secs(seconds), node, from, observed.into())
    }

    #[test]
    fn the_threshold_of_distinct_networks_confirms() {
        // Threshold: 3 networks.
        let mut votes = AddressVotes::new(CONFIG);
        // Two networks agree: not enough.
        assert_eq!(vote(&mut votes, 0, 1, HOME), None);
        assert_eq!(vote(&mut votes, 1, 2, HOME), None);
        assert_eq!(votes.confirmed(), None);
        // The third confirms, reporting three votes.
        assert_eq!(
            vote(&mut votes, 2, 3, HOME),
            Some(ConfirmedAddress {
                address: HOME,
                votes: 3,
            })
        );
        // A fourth agreeing vote changes nothing, so nothing is reported.
        assert_eq!(vote(&mut votes, 3, 4, HOME), None);
        assert_eq!(votes.confirmed(), Some(HOME));
    }

    #[test]
    fn many_nodes_in_one_network_count_once() {
        // Mutation: five node identifiers, all in the public /24 of 1.0.9.0.
        let mut votes = AddressVotes::new(CONFIG);
        for i in 0..5 {
            let from = IpAddr::V4(Ipv4Addr::new(1, 0, 9, 10 + i));
            let confirmed = votes.record(Duration::ZERO, NodeId([i; 32]), from, HOME.into());
            assert_eq!(confirmed, None);
        }
        // One network is one vote, below the threshold of three.
        assert_eq!(votes.confirmed(), None);
    }

    #[test]
    fn local_hosts_count_alone() {
        // Fixture state: three test nodes on 10.0.0.1, 10.0.0.2 and 10.0.0.3, one private /24.
        let mut votes = AddressVotes::new(CONFIG);
        let mut last = None;
        for i in 1..=3 {
            let from = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            last = votes.record(Duration::ZERO, NodeId([i; 32]), from, HOME.into());
        }
        // Private hosts count individually, so three hosts make three votes.
        assert_eq!(
            last,
            Some(ConfirmedAddress {
                address: HOME,
                votes: 3,
            })
        );
    }

    #[test]
    fn a_minority_cannot_flip_the_address() {
        // Fixture state: networks 1 to 4 confirm HOME.
        let mut votes = AddressVotes::new(CONFIG);
        for i in 1..=4 {
            vote(&mut votes, 0, i, HOME);
        }
        assert_eq!(votes.confirmed(), Some(HOME));
        // Mutation: networks 11 to 13 claim FAKE; three clear the threshold but four beat them.
        for i in 11..=13 {
            assert_eq!(vote(&mut votes, 1, i, FAKE), None);
        }
        // A fourth attacker ties at four against four: a tie moves nothing.
        assert_eq!(vote(&mut votes, 2, 14, FAKE), None);
        assert_eq!(votes.confirmed(), Some(HOME));
    }

    #[test]
    fn a_peer_holds_one_vote_and_may_change_it() {
        // Fixture state: networks 1 to 3 confirm HOME.
        let mut votes = AddressVotes::new(CONFIG);
        for i in 1..=3 {
            vote(&mut votes, 0, i, HOME);
        }
        // Peer 1 votes FAKE ten times: its HOME vote is replaced, never multiplied.
        for second in 1..=10 {
            assert_eq!(vote(&mut votes, second, 1, FAKE), None);
        }
        assert_eq!(votes.confirmed(), Some(HOME));
    }

    #[test]
    fn the_address_moves_when_a_new_majority_forms() {
        // Fixture state: networks 1 to 3 confirm HOME at time 0.
        let moved = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 8), 9000);
        let mut votes = AddressVotes::new(CONFIG);
        for i in 1..=3 {
            vote(&mut votes, 0, i, HOME);
        }
        // The provider renumbers the node; peers 1 to 3 vote again and peer 4 joins.
        assert_eq!(vote(&mut votes, 10, 1, moved), None);
        assert_eq!(vote(&mut votes, 11, 2, moved), None);
        // Two against one is a plurality but below the threshold of three.
        assert_eq!(votes.confirmed(), Some(HOME));
        assert_eq!(
            vote(&mut votes, 12, 3, moved),
            Some(ConfirmedAddress {
                address: moved,
                votes: 3,
            })
        );
    }

    #[test]
    fn votes_expire_after_their_lifetime() {
        // Lifetime: 600 s.
        let mut votes = AddressVotes::new(CONFIG);
        vote(&mut votes, 0, 1, HOME);
        vote(&mut votes, 0, 2, HOME);
        // At 600 s the first two votes lapse, so the third finds itself alone.
        assert_eq!(vote(&mut votes, 600, 3, HOME), None);
        assert_eq!(votes.confirmed(), None);
        // At 599 s they would still have counted.
        let mut votes = AddressVotes::new(CONFIG);
        vote(&mut votes, 0, 1, HOME);
        vote(&mut votes, 0, 2, HOME);
        assert_eq!(
            vote(&mut votes, 599, 3, HOME),
            Some(ConfirmedAddress {
                address: HOME,
                votes: 3,
            })
        );
    }

    #[test]
    fn the_confirmed_address_outlives_its_votes() {
        // Fixture state: HOME confirmed at time 0.
        let mut votes = AddressVotes::new(CONFIG);
        for i in 1..=3 {
            vote(&mut votes, 0, i, HOME);
        }
        // An hour later every vote has lapsed; one attacker alone cannot take over.
        assert_eq!(vote(&mut votes, 3600, 20, FAKE), None);
        assert_eq!(votes.confirmed(), Some(HOME));
    }

    #[test]
    fn capacity_drops_the_oldest_vote() {
        // Capacity: 3 votes, threshold 3.
        let mut votes = AddressVotes::new(VoteConfig {
            capacity: 3,
            ..CONFIG
        });
        vote(&mut votes, 0, 1, FAKE);
        vote(&mut votes, 1, 2, HOME);
        vote(&mut votes, 2, 3, HOME);
        // The fourth vote pushes out peer 1's, the oldest; three HOME votes remain.
        assert_eq!(
            vote(&mut votes, 3, 4, HOME),
            Some(ConfirmedAddress {
                address: HOME,
                votes: 3,
            })
        );
    }

    #[test]
    fn impossible_endpoints_are_ignored() {
        // Port zero, the unspecified address, multicast, broadcast, and IPv6 never count.
        let mut votes = AddressVotes::new(VoteConfig {
            threshold: 1,
            ..CONFIG
        });
        let bad: [SocketAddr; 5] = [
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 0).into(),
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 9000).into(),
            SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 9000).into(),
            SocketAddrV4::new(Ipv4Addr::BROADCAST, 9000).into(),
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 9000),
        ];
        let (node, from) = peer(1);
        for observed in bad {
            assert_eq!(votes.record(Duration::ZERO, node, from, observed), None);
        }
        assert_eq!(votes.confirmed(), None);
    }

    proptest! {
        #[test]
        fn honest_majorities_win_whatever_the_order(
            honest in 3_u8..20,
            extra in 0_u8..20,
            seed in any::<u64>(),
        ) {
            // Law: with more honest networks than attacking ones, any interleaving confirms HOME.
            let attackers = honest.saturating_sub(1).min(extra);
            let mut ballots: Vec<(u8, SocketAddrV4)> = (1..=honest)
                .map(|i| (i, HOME))
                .chain((100..100 + attackers).map(|i| (i, FAKE)))
                .collect();
            // A seeded shuffle: the outcome must not depend on arrival order.
            let mut state = seed;
            for i in (1..ballots.len()).rev() {
                state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let j = usize::try_from(state >> 33).unwrap_or(0) % (i + 1);
                ballots.swap(i, j);
            }
            let mut votes = AddressVotes::new(VoteConfig {
                capacity: 64,
                ..CONFIG
            });
            for (i, address) in ballots {
                vote(&mut votes, 0, i, address);
            }
            prop_assert_eq!(votes.confirmed(), Some(HOME));
        }

        #[test]
        fn equal_inputs_give_equal_outputs(
            ballots in proptest::collection::vec((1_u8..30, any::<bool>(), 0_u64..2000), 0..60),
        ) {
            // Law: the decision is a pure function of the inputs.
            let mut first = AddressVotes::new(CONFIG);
            let mut second = AddressVotes::new(CONFIG);
            let mut time = 0;
            for (i, honest, step) in ballots {
                time += step;
                let address = if honest { HOME } else { FAKE };
                let a = vote(&mut first, time, i, address);
                let b = vote(&mut second, time, i, address);
                prop_assert_eq!(a, b);
            }
            prop_assert_eq!(first.confirmed(), second.confirmed());
        }
    }
}
