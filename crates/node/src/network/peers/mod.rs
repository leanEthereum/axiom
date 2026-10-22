//! Peer management: how many peers, which ones, and which to drop.
//!
//! # Overview
//!
//! The manager is a pure state machine: connections, faults and time go in, decisions come out.
//!
//! It keeps the peer count near a target:
//!
//! - It dials while below the target, and refuses inbound peers past a hard maximum.
//! - A share of the slots is kept for outbound peers.
//!   An attacker can flood inbound connections, but it cannot choose whom this node dials.
//! - Each address may hold only a few peers, so one host cannot fill the table with identities.
//! - Faults lower a decaying score; a low score disconnects, a very low one bans.
//! - An address that produced several banned identities is banned too.
//! - Each peer is pinged regularly; a higher metadata sequence number prompts a metadata request.
//!
//! It keeps every subnet the node needs served:
//!
//! - It asks discovery for peers on subnets with too few of them.
//! - When pruning above the target, it never drops a peer a subnet depends on.
//!
//! The decisions protect liveness: an eclipsed or starved node cannot follow the chain.
//! None of them affects safety, which rests on signatures and fork choice alone.

mod metrics;
mod score;
mod subnets;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
    time::Duration,
};

use axiom_p2p::{Multiaddr, PeerId, Protocol as Layer, eth::reqresp::GoodbyeReason};
pub(crate) use metrics::PeerMetrics;
pub(crate) use score::PeerAction;
use score::{PeerScore, Standing};
pub(crate) use subnets::{PeerSubnets, Subnet};

/// Goodbye reasons in the client-specific range above 128, per the phase0 p2p spec.
pub(crate) mod goodbye {
    use axiom_p2p::eth::reqresp::GoodbyeReason;

    /// The node has too many peers.
    pub(crate) const TOO_MANY_PEERS: GoodbyeReason = GoodbyeReason(129);
    /// The peer's score fell below the disconnect threshold.
    pub(crate) const BAD_SCORE: GoodbyeReason = GoodbyeReason(250);
    /// The peer is banned.
    pub(crate) const BANNED: GoodbyeReason = GoodbyeReason(251);
}

/// Disconnected peers remembered, so a peer cannot reconnect to clear its record.
///
/// Threshold: beyond this, the peers already forgiven are forgotten.
const REMEMBERED_PEERS: usize = 1500;

/// Banned identities from one address beyond which the address itself is banned.
///
/// Adversary: identities are free, addresses are not.
/// A few honest nodes may share a NAT, but more than five banned identities do not happen by chance.
const BANNED_PEERS_PER_IP: usize = 5;

/// The share of the target whose negative gossip scores are ignored, the best of them first.
///
/// They may recover in the mesh instead of being dropped for a transient gossip penalty.
const IGNORED_NEGATIVE_GOSSIP_PERCENT: usize = 10;

/// How often an outbound peer is pinged.
const PING_OUTBOUND: Duration = Duration::from_secs(15);

/// How often an inbound peer is pinged.
const PING_INBOUND: Duration = Duration::from_secs(20);

/// The node's targets for its peer set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PeerLimits {
    /// Peers the node aims for.
    pub(crate) target: usize,
    /// Peers past the target the node still accepts, before refusing everyone.
    pub(crate) excess: usize,
    /// Peers kept outbound, as a share of the target in percent.
    pub(crate) outbound_percent: usize,
    /// Peers one address may hold.
    pub(crate) per_ip: usize,
    /// Peers the node wants on each subnet it needs.
    pub(crate) per_subnet: usize,
}

impl Default for PeerLimits {
    fn default() -> Self {
        Self {
            // A mesh wants 6 to 12 peers per topic, per the phase0 gossipsub parameters.
            // Sixty-four peers fill every topic's mesh and leave spares.
            target: 64,
            // Threshold: ten percent of headroom lets new peers in while the worst are pruned.
            excess: 6,
            // Threshold: a fifth of the slots stay out of an inbound flooder's reach.
            outbound_percent: 20,
            // Threshold: a few honest nodes may share a NAT; more from one host is a Sybil.
            per_ip: 5,
            // Threshold: two peers per subnet survive one leaving.
            per_subnet: 2,
        }
    }
}

impl PeerLimits {
    /// The most peers accepted.
    const fn max(&self) -> usize {
        self.target + self.excess
    }

    /// Outbound peers the node keeps at least.
    const fn min_outbound(&self) -> usize {
        (self.target * self.outbound_percent).div_ceil(100)
    }
}

/// A connected peer.
#[derive(Clone, Debug)]
struct Peer {
    /// Whether this node dialed.
    outbound: bool,
    /// The address's IP, for colocation limits.
    ip: Option<IpAddr>,
    /// Whether the connection runs over QUIC.
    quic: bool,
    /// The peer's standing.
    score: PeerScore,
    /// The subnets the peer serves, once its metadata arrived.
    subnets: Option<PeerSubnets>,
    /// When the peer was last pinged.
    pinged: Duration,
    /// Whether a goodbye is on its way, so the peer is no longer counted on.
    leaving: bool,
}

/// A peer that left, remembered for its score.
#[derive(Clone, Copy, Debug)]
struct PastPeer {
    /// The score it left with.
    score: PeerScore,
    /// The address's IP, for address bans.
    ip: Option<IpAddr>,
}

/// What the upkeep decided.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Upkeep {
    /// Peers to drop, with the reason to tell them.
    pub(crate) disconnect: Vec<(PeerId, GoodbyeReason)>,
    /// New outbound peers wanted.
    pub(crate) dials: usize,
    /// Subnets with too few peers, most starved first.
    pub(crate) starved: Vec<Subnet>,
    /// Peers due for a ping.
    pub(crate) pings: Vec<PeerId>,
}

/// Connected peers and the rules that shape the set.
#[derive(Debug)]
pub(crate) struct PeerManager {
    /// The targets.
    limits: PeerLimits,
    /// Connected peers.
    peers: BTreeMap<PeerId, Peer>,
    /// Peers that left with a score not yet forgiven.
    past: HashMap<PeerId, PastPeer>,
}

impl PeerManager {
    /// No peers yet.
    pub(crate) fn new(limits: PeerLimits) -> Self {
        Self {
            limits,
            peers: BTreeMap::new(),
            past: HashMap::new(),
        }
    }

    /// Connected peers.
    pub(crate) fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether a peer is connected and counted.
    pub(crate) fn contains(&self, peer: &PeerId) -> bool {
        self.peers.get(peer).is_some_and(|peer| !peer.leaving)
    }

    /// Connected peers, for status refreshes.
    pub(crate) fn connected(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, peer)| !peer.leaving)
            .map(|(id, _)| id)
    }

    /// The IP of an address, if its first layer names one.
    fn ip_of(address: &Multiaddr) -> Option<IpAddr> {
        match address.protocols().first() {
            Some(Layer::Ip4(ip)) => Some((*ip).into()),
            Some(Layer::Ip6(ip)) => Some((*ip).into()),
            _ => None,
        }
    }

    /// Whether a peer is banned: its score is at or below the ban threshold.
    fn is_banned(&self, peer: &PeerId, now: Duration) -> bool {
        let score = self
            .peers
            .get(peer)
            .map(|known| known.score)
            .or_else(|| self.past.get(peer).map(|past| past.score));
        score.is_some_and(|score| score.standing(now) == Standing::Ban)
    }

    /// Whether an address is banned: more than five banned identities came from it.
    fn is_ip_banned(&self, ip: IpAddr, now: Duration) -> bool {
        let connected = self
            .peers
            .values()
            .filter(|peer| peer.ip == Some(ip) && peer.score.standing(now) == Standing::Ban);
        let past = self
            .past
            .values()
            .filter(|peer| peer.ip == Some(ip) && peer.score.standing(now) == Standing::Ban);
        connected.count() + past.count() > BANNED_PEERS_PER_IP
    }

    /// Whether a dial is allowed: neither the peer nor its address is banned.
    pub(crate) fn may_dial(&self, peer: &PeerId, address: &Multiaddr, now: Duration) -> bool {
        !self.is_banned(peer, now)
            && Self::ip_of(address).is_none_or(|ip| !self.is_ip_banned(ip, now))
    }

    /// Admits a new connection, or says why it must close.
    ///
    /// # Errors
    ///
    /// Returns the goodbye reason when the peer is banned, its address is full, or the node is full.
    pub(crate) fn on_connected(
        &mut self,
        peer: &PeerId,
        address: &Multiaddr,
        outbound: bool,
        now: Duration,
    ) -> Result<(), GoodbyeReason> {
        let ip = Self::ip_of(address);
        if self.is_banned(peer, now) || ip.is_some_and(|ip| self.is_ip_banned(ip, now)) {
            return Err(goodbye::BANNED);
        }
        if let Some(ip) = ip
            && self
                .peers
                .values()
                .filter(|known| known.ip == Some(ip))
                .count()
                >= self.limits.per_ip
        {
            return Err(goodbye::TOO_MANY_PEERS);
        }
        let inbound = self.peers.values().filter(|known| !known.outbound).count();
        // Inbound peers never take the slots kept for outbound ones.
        if !outbound && inbound >= self.limits.max() - self.limits.min_outbound() {
            return Err(goodbye::TOO_MANY_PEERS);
        }
        if self.peers.len() >= self.limits.max() {
            return Err(goodbye::TOO_MANY_PEERS);
        }
        // A returning peer resumes its old score, so reconnecting does not wash it clean.
        let score = self
            .past
            .remove(peer)
            .map_or_else(|| PeerScore::new(now), |past| past.score);
        if score.standing(now) != Standing::Good {
            return Err(goodbye::BAD_SCORE);
        }
        let quic = address.protocols().contains(&Layer::QuicV1);
        self.peers.insert(
            peer.clone(),
            Peer {
                outbound,
                ip,
                quic,
                score,
                subnets: None,
                pinged: now,
                leaving: false,
            },
        );
        Ok(())
    }

    /// Forgets a peer that disconnected, remembering its score.
    pub(crate) fn on_disconnected(&mut self, peer: &PeerId, now: Duration) {
        let Some(gone) = self.peers.remove(peer) else {
            return;
        };
        if !gone.score.is_forgiven(now) {
            if self.past.len() >= REMEMBERED_PEERS {
                self.past.retain(|_, past| !past.score.is_forgiven(now));
            }
            self.past.insert(
                peer.clone(),
                PastPeer {
                    score: gone.score,
                    ip: gone.ip,
                },
            );
        }
    }

    /// Records a fault.
    ///
    /// # Returns
    ///
    /// The goodbye to send when the fault pushed the peer out.
    pub(crate) fn report(
        &mut self,
        peer: &PeerId,
        action: PeerAction,
        now: Duration,
    ) -> Option<GoodbyeReason> {
        let known = self.peers.get_mut(peer)?;
        if known.leaving {
            return None;
        }
        let reason = match known.score.apply(action, now) {
            Standing::Good => return None,
            Standing::Disconnect => goodbye::BAD_SCORE,
            Standing::Ban => goodbye::BANNED,
        };
        known.leaving = true;
        Some(reason)
    }

    /// Records the subnets a peer's metadata states.
    pub(crate) fn set_subnets(&mut self, peer: &PeerId, subnets: PeerSubnets) {
        if let Some(known) = self.peers.get_mut(peer) {
            known.subnets = Some(subnets);
        }
    }

    /// Takes the gossipsub router's scores of connected peers.
    ///
    /// # Returns
    ///
    /// The goodbyes for peers the combined score pushed out.
    pub(crate) fn update_gossip_scores(
        &mut self,
        mut scores: Vec<(PeerId, f64)>,
        now: Duration,
    ) -> Vec<(PeerId, GoodbyeReason)> {
        // The best scores first, so the leniency goes to the peers closest to recovering.
        scores.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        let mut lenient = (self.limits.target * IGNORED_NEGATIVE_GOSSIP_PERCENT).div_ceil(100);
        let mut goodbyes = Vec::new();
        for (id, gossip) in scores {
            let Some(peer) = self.peers.get_mut(&id) else {
                continue;
            };
            let ignore = gossip < 0.0 && lenient > 0;
            if ignore {
                lenient -= 1;
            }
            let standing = peer.score.set_gossip(gossip, ignore, now);
            if peer.leaving {
                continue;
            }
            let reason = match standing {
                Standing::Good => continue,
                Standing::Disconnect => goodbye::BAD_SCORE,
                Standing::Ban => goodbye::BANNED,
            };
            peer.leaving = true;
            goodbyes.push((id, reason));
        }
        goodbyes
    }

    /// Takes a ping answer, returning whether the peer's metadata changed and must be fetched.
    pub(crate) fn on_pong(&self, peer: &PeerId, seq_number: u64) -> bool {
        self.peers.get(peer).is_some_and(|known| {
            known
                .subnets
                .as_ref()
                .is_none_or(|subnets| seq_number > subnets.seq_number)
        })
    }

    /// Peers serving a subnet.
    fn providers(&self, subnet: Subnet) -> usize {
        self.peers
            .values()
            .filter(|peer| {
                !peer.leaving
                    && peer
                        .subnets
                        .as_ref()
                        .is_some_and(|known| known.covers(subnet))
            })
            .count()
    }

    /// The periodic decisions: prune past the target, dial below it, seek starved subnets.
    ///
    /// # Arguments
    ///
    /// - `needed`: the subnets the node subscribes to.
    pub(crate) fn upkeep(&mut self, needed: &BTreeSet<Subnet>, now: Duration) -> Upkeep {
        self.past.retain(|_, past| !past.score.is_forgiven(now));
        let mut upkeep = Upkeep::default();

        // Subnets below their share of peers, the emptiest first.
        let mut starved: Vec<(usize, Subnet)> = needed
            .iter()
            .map(|subnet| (self.providers(*subnet), *subnet))
            .filter(|(count, _)| *count < self.limits.per_subnet)
            .collect();
        starved.sort_unstable();
        upkeep.starved = starved.into_iter().map(|(_, subnet)| subnet).collect();

        self.prune(needed, now, &mut upkeep);

        let counted: Vec<&Peer> = self.peers.values().filter(|peer| !peer.leaving).collect();
        let outbound = counted.iter().filter(|peer| peer.outbound).count();
        let below_target = self.limits.target.saturating_sub(counted.len());
        let outbound_deficit = self.limits.min_outbound().saturating_sub(outbound);
        upkeep.dials = below_target.max(outbound_deficit);
        // Pings carry the metadata sequence number, so changed metadata is noticed within seconds.
        for (id, peer) in &mut self.peers {
            let interval = if peer.outbound {
                PING_OUTBOUND
            } else {
                PING_INBOUND
            };
            if !peer.leaving && now.saturating_sub(peer.pinged) >= interval {
                peer.pinged = now;
                upkeep.pings.push(id.clone());
            }
        }
        upkeep
    }

    /// Picks peers to drop past the target, sparing those the subnets and the outbound share need.
    ///
    /// Inbound peers go first, then the lowest scores.
    fn prune(&mut self, needed: &BTreeSet<Subnet>, now: Duration, upkeep: &mut Upkeep) {
        let counted = self.peers.values().filter(|peer| !peer.leaving).count();
        let mut excess = counted.saturating_sub(self.limits.target);
        if excess == 0 {
            return;
        }
        // A peer is protected while a subnet it serves has no more than the wanted count.
        let protected: BTreeSet<PeerId> = needed
            .iter()
            .filter(|subnet| self.providers(**subnet) <= self.limits.per_subnet)
            .flat_map(|subnet| {
                self.peers
                    .iter()
                    .filter(move |(_, peer)| {
                        peer.subnets
                            .as_ref()
                            .is_some_and(|known| known.covers(*subnet))
                    })
                    .map(|(id, _)| id.clone())
            })
            .collect();
        let mut outbound = self
            .peers
            .values()
            .filter(|peer| !peer.leaving && peer.outbound)
            .count();
        let mut candidates: Vec<(bool, f64, PeerId)> = self
            .peers
            .iter()
            .filter(|(id, peer)| !peer.leaving && !protected.contains(*id))
            .map(|(id, peer)| (peer.outbound, peer.score.at(now), id.clone()))
            .collect();
        // Inbound before outbound, then the lowest score first; ties fall to the identifier order.
        candidates.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)).then(a.2.cmp(&b.2)));
        for (is_outbound, _, id) in candidates {
            if excess == 0 {
                break;
            }
            if is_outbound && outbound <= self.limits.min_outbound() {
                continue;
            }
            if let Some(peer) = self.peers.get_mut(&id) {
                peer.leaving = true;
            }
            if is_outbound {
                outbound -= 1;
            }
            excess -= 1;
            upkeep.disconnect.push((id, goodbye::TOO_MANY_PEERS));
        }
    }

    /// Counts for the metrics: inbound, outbound, QUIC and TCP peers, and active bans.
    pub(crate) fn census(&self, now: Duration) -> Census {
        let mut census = Census {
            banned: self
                .past
                .values()
                .filter(|past| past.score.standing(now) == Standing::Ban)
                .count(),
            ..Census::default()
        };
        for peer in self.peers.values() {
            if peer.outbound {
                census.outbound += 1;
            } else {
                census.inbound += 1;
            }
            if peer.quic {
                census.quic += 1;
            } else {
                census.tcp += 1;
            }
        }
        census
    }

    /// Peers serving each subnet, for the metrics.
    pub(crate) fn subnet_peers<'a>(
        &'a self,
        needed: &'a BTreeSet<Subnet>,
    ) -> impl Iterator<Item = (Subnet, usize)> + 'a {
        needed
            .iter()
            .map(|subnet| (*subnet, self.providers(*subnet)))
    }
}

/// Peer counts by kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Census {
    /// Peers that dialed this node.
    pub(crate) inbound: usize,
    /// Peers this node dialed.
    pub(crate) outbound: usize,
    /// Peers over QUIC.
    pub(crate) quic: usize,
    /// Peers over TCP.
    pub(crate) tcp: usize,
    /// Peers banned now.
    pub(crate) banned: usize,
}

#[cfg(test)]
mod tests {
    use axiom_p2p::{
        Keypair,
        eth::reqresp::{Attnets, MetaData},
    };
    use axiom_ssz::Ssz;
    use axiom_types::{ChainConfig, Mainnet};

    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    /// Four peers to aim for, one more accepted, a quarter outbound, two per address and subnet.
    const LIMITS: PeerLimits = PeerLimits {
        target: 4,
        excess: 1,
        outbound_percent: 25,
        per_ip: 2,
        per_subnet: 2,
    };

    fn peer(seed: u8) -> PeerId {
        Keypair::from_secret_bytes(&[seed; 32]).unwrap().peer_id()
    }

    /// A TCP address on host 10.0.0.x.
    fn address(host: u8) -> Multiaddr {
        Multiaddr::from_tcp(([10, 0, 0, host], 9000).into())
    }

    /// Subnets of a peer serving the given attestation subnets.
    fn serving(peer: &PeerId, subnets: &[usize]) -> PeerSubnets {
        let mut attnets = Attnets::default();
        for subnet in subnets {
            attnets.set(*subnet, true);
        }
        let metadata = MetaData {
            seq_number: 1,
            attnets,
            custody_group_count: 4,
            ..MetaData::default()
        };
        PeerSubnets::from_metadata::<Mainnet>(peer, &metadata.encode(), &ChainConfig::mainnet())
            .unwrap()
    }

    #[test]
    fn admission_limits() {
        let mut peers = PeerManager::new(LIMITS);
        let now = Duration::ZERO;
        // Two peers from host 1 fit; the third is one host too many.
        assert_eq!(
            peers.on_connected(&peer(1), &address(1), false, now),
            Ok(())
        );
        assert_eq!(
            peers.on_connected(&peer(2), &address(1), false, now),
            Ok(())
        );
        assert_eq!(
            peers.on_connected(&peer(3), &address(1), false, now),
            Err(goodbye::TOO_MANY_PEERS)
        );
        // Inbound fills up to 5 - 1 = 4 slots, keeping one for an outbound peer.
        assert_eq!(
            peers.on_connected(&peer(4), &address(2), false, now),
            Ok(())
        );
        assert_eq!(
            peers.on_connected(&peer(5), &address(3), false, now),
            Ok(())
        );
        assert_eq!(
            peers.on_connected(&peer(6), &address(4), false, now),
            Err(goodbye::TOO_MANY_PEERS)
        );
        // The kept slot takes an outbound peer; then the node is full for everyone.
        assert_eq!(peers.on_connected(&peer(7), &address(5), true, now), Ok(()));
        assert_eq!(
            peers.on_connected(&peer(8), &address(6), true, now),
            Err(goodbye::TOO_MANY_PEERS)
        );
        assert_eq!(peers.len(), 5);
        assert_eq!(
            peers.census(now),
            Census {
                inbound: 4,
                outbound: 1,
                quic: 0,
                tcp: 5,
                banned: 0,
            }
        );
    }

    #[test]
    fn faults_disconnect_then_ban_and_scores_survive_reconnection() {
        let mut peers = PeerManager::new(LIMITS);
        let alice = peer(1);
        peers
            .on_connected(&alice, &address(1), true, Duration::ZERO)
            .unwrap();
        // Two low-tolerance faults reach -20: disconnect.
        assert_eq!(
            peers.report(&alice, PeerAction::LowTolerance, Duration::ZERO),
            None
        );
        assert_eq!(
            peers.report(&alice, PeerAction::LowTolerance, Duration::ZERO),
            Some(goodbye::BAD_SCORE)
        );
        // The leaving peer is no longer counted on, and further faults are moot.
        assert!(!peers.contains(&alice));
        assert_eq!(
            peers.report(&alice, PeerAction::Fatal, Duration::ZERO),
            None
        );
        peers.on_disconnected(&alice, Duration::ZERO);

        // Reconnecting at once finds the score still at the threshold.
        assert_eq!(
            peers.on_connected(&alice, &address(1), true, Duration::ZERO),
            Err(goodbye::BAD_SCORE)
        );
        // Ten minutes on, the score has halved: the peer is welcome again.
        assert_eq!(
            peers.on_connected(&alice, &address(1), true, 11 * MINUTE),
            Ok(())
        );

        // A fatal fault bans: the peer and dials to it are refused for twelve hours and more.
        assert_eq!(
            peers.report(&alice, PeerAction::Fatal, 11 * MINUTE),
            Some(goodbye::BANNED)
        );
        peers.on_disconnected(&alice, 11 * MINUTE);
        assert!(!peers.may_dial(&alice, &address(1), 12 * MINUTE));
        assert_eq!(
            peers.on_connected(&alice, &address(1), true, 12 * MINUTE),
            Err(goodbye::BANNED)
        );
        assert_eq!(peers.census(12 * MINUTE).banned, 1);
    }

    #[test]
    fn upkeep_dials_below_target_and_names_starved_subnets() {
        let mut peers = PeerManager::new(LIMITS);
        let now = Duration::ZERO;
        let needed: BTreeSet<Subnet> = [Subnet::Attestation(0), Subnet::Attestation(1)].into();
        // Two inbound peers, one serving subnet 1, the other without metadata yet.
        peers
            .on_connected(&peer(1), &address(1), false, now)
            .unwrap();
        peers
            .on_connected(&peer(2), &address(2), false, now)
            .unwrap();
        peers.set_subnets(&peer(1), serving(&peer(1), &[1]));
        let upkeep = peers.upkeep(&needed, now);
        assert_eq!(
            upkeep,
            Upkeep {
                disconnect: Vec::new(),
                // Two short of four.
                dials: 2,
                // Subnet 0 has no peer, subnet 1 one: the emptiest first.
                starved: vec![Subnet::Attestation(0), Subnet::Attestation(1)],
                // Both were pinged in effect on connection.
                pings: Vec::new(),
            }
        );
    }

    #[test]
    fn pings_are_due_every_15_or_20_seconds_and_reveal_new_metadata() {
        let mut peers = PeerManager::new(LIMITS);
        let needed = BTreeSet::new();
        peers
            .on_connected(&peer(1), &address(1), true, Duration::ZERO)
            .unwrap();
        peers
            .on_connected(&peer(2), &address(2), false, Duration::ZERO)
            .unwrap();
        // At 15 s the outbound peer is due, at 20 s the inbound one; each once.
        assert_eq!(
            peers.upkeep(&needed, Duration::from_secs(15)).pings,
            vec![peer(1)]
        );
        assert_eq!(
            peers.upkeep(&needed, Duration::from_secs(20)).pings,
            vec![peer(2)]
        );
        assert_eq!(
            peers.upkeep(&needed, Duration::from_secs(21)).pings,
            Vec::<PeerId>::new()
        );

        // Without metadata any pong asks for it; with sequence 1 known, only a higher one does.
        assert!(peers.on_pong(&peer(1), 0));
        peers.set_subnets(&peer(1), serving(&peer(1), &[]));
        assert!(!peers.on_pong(&peer(1), 1));
        assert!(peers.on_pong(&peer(1), 2));
        assert!(!peers.on_pong(&peer(9), 2));
    }

    #[test]
    fn an_address_with_more_than_five_banned_peers_is_banned() {
        let mut peers = PeerManager::new(PeerLimits {
            per_ip: 10,
            target: 20,
            ..LIMITS
        });
        let now = Duration::ZERO;
        let host = address(7);
        // Five banned identities from one host leave it welcome.
        for seed in 1..=5 {
            peers.on_connected(&peer(seed), &host, false, now).unwrap();
            peers.report(&peer(seed), PeerAction::Fatal, now);
            peers.on_disconnected(&peer(seed), now);
        }
        assert!(peers.may_dial(&peer(20), &host, now));
        // The sixth bans the address, for any identity.
        peers.on_connected(&peer(6), &host, false, now).unwrap();
        peers.report(&peer(6), PeerAction::Fatal, now);
        assert!(!peers.may_dial(&peer(20), &host, now));
        assert_eq!(
            peers.on_connected(&peer(21), &host, true, now),
            Err(goodbye::BANNED)
        );
    }

    #[test]
    fn gossip_scores_are_lenient_with_the_best_negative_peers() {
        // A target of 10 forgives one negative gossip score.
        let mut peers = PeerManager::new(PeerLimits {
            target: 10,
            ..LIMITS
        });
        let now = Duration::ZERO;
        for seed in 1..=2 {
            peers
                .on_connected(&peer(seed), &address(seed), true, now)
                .unwrap();
            // A mid-tolerance fault each: -5 locally.
            peers.report(&peer(seed), PeerAction::MidTolerance, now);
        }
        // Both graylisted: -19 each from gossip. The better one is forgiven, the worse drops.
        let goodbyes =
            peers.update_gossip_scores(vec![(peer(1), -16_000.0), (peer(2), -16_001.0)], now);
        assert_eq!(goodbyes, vec![(peer(2), goodbye::BAD_SCORE)]);
        assert!(peers.contains(&peer(1)));
    }

    #[test]
    fn outbound_deficit_asks_for_dials_at_the_target() {
        let mut peers = PeerManager::new(LIMITS);
        let now = Duration::ZERO;
        for seed in 1..=4 {
            peers
                .on_connected(&peer(seed), &address(seed), false, now)
                .unwrap();
        }
        // Four inbound peers meet the target, but the outbound share of one is missing.
        assert_eq!(peers.upkeep(&BTreeSet::new(), now).dials, 1);
    }

    #[test]
    fn pruning_spares_subnet_providers_and_the_outbound_share() {
        let mut peers = PeerManager::new(LIMITS);
        let now = Duration::ZERO;
        let needed: BTreeSet<Subnet> = [Subnet::Attestation(7)].into();
        // Five peers, one over the target of four: two outbound, three inbound.
        peers
            .on_connected(&peer(1), &address(1), true, now)
            .unwrap();
        peers
            .on_connected(&peer(2), &address(2), true, now)
            .unwrap();
        for seed in 3..=5 {
            peers
                .on_connected(&peer(seed), &address(seed), false, now)
                .unwrap();
            peers.set_subnets(&peer(seed), serving(&peer(seed), &[]));
        }
        peers.set_subnets(&peer(1), serving(&peer(1), &[7]));
        peers.set_subnets(&peer(2), serving(&peer(2), &[]));
        // Inbound peer 3 serves subnet 7 too; with two providers both are protected.
        peers.set_subnets(&peer(3), serving(&peer(3), &[7]));
        // Peer 3 has the worst score, but the subnet needs it; peer 4 is next worst.
        peers.report(&peer(3), PeerAction::MidTolerance, now);
        peers.report(&peer(4), PeerAction::HighTolerance, now);
        let upkeep = peers.upkeep(&needed, now);
        assert_eq!(upkeep.disconnect, vec![(peer(4), goodbye::TOO_MANY_PEERS)]);
        assert_eq!(upkeep.starved, Vec::<Subnet>::new());
        assert_eq!(peers.connected().count(), 4);
    }
}
