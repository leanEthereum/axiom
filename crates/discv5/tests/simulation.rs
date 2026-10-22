//! A deterministic simulation: 50 nodes bootstrap from one boot node over an in-memory network.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap},
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use axiom_crypto::secp256k1::SecretKey;
use axiom_discv5::{
    Enr, LogDistance, NodeId,
    enr::Attnets,
    service::{Config, EnrFilter, Event, LookupId, Output, Service},
};

/// Nodes in the network, the boot node included.
const NODES: usize = 50;

/// The subnet every fifth node advertises.
const SUBNET: usize = 5;

/// A tiny seeded generator for latencies, so the schedule replays exactly.
struct SplitMix(u64);

impl SplitMix {
    /// The next 64 random bits.
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// A datagram in transit.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Delivery {
    /// Arrival time.
    at: Duration,
    /// Tie-breaker that keeps the order total and stable.
    sequence: u64,
    /// The sender's endpoint.
    from: SocketAddr,
    /// The recipient's index.
    to: usize,
    /// The packet.
    bytes: Vec<u8>,
}

/// The network: nodes, a virtual clock, and datagrams in transit.
struct Network {
    /// The services, by index.
    nodes: Vec<Service>,
    /// Each node's endpoint, by index.
    addrs: Vec<SocketAddr>,
    /// Index of each endpoint.
    index: BTreeMap<SocketAddr, usize>,
    /// Datagrams in transit, earliest first.
    in_transit: BinaryHeap<Reverse<Delivery>>,
    /// The virtual clock.
    now: Duration,
    /// Latency source.
    rng: SplitMix,
    /// Deliveries so far, for the tie-breaker.
    sequence: u64,
    /// Finished lookups, by node and lookup id.
    lookups: BTreeMap<(usize, LookupId), Vec<Enr>>,
    /// Datagrams delivered.
    delivered: u64,
}

impl Network {
    /// Builds the nodes: node i listens on 10.0.i.1:9000, and every fifth serves the subnet.
    fn new() -> Self {
        let mut nodes = Vec::with_capacity(NODES);
        let mut addrs = Vec::with_capacity(NODES);
        for i in 0..NODES {
            let mut secret = [0x11; 32];
            secret[0] = u8::try_from(i + 1).expect("fits");
            let key = SecretKey::from_bytes(&secret).expect("valid key");
            let ip = Ipv4Addr::new(10, 0, u8::try_from(i).expect("fits"), 1);
            let mut builder = Enr::builder().ip4(ip).udp4(9000);
            if i % 5 == 0 {
                let mut attnets = Attnets::new();
                attnets.set(SUBNET, true);
                builder = builder.attnets(&attnets);
            }
            let enr = builder.build(&key).expect("record fits");
            let mut seed = [0; 32];
            seed[0] = u8::try_from(i).expect("fits");
            // Timing: a refresh lookup every 5 s, so late joiners spread within the run.
            let config = Config {
                refresh_interval: Duration::from_secs(5),
                ..Config::default()
            };
            nodes.push(Service::new(key, enr, config, seed).expect("key matches"));
            addrs.push(SocketAddr::from((ip, 9000)));
        }
        let index = addrs.iter().enumerate().map(|(i, a)| (*a, i)).collect();
        Self {
            nodes,
            addrs,
            index,
            in_transit: BinaryHeap::new(),
            now: Duration::ZERO,
            rng: SplitMix(42),
            sequence: 0,
            lookups: BTreeMap::new(),
            delivered: 0,
        }
    }

    /// Collects a node's outputs: datagrams go in transit, lookup results are kept.
    fn drain(&mut self, node: usize) {
        while let Some(output) = self.nodes[node].poll_output() {
            match output {
                Output::Send(datagram) => {
                    // Latency: 5 to 44 ms, drawn per datagram.
                    let latency = Duration::from_millis(5 + self.rng.next() % 40);
                    if let Some(&to) = self.index.get(&datagram.to) {
                        self.sequence += 1;
                        self.in_transit.push(Reverse(Delivery {
                            at: self.now + latency,
                            sequence: self.sequence,
                            from: self.addrs[node],
                            to,
                            bytes: datagram.bytes,
                        }));
                    }
                }
                Output::Event(Event::LookupFinished { id, peers, .. }) => {
                    self.lookups.insert((node, id), peers);
                }
                Output::Event(_) => {}
            }
        }
    }

    /// Runs until the clock reaches a time, interleaving deliveries and timers in order.
    fn run_until(&mut self, end: Duration) {
        loop {
            // The next thing to happen: the earliest delivery or the earliest timer.
            let delivery = self.in_transit.peek().map(|Reverse(d)| d.at);
            let timer = (0..NODES)
                .filter_map(|i| self.nodes[i].next_deadline().map(|at| (at, i)))
                .min();
            let next = match (delivery, timer) {
                (Some(d), Some((t, _))) => d.min(t),
                (Some(d), None) => d,
                (None, Some((t, _))) => t,
                (None, None) => end,
            };
            if next > end {
                self.now = end;
                return;
            }
            self.now = self.now.max(next);
            if delivery == Some(next) {
                let Reverse(datagram) = self.in_transit.pop().expect("peeked");
                self.delivered += 1;
                self.nodes[datagram.to].handle_datagram(self.now, datagram.from, &datagram.bytes);
                self.drain(datagram.to);
            } else if let Some((_, node)) = timer {
                self.nodes[node].handle_timeout(self.now);
                self.drain(node);
            }
        }
    }

    /// Starts a lookup on a node.
    fn lookup(&mut self, node: usize, target: NodeId, filter: EnrFilter) -> LookupId {
        let id = self.nodes[node].lookup(self.now, target, filter, 16);
        self.drain(node);
        id
    }

    /// The most entries a node's table could hold: per bucket, the nodes at that distance, at most 16.
    fn capacity(&self, node: usize) -> usize {
        let local = self.nodes[node].local_enr().node_id();
        let mut per_bucket: BTreeMap<LogDistance, usize> = BTreeMap::new();
        for other in &self.nodes {
            let distance = local.log_distance(&other.local_enr().node_id());
            if distance != LogDistance::ZERO {
                *per_bucket.entry(distance).or_default() += 1;
            }
        }
        per_bucket.values().map(|count| (*count).min(16)).sum()
    }
}

#[test]
fn fifty_nodes_bootstrap_and_find_each_other() {
    let mut network = Network::new();
    let boot = network.nodes[0].local_enr().clone();

    // Phase 1: nodes 1 to 49 learn the boot node and look up their own id, 100 ms apart.
    for node in 1..NODES {
        network.run_until(Duration::from_millis(100 * node as u64));
        network.nodes[node].add_enr(network.now, boot.clone());
        let own = network.nodes[node].local_enr().node_id();
        network.lookup(node, own, EnrFilter::Any);
    }
    network.run_until(Duration::from_secs(10));

    // Phase 2: every node looks up a random-looking id, spreading knowledge further.
    for node in 0..NODES {
        let mut target = [0_u8; 32];
        target[0] = u8::try_from(node * 5).expect("fits");
        target[31] = 0x5a;
        network.lookup(node, NodeId(target), EnrFilter::Any);
    }
    network.run_until(Duration::from_secs(20));

    // Every node's table holds at least nine tenths of what its buckets could hold.
    for node in 0..NODES {
        let held = network.nodes[node].table().len();
        let capacity = network.capacity(node);
        assert!(
            held * 10 >= capacity * 9,
            "node {node} holds {held} of {capacity}"
        );
    }

    // Phase 3: node 49 looks up node 7, which is found as the nearest result.
    let target = network.nodes[7].local_enr().node_id();
    let id = network.lookup(49, target, EnrFilter::Any);
    network.run_until(Duration::from_secs(25));
    let peers = network.lookups.get(&(49, id)).expect("lookup finished");
    assert_eq!(peers.first().map(Enr::node_id), Some(target));

    // Phase 4: node 33 searches for subnet peers; every result advertises the subnet.
    let id = network.lookup(33, NodeId([0x77; 32]), EnrFilter::AttestationSubnet(SUBNET));
    network.run_until(Duration::from_secs(30));
    let peers = network.lookups.get(&(33, id)).expect("lookup finished");
    assert!(peers.len() >= 3, "found {} subnet peers", peers.len());
    for peer in peers {
        assert!(peer.eth2().on_attestation_subnet(SUBNET));
    }
}

#[test]
fn simulation_is_deterministic() {
    // Two runs from the same seeds deliver the same number of datagrams and fill the same tables.
    let run = || {
        let mut network = Network::new();
        let boot = network.nodes[0].local_enr().clone();
        for node in 1..10 {
            network.nodes[node].add_enr(network.now, boot.clone());
            let own = network.nodes[node].local_enr().node_id();
            network.lookup(node, own, EnrFilter::Any);
        }
        network.run_until(Duration::from_secs(5));
        let tables: Vec<usize> = network.nodes.iter().map(|n| n.table().len()).collect();
        (network.delivered, tables)
    };
    assert_eq!(run(), run());
}
