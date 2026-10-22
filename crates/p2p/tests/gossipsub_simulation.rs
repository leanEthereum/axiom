//! A deterministic simulation of many gossipsub routers over an in-memory network.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, BinaryHeap},
    time::Duration,
};

use axiom_p2p::{
    PeerId, PublicKey,
    eth::encode_gossip,
    gossipsub::{
        GossipsubConfig, GossipsubEvent, MessageId, PeerScoreParams, PeerScoreThresholds,
        ProtocolVersion, Router, Rpc, Topic, TopicScoreParams, ValidationOutcome,
    },
    protobuf::ProtoMessage,
};

/// A tiny seeded generator, so the scheduler replays exactly.
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

    /// A value in 0..bound.
    const fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// Something scheduled at a virtual time.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Action {
    /// Wire bytes of an RPC arrive at a node.
    Deliver {
        /// Sender index.
        from: usize,
        /// Recipient index.
        to: usize,
        /// The encoded RPC.
        bytes: Vec<u8>,
    },
    /// A node runs its heartbeat.
    Heartbeat(usize),
    /// A node publishes a payload.
    Publish(usize, Vec<u8>),
}

/// The simulated network: nodes, a virtual clock, and a time-ordered queue.
struct Network {
    /// Routers by node index.
    nodes: Vec<Router>,
    /// Peer identifiers by node index.
    ids: Vec<PeerId>,
    /// Node index by peer identifier.
    index: BTreeMap<PeerId, usize>,
    /// Scheduled actions: (time in ms, sequence number for stable order, action).
    queue: BinaryHeap<Reverse<(u64, u64, Action)>>,
    /// Sequence counter.
    sequence: u64,
    /// The scheduler's randomness: latencies and topology.
    rng: SplitMix,
    /// Messages each node has accepted.
    delivered: Vec<BTreeSet<MessageId>>,
    /// Mesh sizes recorded right after each heartbeat, after warm-up.
    mesh_sizes: Vec<usize>,
}

/// Heartbeat period of the Ethereum profile, in ms.
const HEARTBEAT_MS: u64 = 700;

impl Network {
    /// Builds a random topology: each node dials a few random others.
    fn new(n: usize, dials_per_node: usize, seed: u64, topic: &Topic) -> Self {
        let rng = SplitMix(seed);
        let ids: Vec<PeerId> = (0..n)
            .map(|i| {
                let mut key = [0u8; 33];
                key[0] = 2;
                key[1..9].copy_from_slice(&(i as u64).to_le_bytes());
                PeerId::from_public_key(&PublicKey::secp256k1(key))
            })
            .collect();
        let index = ids
            .iter()
            .enumerate()
            .map(|(i, id)| (id.clone(), i))
            .collect();
        let slot = Duration::from_secs(12);
        let nodes = (0..n)
            .map(|i| {
                let mut params = PeerScoreParams::ethereum(slot, 32, 0.5);
                params.topics.insert(
                    topic.clone(),
                    TopicScoreParams::ethereum(0.5, 1.0, slot, 32, 8),
                );
                Router::new(
                    GossipsubConfig::default(),
                    Some((params, PeerScoreThresholds::ethereum())),
                    seed ^ i as u64,
                )
            })
            .collect();
        let mut network = Self {
            nodes,
            ids,
            index,
            queue: BinaryHeap::new(),
            sequence: 0,
            rng,
            delivered: vec![BTreeSet::new(); n],
            mesh_sizes: Vec::new(),
        };
        // Connections: node i dials random distinct peers; the dialer marks it outbound.
        let mut links = BTreeSet::new();
        for i in 0..n {
            while links.iter().filter(|(a, _)| *a == i).count() < dials_per_node {
                let j = network.rng.below(n as u64) as usize;
                if j != i && !links.contains(&(j, i)) {
                    links.insert((i, j));
                }
            }
        }
        for (i, j) in links {
            let (id_i, id_j) = (network.ids[i].clone(), network.ids[j].clone());
            network.nodes[i].add_peer(&id_j, ProtocolVersion::V1_2, true);
            network.nodes[j].add_peer(&id_i, ProtocolVersion::V1_1, false);
        }
        // Heartbeats with a random phase per node, as real nodes start at different times.
        for i in 0..n {
            let phase = network.rng.below(HEARTBEAT_MS);
            network.schedule(phase, Action::Heartbeat(i));
        }
        network
    }

    /// Queues an action at a time.
    fn schedule(&mut self, at: u64, action: Action) {
        self.sequence += 1;
        self.queue.push(Reverse((at, self.sequence, action)));
    }

    /// Sends every pending RPC of a node, with a random 10 to 60 ms latency.
    fn flush(&mut self, node: usize, now: u64) {
        // Events first: the application accepts every message at once.
        while let Some(event) = self.nodes[node].poll_event() {
            if let GossipsubEvent::Message { id, .. } = event {
                self.delivered[node].insert(id);
                self.nodes[node].report_validation(
                    &id,
                    ValidationOutcome::Accept,
                    Duration::from_millis(now),
                );
            }
        }
        while let Some((peer, rpc)) = self.nodes[node].poll_transmit() {
            let to = self.index[&peer];
            let latency = 10 + self.rng.below(50);
            // Through the real codec, as on a wire.
            self.schedule(
                now + latency,
                Action::Deliver {
                    from: node,
                    to,
                    bytes: rpc.encode(),
                },
            );
        }
    }

    /// Runs every action up to a time.
    fn run_until(&mut self, end: u64, record_after: u64) {
        while let Some(Reverse((at, _, _))) = self.queue.peek() {
            if *at > end {
                return;
            }
            let Some(Reverse((now, _, action))) = self.queue.pop() else {
                return;
            };
            let time = Duration::from_millis(now);
            let node = match action {
                Action::Deliver { from, to, bytes } => {
                    let rpc = Rpc::decode(&bytes).expect("own encoding decodes");
                    let sender = self.ids[from].clone();
                    self.nodes[to].handle_rpc(&sender, rpc, time);
                    to
                }
                Action::Heartbeat(node) => {
                    self.nodes[node].heartbeat(time);
                    if now >= record_after {
                        let topic = Topic::new(TOPIC);
                        self.mesh_sizes
                            .push(self.nodes[node].mesh_peers(&topic).count());
                    }
                    self.schedule(now + HEARTBEAT_MS, Action::Heartbeat(node));
                    node
                }
                Action::Publish(node, data) => {
                    let id = self.nodes[node]
                        .publish(Topic::new(TOPIC), data, time)
                        .expect("publish succeeds");
                    self.delivered[node].insert(id);
                    node
                }
            };
            self.flush(node, now);
        }
    }
}

/// The simulated topic.
const TOPIC: &str = "/eth2/00000000/beacon_block/ssz_snappy";

#[test]
fn messages_reach_every_node_and_meshes_stay_in_bounds() {
    // Fixture state: 50 nodes, each dialing 10 others → about 20 connections per node.
    let topic = Topic::new(TOPIC);
    let mut network = Network::new(50, 10, 0x5eed, &topic);
    for node in &mut network.nodes {
        node.subscribe(&topic, Duration::ZERO);
    }
    for i in 0..network.nodes.len() {
        network.flush(i, 0);
    }

    // Phase 1: ten seconds of warm-up let subscriptions spread and meshes form.
    network.run_until(10_000, 5_000);

    // Phase 2: 30 messages from random publishers, one every 200 ms.
    let mut published = Vec::new();
    for k in 0..30u64 {
        let publisher = network.rng.below(50) as usize;
        let payload = encode_gossip(format!("block {k}").as_bytes());
        network.schedule(
            10_000 + k * 200,
            Action::Publish(publisher, payload.clone()),
        );
        published.push(payload);
    }
    network.run_until(25_000, 5_000);

    // Every node accepted every message.
    let ids: BTreeSet<MessageId> = published
        .iter()
        .map(|data| (GossipsubConfig::default().message_id)(&topic, data))
        .collect();
    for (node, delivered) in network.delivered.iter().enumerate() {
        let missing = ids.difference(delivered).count();
        assert_eq!(missing, 0, "node {node} missed {missing} messages");
    }

    // After every heartbeat past warm-up, the mesh degree sat within [D_low, D_high] = [6, 12].
    assert!(!network.mesh_sizes.is_empty());
    let (min, max) = (
        network.mesh_sizes.iter().min().copied(),
        network.mesh_sizes.iter().max().copied(),
    );
    assert!(
        network.mesh_sizes.iter().all(|&d| (6..=12).contains(&d)),
        "mesh sizes ranged {min:?}..={max:?}"
    );
}

#[test]
fn simulation_is_deterministic() {
    // Two runs with one seed record identical mesh histories.
    let run = || {
        let topic = Topic::new(TOPIC);
        let mut network = Network::new(20, 6, 42, &topic);
        for node in &mut network.nodes {
            node.subscribe(&topic, Duration::ZERO);
        }
        for i in 0..network.nodes.len() {
            network.flush(i, 0);
        }
        network.run_until(5_000, 0);
        network.mesh_sizes
    };
    assert_eq!(run(), run());
}
