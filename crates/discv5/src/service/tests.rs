use std::{collections::VecDeque, net::Ipv4Addr};

use super::*;
use crate::table::TableConfig;

/// Nodes wired back to back: datagrams arrive in send order, with no loss and no delay.
struct Wire {
    /// The services.
    nodes: Vec<Service>,
    /// Datagrams in transit: sender index, then the datagram.
    queue: VecDeque<(usize, Datagram)>,
    /// Events per node.
    events: Vec<Vec<Event>>,
    /// Indices of datagrams to drop, counted from zero over the whole run.
    drop: Vec<usize>,
    /// Datagrams sent so far.
    sent: usize,
    /// Every datagram sent, dropped ones included.
    log: Vec<Vec<u8>>,
}

impl Wire {
    /// Nodes 1 to n on 10.0.i.1:9000, with a given key seed per node.
    fn new(count: u8) -> Self {
        // Node i signs with key [i; 32] and seeds its generator with [i; 32].
        let nodes = (1..=count)
            .map(|i| {
                let enr = record(i, 1);
                Service::new(key(i), enr, Config::default(), [i; 32]).expect("key matches")
            })
            .collect();
        Self {
            nodes,
            queue: VecDeque::new(),
            events: vec![Vec::new(); usize::from(count)],
            drop: Vec::new(),
            sent: 0,
            log: Vec::new(),
        }
    }

    /// Collects one node's outputs.
    fn drain(&mut self, node: usize) {
        // Datagrams go on the wire unless marked for dropping; events are kept per node.
        while let Some(output) = self.nodes[node].poll_output() {
            match output {
                Output::Send(datagram) => {
                    self.log.push(datagram.bytes.clone());
                    if !self.drop.contains(&self.sent) {
                        self.queue.push_back((node, datagram));
                    }
                    self.sent += 1;
                }
                Output::Event(event) => self.events[node].push(event),
            }
        }
    }

    /// Delivers datagrams until none are in transit.
    fn settle(&mut self, now: Duration) {
        // First collect what every node already queued, then deliver in order.
        for node in 0..self.nodes.len() {
            self.drain(node);
        }
        while let Some((from, datagram)) = self.queue.pop_front() {
            let to = self
                .nodes
                .iter()
                .position(|node| node.local_enr().endpoints().udp_socket() == Some(datagram.to))
                .expect("known endpoint");
            let from_addr = self.nodes[from]
                .local_enr()
                .endpoints()
                .udp_socket()
                .expect("endpoint");
            self.nodes[to].handle_datagram(now, from_addr, &datagram.bytes);
            self.drain(to);
        }
    }

    /// The record of node i.
    fn enr(&self, node: usize) -> Enr {
        self.nodes[node].local_enr().clone()
    }
}

/// The key of node i.
fn key(i: u8) -> SecretKey {
    SecretKey::from_bytes(&[i; 32]).expect("valid key")
}

/// The record of node i at a sequence number.
fn record(i: u8, seq: u64) -> Enr {
    // Node i lives on 10.0.i.1:9000, its own /24.
    Enr::builder()
        .seq(seq)
        .ip4(Ipv4Addr::new(10, 0, i, 1))
        .udp4(9000)
        .build(&key(i))
        .expect("record fits")
}

#[test]
fn records_must_match_the_key() {
    // Node 2's record with node 1's key.
    assert_eq!(
        Service::new(key(1), record(2, 1), Config::default(), [0; 32]).map(|_| ()),
        Err(ServiceError::KeyMismatch)
    );
}

#[test]
fn ping_opens_a_session_in_four_packets() {
    // Packets: random opener, WHOAREYOU, handshake with PING, PONG.
    let mut wire = Wire::new(2);
    let bob = wire.enr(1);
    let request_id = wire.nodes[0]
        .ping(Duration::ZERO, &bob)
        .expect("bob has an endpoint");
    wire.settle(Duration::ZERO);
    assert_eq!(wire.sent, 4);
    assert_eq!(
        wire.events[0],
        [Event::Pong {
            node: bob.node_id(),
            request_id,
            enr_seq: 1,
            observed: wire.enr(0).endpoints().udp_socket().expect("endpoint"),
        }]
    );
    // Bob learned alice from the record in her handshake.
    assert_eq!(wire.events[1], [Event::Discovered(Box::new(wire.enr(0)))]);
    // A second ping reuses the session: two packets.
    wire.nodes[0].ping(Duration::ZERO, &bob);
    wire.settle(Duration::ZERO);
    assert_eq!(wire.sent, 6);
}

#[test]
fn simultaneous_handshakes_converge() {
    // Alice and bob ping each other before either has a session.
    let mut wire = Wire::new(2);
    let alice = wire.enr(0);
    let bob = wire.enr(1);
    wire.nodes[0].ping(Duration::ZERO, &bob);
    wire.nodes[1].ping(Duration::ZERO, &alice);
    wire.settle(Duration::ZERO);
    // Each ends with a session and a PONG, whichever handshake won on each side.
    let pongs = |events: &[Event]| {
        events
            .iter()
            .filter(|event| matches!(event, Event::Pong { .. }))
            .count()
    };
    assert_eq!(pongs(&wire.events[0]), 1);
    assert_eq!(pongs(&wire.events[1]), 1);
    // Later traffic flows both ways without a new handshake: two packets per ping.
    let before = wire.sent;
    wire.nodes[0].ping(Duration::ZERO, &bob);
    wire.nodes[1].ping(Duration::ZERO, &alice);
    wire.settle(Duration::ZERO);
    assert_eq!(wire.sent - before, 4);
    assert_eq!(pongs(&wire.events[0]), 2);
    assert_eq!(pongs(&wire.events[1]), 2);
}

#[test]
fn silent_peers_fail_and_leave_the_table() {
    // Mutation: drop every datagram from the start, so the opener never arrives.
    let mut wire = Wire::new(2);
    wire.drop = (0..10).collect();
    let bob = wire.enr(1);
    wire.nodes[0].add_enr(Duration::ZERO, bob.clone());
    let request_id = wire.nodes[0].ping(Duration::ZERO, &bob).expect("endpoint");
    wire.settle(Duration::ZERO);
    // Timing: nothing fails before 500 ms; at 500 ms the request lapses.
    wire.nodes[0].handle_timeout(Duration::from_millis(499));
    wire.drain(0);
    assert!(!wire.events[0].contains(&Event::RequestFailed {
        node: bob.node_id(),
        request_id,
    }));
    wire.nodes[0].handle_timeout(Duration::from_millis(500));
    wire.drain(0);
    assert!(wire.events[0].contains(&Event::RequestFailed {
        node: bob.node_id(),
        request_id,
    }));
    // Bob never answered, so he leaves the table at once.
    assert!(wire.nodes[0].table().get(&bob.node_id()).is_none());
}

#[test]
fn repeated_packets_get_the_same_challenge() {
    // Mutation: drop alice's handshake, the third datagram, so bob's challenge stays open.
    let mut wire = Wire::new(2);
    wire.drop = vec![2];
    let bob = wire.enr(1);
    wire.nodes[0].ping(Duration::ZERO, &bob);
    wire.settle(Duration::ZERO);
    let first_challenge = wire.log[1].clone();

    // At 600 ms alice pings under her session; bob, still waiting, resends the same challenge.
    wire.nodes[0].ping(Duration::from_millis(600), &bob);
    wire.settle(Duration::from_millis(600));
    assert_eq!(wire.log.len(), 5);
    assert_eq!(wire.log[4], first_challenge);

    // The challenge names a packet alice no longer awaits, so her ping lapses at 1100 ms.
    wire.nodes[0].handle_timeout(Duration::from_millis(1100));
    wire.settle(Duration::from_millis(1100));
    let failures = wire.events[0]
        .iter()
        .filter(|event| matches!(event, Event::RequestFailed { .. }))
        .count();
    assert_eq!(failures, 2);

    // Bob's challenge lapsed at 1 s, so the next ping meets a fresh one and succeeds.
    wire.nodes[0].ping(Duration::from_millis(1200), &bob);
    wire.settle(Duration::from_millis(1200));
    assert_ne!(wire.log[6], first_challenge);
    assert!(
        wire.events[0]
            .iter()
            .any(|event| matches!(event, Event::Pong { .. }))
    );
}

#[test]
fn find_node_answers_split_across_messages() {
    // Fixture state: bob's table holds 16 verified nodes at distance 256 from him.
    let mut wire = Wire::new(2);
    let bob_id = wire.enr(1).node_id();
    let config = TableConfig {
        ip_limits: None,
        ..TableConfig::default()
    };
    wire.nodes[1].table = RoutingTable::new(bob_id, config);
    let mut far = Vec::new();
    for seed in 10..=250_u8 {
        let enr = record(seed, 1);
        if bob_id.log_distance(&enr.node_id()) == LogDistance::MAX && far.len() < 16 {
            wire.nodes[1].table.insert(enr.clone(), Duration::ZERO);
            wire.nodes[1].table.record_success(&enr.node_id());
            far.push(enr);
        }
    }
    assert_eq!(far.len(), 16);

    // Alice asks for distance 256 and gets all 16 back across two messages.
    let bob = wire.enr(1);
    wire.nodes[0].find_node(Duration::ZERO, &bob, vec![LogDistance::MAX]);
    wire.settle(Duration::ZERO);
    let found = wire.events[0]
        .iter()
        .find_map(|event| match event {
            Event::NodesFound { enrs, .. } => Some(enrs.clone()),
            _ => None,
        })
        .expect("answer arrived");
    assert_eq!(found.len(), 16);
    // Opener, WHOAREYOU, handshake, then two NODES packets, each within 1280 bytes.
    assert_eq!(wire.sent, 5);
}

#[test]
fn newer_records_are_fetched_after_ping() {
    // Bob knows alice at sequence 1; alice moves to sequence 2.
    let mut wire = Wire::new(2);
    let alice_v1 = wire.enr(0);
    let alice_v2 = alice_v1
        .to_builder()
        .udp4(9000)
        .build(&key(1))
        .expect("fits");
    wire.nodes[1].add_enr(Duration::ZERO, alice_v1.clone());
    wire.nodes[0].set_local_enr(alice_v2).expect("same key");
    // Bob pings alice; her PONG announces sequence 2, so bob asks for her record.
    wire.nodes[1].ping(Duration::ZERO, &alice_v1);
    wire.settle(Duration::ZERO);
    let held = wire.nodes[1]
        .table()
        .get(&alice_v1.node_id())
        .map(|entry| entry.enr.seq());
    assert_eq!(held, Some(2));
}

#[test]
fn talk_requests_reach_the_application() {
    // Alice sends TALKREQ "ask" under protocol "proto"; bob's application sees it.
    let mut wire = Wire::new(2);
    let bob = wire.enr(1);
    let request_id = wire.nodes[0]
        .talk_request(Duration::ZERO, &bob, b"proto".to_vec(), b"ask".to_vec())
        .expect("endpoint");
    wire.settle(Duration::ZERO);
    let alice_addr = wire.enr(0).endpoints().udp_socket().expect("endpoint");
    assert!(wire.events[1].contains(&Event::TalkRequest {
        node: wire.enr(0).node_id(),
        addr: alice_addr,
        request_id,
        protocol: b"proto".to_vec(),
        request: b"ask".to_vec(),
    }));
    let alice_id = wire.enr(0).node_id();
    // Bob's application answers "ok", which reaches alice's application.
    wire.nodes[1].talk_response(alice_id, alice_addr, request_id, b"ok".to_vec());
    wire.settle(Duration::ZERO);
    assert!(wire.events[0].contains(&Event::TalkResponse {
        node: bob.node_id(),
        request_id,
        response: b"ok".to_vec(),
    }));
}

#[test]
fn lookups_on_an_empty_table_finish_at_once() {
    // A lone node has nobody to ask, so the lookup reports no peers straight away.
    let mut wire = Wire::new(1);
    let id = wire.nodes[0].lookup(Duration::ZERO, NodeId([1; 32]), EnrFilter::Any, 16);
    wire.drain(0);
    assert_eq!(
        wire.events[0],
        [Event::LookupFinished {
            id,
            target: NodeId([1; 32]),
            peers: Vec::new(),
        }]
    );
}

#[test]
fn garbage_is_ignored() {
    // Random bytes of every length up to 1300 never panic and never produce output.
    let mut wire = Wire::new(1);
    let mut rng = Csprng::from_seed([9; 32]);
    let from: SocketAddr = "10.9.9.9:1".parse().expect("address");
    for len in 0..1300 {
        let mut bytes = vec![0; len];
        rng.fill(&mut bytes);
        wire.nodes[0].handle_datagram(Duration::ZERO, from, &bytes);
    }
    assert_eq!(wire.nodes[0].poll_output(), None);
}
