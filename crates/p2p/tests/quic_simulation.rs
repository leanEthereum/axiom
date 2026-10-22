//! Two QUIC endpoints over a simulated network with a virtual clock.
//!
//! The network delays, drops, reorders and duplicates datagrams under a seeded generator.
//! Every run is deterministic, so a failure replays exactly.

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};

use axiom_p2p::{
    Keypair, PeerId,
    quic::{
        Connection, ConnectionError, ConnectionHandle, DatagramEvent, Endpoint, Event, QuicConfig,
        StreamId, Transmit,
    },
    tls::{TlsIdentity, VerifiedPeer},
};

/// Seconds since the Unix epoch the simulated clocks start at: 2026-01-01.
const UNIX_START: u64 = 1_767_225_600;

/// The simulated round-trip time.
const RTT: Duration = Duration::from_millis(40);

/// A small deterministic generator for the network's decisions.
struct Dice(u64);

impl Dice {
    const fn next(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// True with a probability in percent.
    const fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

/// How the network mistreats datagrams.
#[derive(Clone, Copy)]
struct Weather {
    /// Percent of datagrams lost.
    loss: u64,
    /// Percent of datagrams delivered twice.
    duplication: u64,
    /// Extra random delay, which reorders.
    jitter: Duration,
}

const CLEAR: Weather = Weather {
    loss: 0,
    duplication: 0,
    jitter: Duration::ZERO,
};

/// One node: an endpoint, its connections, and the events they reported.
struct Node {
    address: SocketAddr,
    keypair: Keypair,
    identity: Arc<TlsIdentity>,
    endpoint: Endpoint,
    connections: BTreeMap<ConnectionHandle, Connection>,
    events: Vec<(ConnectionHandle, Event)>,
}

impl Node {
    fn new(port: u16, secret: u8, config: impl Fn(Arc<TlsIdentity>) -> QuicConfig) -> Self {
        let keypair = Keypair::from_secret_bytes(&[secret; 32])
            .expect("a repeated byte below the order is a valid scalar");
        let identity = Arc::new(
            TlsIdentity::generate(&keypair, [secret ^ 0x55; 32])
                .expect("the certificate key derives from the seed"),
        );
        Self {
            address: SocketAddr::from(([10, 0, 0, secret], port)),
            endpoint: Endpoint::new(Arc::new(config(Arc::clone(&identity))), [secret; 32]),
            identity,
            keypair,
            connections: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    fn peer_id(&self) -> PeerId {
        self.keypair.peer_id()
    }

    fn only(&mut self) -> &mut Connection {
        self.connections
            .values_mut()
            .next()
            .expect("the node has a connection")
    }

    fn handle(&self) -> ConnectionHandle {
        *self
            .connections
            .keys()
            .next()
            .expect("the node has a connection")
    }
}

/// Datagrams in flight, by delivery time and sequence.
struct Network {
    now: Duration,
    weather: Weather,
    dice: Dice,
    in_flight: BTreeMap<(Duration, u64), (SocketAddr, Transmit)>,
    sequence: u64,
    /// Whether the network drops everything, as a cut cable does.
    cut: bool,
    /// A sender whose datagrams are all dropped.
    silenced: Option<SocketAddr>,
    /// Bytes each address handed to the network.
    sent: BTreeMap<SocketAddr, usize>,
}

impl Network {
    const fn new(weather: Weather, seed: u64) -> Self {
        Self {
            now: Duration::ZERO,
            weather,
            dice: Dice(seed),
            in_flight: BTreeMap::new(),
            sequence: 0,
            cut: false,
            silenced: None,
            sent: BTreeMap::new(),
        }
    }

    fn send(&mut self, from: SocketAddr, transmit: &Transmit) {
        *self.sent.entry(from).or_default() += transmit.bytes.len();
        if self.cut || self.silenced == Some(from) || self.dice.chance(self.weather.loss) {
            return;
        }
        let copies = if self.dice.chance(self.weather.duplication) {
            2
        } else {
            1
        };
        for _ in 0..copies {
            let jitter_ns = self.weather.jitter.as_nanos() as u64;
            let jitter = if jitter_ns == 0 {
                0
            } else {
                self.dice.next() % jitter_ns
            };
            let at = self.now + RTT / 2 + Duration::from_nanos(jitter);
            self.sequence += 1;
            self.in_flight
                .insert((at, self.sequence), (from, transmit.clone()));
        }
    }
}

/// Moves every node's output onto the network.
fn flush(network: &mut Network, nodes: &mut [&mut Node]) {
    for node in nodes.iter_mut() {
        for connection in node.connections.values_mut() {
            while let Some(transmit) = connection.poll_transmit(network.now) {
                network.send(node.address, &transmit);
            }
        }
    }
}

/// Collects events and forgets closed connections' routes.
fn collect(nodes: &mut [&mut Node]) {
    for node in nodes.iter_mut() {
        for (handle, connection) in &mut node.connections {
            while let Some(event) = connection.poll_event() {
                node.events.push((*handle, event));
            }
        }
    }
}

/// Runs the simulation until a condition holds or a virtual deadline passes.
fn run(
    network: &mut Network,
    client: &mut Node,
    server: &mut Node,
    limit: Duration,
    mut done: impl FnMut(&mut Node, &mut Node) -> bool,
) -> bool {
    let deadline = network.now + limit;
    loop {
        flush(network, &mut [client, server]);
        collect(&mut [client, server]);
        if done(client, server) {
            return true;
        }
        // The condition may have written or consumed: send what that produced.
        flush(network, &mut [client, server]);
        // The next moment anything happens: a delivery or a timer.
        let mut next = network.in_flight.keys().next().map(|(at, _)| *at);
        for node in [&*client, &*server] {
            for connection in node.connections.values() {
                if let Some(at) = connection.poll_timeout() {
                    next = Some(next.map_or(at, |n: Duration| n.min(at)));
                }
            }
        }
        let Some(next) = next else {
            return false;
        };
        if next > deadline {
            return false;
        }
        network.now = network.now.max(next);
        // Deliver what is due.
        while let Some((&key, _)) = network.in_flight.first_key_value() {
            if key.0 > network.now {
                break;
            }
            let (from, transmit) = network
                .in_flight
                .remove(&key)
                .expect("the earliest datagram was just seen");
            let node: &mut Node = if transmit.destination == client.address {
                client
            } else {
                server
            };
            deliver(network, node, from, &transmit.bytes);
        }
        for node in [&mut *client, &mut *server] {
            for connection in node.connections.values_mut() {
                if connection
                    .poll_timeout()
                    .is_some_and(|at| at <= network.now)
                {
                    connection.handle_timeout(network.now);
                }
            }
        }
    }
}

/// Hands a datagram to a node's endpoint and the connection it routes to.
fn deliver(network: &mut Network, node: &mut Node, from: SocketAddr, bytes: &[u8]) {
    let unix = UNIX_START + network.now.as_secs();
    match node.endpoint.handle(network.now, unix, from, bytes) {
        Some(DatagramEvent::Route(handle)) => {
            if let Some(connection) = node.connections.get_mut(&handle) {
                connection.handle_datagram(network.now, from, bytes);
            }
        }
        Some(DatagramEvent::Accept(handle, connection)) => {
            node.connections.insert(handle, *connection);
        }
        Some(DatagramEvent::Respond(transmit)) => network.send(node.address, &transmit),
        None => {}
    }
}

/// A client and a server with default settings, the client dialing the server.
fn pair(weather: Weather, seed: u64) -> (Network, Node, Node) {
    pair_with(weather, seed, QuicConfig::new)
}

fn pair_with(
    weather: Weather,
    seed: u64,
    config: impl Fn(Arc<TlsIdentity>) -> QuicConfig + Copy,
) -> (Network, Node, Node) {
    let network = Network::new(weather, seed);
    let mut client = Node::new(4001, 1, config);
    let server = Node::new(4002, 2, config);
    let (handle, connection) = client.endpoint.connect(
        server.address,
        Some(server.peer_id()),
        network.now,
        UNIX_START,
    );
    client.connections.insert(handle, connection);
    (network, client, server)
}

fn connected(node: &Node) -> Option<VerifiedPeer> {
    node.events.iter().find_map(|(_, event)| match event {
        Event::Connected(peer) => Some(peer.clone()),
        _ => None,
    })
}

fn handshake(network: &mut Network, client: &mut Node, server: &mut Node) {
    let ok = run(
        network,
        client,
        server,
        Duration::from_secs(10),
        |client, server| connected(client).is_some() && connected(server).is_some(),
    );
    assert!(ok, "handshake did not complete");
}

/// The bytes a node received on a stream, and whether the stream finished.
fn stream_bytes(node: &Node, stream: StreamId) -> (Vec<u8>, bool) {
    let mut data = Vec::new();
    let mut finished = false;
    for (_, event) in &node.events {
        match event {
            Event::Data { stream: s, data: d } if *s == stream => data.extend_from_slice(d),
            Event::StreamFinished(s) if *s == stream => finished = true,
            _ => {}
        }
    }
    (data, finished)
}

/// A payload whose bytes identify their stream and position.
fn payload(stream: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u64 * 31 + stream * 7) as u8)
        .collect()
}

/// Writes as much of a payload as the stream takes, returning how much went in.
fn write_some(connection: &mut Connection, stream: StreamId, data: &[u8], sent: &mut usize) {
    while *sent < data.len() {
        let room = connection.writable(stream);
        if room == 0 {
            return;
        }
        let end = (*sent + room).min(data.len());
        connection
            .send(stream, &data[*sent..end])
            .expect("the stream is open");
        *sent = end;
    }
}

/// Consumes every byte a node received, as an application that keeps up does.
fn consume_all(node: &mut Node, seen: &mut usize) {
    let fresh: Vec<(StreamId, usize)> = node.events[*seen..]
        .iter()
        .filter_map(|(_, event)| match event {
            Event::Data { stream, data } => Some((*stream, data.len())),
            _ => None,
        })
        .collect();
    *seen = node.events.len();
    for (stream, len) in fresh {
        node.only().consume(stream, len);
    }
}

#[test]
fn handshake_authenticates_both_peers() {
    let (mut network, mut client, mut server) = pair(CLEAR, 1);
    handshake(&mut network, &mut client, &mut server);

    // Each side learns the other's libp2p identity from its certificate.
    assert_eq!(connected(&client).unwrap().peer_id, server.peer_id());
    assert_eq!(connected(&server).unwrap().peer_id, client.peer_id());

    // One round trip for the handshake, plus the delivery of the client's last flight.
    assert!(network.now <= RTT * 2, "handshake took {:?}", network.now);
}

#[test]
fn a_wrong_expected_peer_is_refused() {
    let mut network = Network::new(CLEAR, 2);
    let mut client = Node::new(4001, 1, QuicConfig::new);
    let mut server = Node::new(4002, 2, QuicConfig::new);
    // The client expects a third identity.
    let impostor = Keypair::from_secret_bytes(&[9; 32]).unwrap().peer_id();
    let (handle, connection) =
        client
            .endpoint
            .connect(server.address, Some(impostor), network.now, UNIX_START);
    client.connections.insert(handle, connection);
    run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_secs(5),
        |client, _| {
            client
                .events
                .iter()
                .any(|(_, event)| matches!(event, Event::Closed(_)))
        },
    );
    assert!(connected(&client).is_none());
    assert!(matches!(
        client.events.last(),
        Some((_, Event::Closed(ConnectionError::Transport(_))))
    ));
}

/// Opens streams both ways, sends a payload on each, and checks every byte arrives.
fn exchange(weather: Weather, seed: u64, streams: u64, len: usize, limit: Duration) {
    let (mut network, mut client, mut server) = pair(weather, seed);
    handshake(&mut network, &mut client, &mut server);

    let mut client_streams = Vec::new();
    for _ in 0..streams {
        client_streams.push(client.only().open_stream().expect("the stream is open"));
    }
    let mut server_streams = Vec::new();
    for _ in 0..streams {
        server_streams.push(server.only().open_stream().expect("the stream is open"));
    }
    let mut client_sent = vec![0; streams as usize];
    let mut server_sent = vec![0; streams as usize];
    let mut client_seen = 0;
    let mut server_seen = 0;
    let ok = run(
        &mut network,
        &mut client,
        &mut server,
        limit,
        |client, server| {
            // Keep feeding the send buffers and consuming what arrived.
            for (i, stream) in client_streams.iter().enumerate() {
                let data = payload(stream.0, len);
                let before = client_sent[i];
                write_some(client.only(), *stream, &data, &mut client_sent[i]);
                if client_sent[i] == len && before < len {
                    client.only().close(*stream).expect("the stream is open");
                }
            }
            for (i, stream) in server_streams.iter().enumerate() {
                let data = payload(stream.0, len);
                let before = server_sent[i];
                write_some(server.only(), *stream, &data, &mut server_sent[i]);
                if server_sent[i] == len && before < len {
                    server.only().close(*stream).expect("the stream is open");
                }
            }
            consume_all(client, &mut client_seen);
            consume_all(server, &mut server_seen);
            client_streams
                .iter()
                .all(|stream| stream_bytes(server, *stream).1)
                && server_streams
                    .iter()
                    .all(|stream| stream_bytes(client, *stream).1)
        },
    );
    let closes: Vec<&Event> = client
        .events
        .iter()
        .chain(&server.events)
        .map(|(_, event)| event)
        .filter(|event| matches!(event, Event::Closed(_)))
        .collect();
    assert!(
        ok,
        "transfer did not complete by {:?}: {closes:?}",
        network.now
    );
    for stream in &client_streams {
        assert_eq!(
            stream_bytes(&server, *stream),
            (payload(stream.0, len), true)
        );
    }
    for stream in &server_streams {
        assert_eq!(
            stream_bytes(&client, *stream),
            (payload(stream.0, len), true)
        );
    }
}

#[test]
fn streams_carry_data_both_ways() {
    // Four streams each way, 300 KB each: past the 1 MiB stream window in total per side.
    exchange(CLEAR, 3, 4, 300_000, Duration::from_secs(30));
}

#[test]
fn recovers_from_loss_reordering_and_duplication() {
    let weather = Weather {
        loss: 20,
        duplication: 5,
        jitter: Duration::from_millis(15),
    };
    for seed in 10..14 {
        exchange(weather, seed, 3, 60_000, Duration::from_secs(120));
    }
}

#[test]
fn flow_control_stalls_until_the_receiver_consumes() {
    let (mut network, mut client, mut server) = pair_with(CLEAR, 4, |identity| {
        let mut config = QuicConfig::new(identity);
        config.limits.stream_window = 10_000;
        config.limits.connection_window = 20_000;
        config
    });
    handshake(&mut network, &mut client, &mut server);
    let stream = client.only().open_stream().unwrap();
    client.only().send(stream, &payload(0, 50_000)).unwrap();

    // Without consumption, the server's 10 000-byte window holds the client back.
    run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_secs(2),
        |_, _| false,
    );
    assert_eq!(stream_bytes(&server, stream).0.len(), 10_000);

    // Consuming releases the rest.
    let mut seen = 0;
    let ok = run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_secs(10),
        |_, server| {
            consume_all(server, &mut seen);
            stream_bytes(server, stream).0.len() == 50_000
        },
    );
    assert!(ok, "received {}", stream_bytes(&server, stream).0.len());
}

#[test]
fn reset_reaches_the_peer() {
    let (mut network, mut client, mut server) = pair(CLEAR, 5);
    handshake(&mut network, &mut client, &mut server);
    let stream = client.only().open_stream().unwrap();
    client.only().send(stream, b"half a request").unwrap();
    client.only().reset(stream).unwrap();
    let ok = run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_secs(5),
        |_, server| {
            server
                .events
                .iter()
                .any(|(_, event)| *event == Event::StreamReset(stream))
        },
    );
    assert!(ok);
}

#[test]
fn application_close_reaches_the_peer() {
    let (mut network, mut client, mut server) = pair(CLEAR, 6);
    handshake(&mut network, &mut client, &mut server);
    let now = network.now;
    client.only().close_connection(now, 7, b"bye");
    let ok = run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_secs(5),
        |_, server| {
            server.events.iter().any(|(_, event)| {
                *event
                    == Event::Closed(ConnectionError::PeerApplication {
                        code: 7,
                        reason: "bye".to_owned(),
                    })
            })
        },
    );
    assert!(ok);
    // Both sides end after their closing and draining periods.
    run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_secs(10),
        |_, _| false,
    );
    assert!(client.only().is_closed() && server.only().is_closed());
    let handle = server.handle();
    server.endpoint.forget(handle);
    assert!(server.endpoint.is_empty());
}

#[test]
fn idle_connection_times_out_when_the_network_is_cut() {
    let (mut network, mut client, mut server) = pair_with(CLEAR, 7, |identity| {
        let mut config = QuicConfig::new(identity);
        config.idle_timeout = Duration::from_secs(5);
        config
    });
    handshake(&mut network, &mut client, &mut server);
    network.cut = true;
    let ok = run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_secs(30),
        |client, server| {
            [client, server].iter().all(|node| {
                node.events
                    .iter()
                    .any(|(_, event)| *event == Event::Closed(ConnectionError::TimedOut))
            })
        },
    );
    assert!(ok);
}

#[test]
fn keep_alive_holds_an_idle_connection_open() {
    let (mut network, mut client, mut server) = pair(CLEAR, 8);
    handshake(&mut network, &mut client, &mut server);
    // A minute of silence, twice the idle timeout: keep-alive PINGs every 10 s hold it.
    run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_secs(60),
        |_, _| false,
    );
    assert!(client.only().is_established() && server.only().is_established());
}

#[test]
fn keep_alive_beats_a_shorter_idle_timeout_of_the_peer() {
    // The server allows only 6 s of silence, less than the client's 10 s keep-alive.
    let (mut network, mut client, mut server) = pair(CLEAR, 13);
    let identity = Arc::clone(&server.identity);
    let mut config = QuicConfig::new(identity);
    config.idle_timeout = Duration::from_secs(6);
    config.keep_alive = None;
    server.endpoint = Endpoint::new(Arc::new(config), [2; 32]);
    handshake(&mut network, &mut client, &mut server);
    // A minute of silence: the client's keep-alive drops to 3 s and holds both ends open.
    run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_secs(60),
        |_, _| false,
    );
    assert!(client.only().is_established() && server.only().is_established());
}

#[test]
fn key_update_keeps_data_flowing() {
    let (mut network, mut client, mut server) = pair(CLEAR, 9);
    handshake(&mut network, &mut client, &mut server);
    let stream = client.only().open_stream().unwrap();
    client.only().send(stream, b"before").unwrap();
    run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_secs(1),
        |_, server| stream_bytes(server, stream).0.len() == 6,
    );
    // Once the server acknowledges the first data and confirms the handshake, the client may update.
    run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_millis(200),
        |_, _| false,
    );
    assert!(client.only().update_keys());
    client.only().send(stream, b" after").unwrap();
    client.only().close(stream).unwrap();
    let ok = run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_secs(5),
        |_, server| stream_bytes(server, stream).1,
    );
    assert!(ok);
    assert_eq!(
        stream_bytes(&server, stream),
        (b"before after".to_vec(), true)
    );
}

#[test]
fn unknown_versions_get_version_negotiation() {
    let mut node = Node::new(4002, 2, QuicConfig::new);
    // A 1200-byte long header of version 0x1a2a3a4a with dcid 0102 and scid 03.
    let mut datagram = vec![0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 2, 1, 2, 1, 3];
    datagram.resize(1200, 0);
    let from = SocketAddr::from(([10, 0, 0, 9], 5000));
    let Some(DatagramEvent::Respond(reply)) =
        node.endpoint
            .handle(Duration::ZERO, UNIX_START, from, &datagram)
    else {
        panic!("no version negotiation");
    };
    // The reply swaps the ids and lists version 1.
    assert_eq!(reply.destination, from);
    assert_eq!(reply.bytes[1..], [0, 0, 0, 0, 1, 3, 2, 1, 2, 0, 0, 0, 1]);
    assert_eq!(reply.bytes[0] & 0x80, 0x80);

    // A short datagram of an unknown version is not answered, so the endpoint amplifies nothing.
    assert!(
        node.endpoint
            .handle(Duration::ZERO, UNIX_START, from, &datagram[..100])
            .is_none()
    );
}

#[test]
fn a_server_sends_at_most_three_times_what_it_received_before_validation() {
    let (mut network, mut client, mut server) = pair(CLEAR, 12);
    // Deliver the client's first Initial, then silence the client, as a spoofed source would be.
    run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_secs(1),
        |_, server| !server.connections.is_empty(),
    );
    network.silenced = Some(client.address);
    let received = network.sent[&client.address];
    run(
        &mut network,
        &mut client,
        &mut server,
        Duration::from_secs(20),
        |_, _| false,
    );

    // Probe timeouts fire, but the server never sends past three times the client's 1200 bytes.
    let sent = network.sent.get(&server.address).copied().unwrap_or(0);
    assert_eq!(received, 1200);
    assert!(
        sent <= 3 * received,
        "server sent {sent} for {received} received"
    );
    assert!(sent > 1200, "the server answered at all: {sent}");
}
