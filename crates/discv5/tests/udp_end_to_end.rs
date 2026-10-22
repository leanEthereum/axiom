//! Two tokio nodes over real UDP sockets: handshake, PING/PONG, FINDNODE, TALKREQ, and record updates.

use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket},
    time::Duration,
};

use axiom_crypto::secp256k1::SecretKey;
use axiom_discv5::{
    Enr, LogDistance,
    driver::{Discv5, Discv5Events, RecordUpdateError},
    service::{Config, Event, ServiceError},
};
use tokio::{runtime::Builder, time::timeout};

/// A free loopback UDP port, found by binding port zero and letting it go.
fn free_port() -> u16 {
    let socket = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind succeeds");
    socket.local_addr().expect("bound").port()
}

/// Starts a node whose record advertises its loopback port.
async fn node(seed: u8) -> (Discv5, Discv5Events) {
    let key = SecretKey::from_bytes(&[seed; 32]).expect("valid key");
    let port = free_port();
    let enr = Enr::builder()
        .ip4(Ipv4Addr::LOCALHOST)
        .udp4(port)
        .build(&key)
        .expect("record fits");
    let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    Discv5::start(key, enr, Config::default(), bind)
        .await
        .expect("node starts")
}

/// Waits for the first event a filter accepts, dropping the others.
async fn wait_for<T>(events: &mut Discv5Events, filter: impl Fn(Event) -> Option<T>) -> T {
    loop {
        let event = events.next().await.expect("driver running");
        if let Some(found) = filter(event) {
            return found;
        }
    }
}

/// Runs a scenario on a single-threaded runtime, where both drivers interleave on one thread.
fn run(scenario: impl Future<Output = ()>) {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds");
    runtime.block_on(async {
        timeout(Duration::from_secs(20), scenario)
            .await
            .expect("scenario completes in time");
    });
}

#[test]
fn ping_find_node_and_talk_over_udp() {
    run(scenario());
}

#[test]
fn an_updated_record_reaches_peers() {
    run(record_update());
}

/// Alice re-signs her record; bob learns of it through PONG and fetches it.
async fn record_update() {
    let (mut alice, _alice_events) = node(1).await;
    let (bob, mut bob_events) = node(2).await;
    let alice_v1 = alice.local_enr().clone();

    // Alice moves to sequence 2 with one more entry, signed by her own key.
    let key = SecretKey::from_bytes(&[1; 32]).expect("valid key");
    let alice_v2 = alice_v1
        .to_builder()
        .uint(b"cgc", 4)
        .build(&key)
        .expect("record fits");
    alice
        .set_local_enr(alice_v2.clone())
        .await
        .expect("driver up");
    assert_eq!(alice.local_enr(), &alice_v2);

    // Bob still holds sequence 1; alice's PONG announces sequence 2.
    bob.ping(alice_v1.clone()).await.expect("driver up");
    let announced = wait_for(&mut bob_events, |event| match event {
        Event::Pong { node, enr_seq, .. } => Some((node, enr_seq)),
        _ => None,
    })
    .await;
    assert_eq!(announced, (alice_v1.node_id(), 2));

    // FINDNODE at distance zero now returns the new record.
    bob.find_node(alice_v1, vec![LogDistance::ZERO])
        .await
        .expect("driver up");
    let found = wait_for(&mut bob_events, |event| match event {
        Event::NodesFound { enrs, .. } => Some(enrs),
        _ => None,
    })
    .await;
    assert_eq!(found, vec![alice_v2.clone()]);

    // Bob's record under alice's handle is refused, and alice keeps hers.
    let refused = alice.set_local_enr(bob.local_enr().clone()).await;
    assert_eq!(
        refused,
        Err(RecordUpdateError::Refused(ServiceError::KeyMismatch {
            record: bob.local_enr().node_id(),
            local: alice_v2.node_id(),
        }))
    );
    assert_eq!(alice.local_enr(), &alice_v2);
    alice.shutdown();
    bob.shutdown();
}

/// The whole exchange, phase by phase.
async fn scenario() {
    let (alice, mut alice_events) = node(1).await;
    let (bob, mut bob_events) = node(2).await;
    let bob_enr = bob.local_enr().clone();
    let bob_id = bob_enr.node_id();

    // Phase 1: alice pings bob; the handshake runs first, then PONG mirrors alice's endpoint.
    let request = alice.ping(bob_enr.clone()).await.expect("driver up");
    let pong = wait_for(&mut alice_events, |event| match event {
        Event::Pong {
            node,
            request_id,
            enr_seq,
            observed,
        } => Some((node, Some(request_id), enr_seq, observed)),
        _ => None,
    })
    .await;
    assert_eq!(pong, (bob_id, request, 1, alice.local_addr()));

    // Bob learned alice from her handshake record and added her to his table.
    let discovered = wait_for(&mut bob_events, |event| match event {
        Event::Discovered(enr) => Some(enr),
        _ => None,
    })
    .await;
    assert_eq!(&*discovered, alice.local_enr());

    // Phase 2: FINDNODE at distance zero returns bob's own record.
    let request = alice
        .find_node(bob_enr.clone(), vec![LogDistance::ZERO])
        .await
        .expect("driver up");
    let found = wait_for(&mut alice_events, |event| match event {
        Event::NodesFound {
            node,
            request_id,
            enrs,
        } => Some((node, Some(request_id), enrs)),
        _ => None,
    })
    .await;
    assert_eq!(found, (bob_id, request, vec![bob_enr.clone()]));

    // FINDNODE at alice's distance from bob returns alice, verified by her handshake.
    let distance = bob_id.log_distance(&alice.local_enr().node_id());
    alice
        .find_node(bob_enr.clone(), vec![distance])
        .await
        .expect("driver up");
    let found = wait_for(&mut alice_events, |event| match event {
        Event::NodesFound { enrs, .. } => Some(enrs),
        _ => None,
    })
    .await;
    assert_eq!(found, vec![alice.local_enr().clone()]);

    // Phase 3: a TALKREQ reaches bob's application, and its answer reaches alice.
    let request = alice
        .talk_request(bob_enr, b"echo".to_vec(), b"hello".to_vec())
        .await
        .expect("driver up");
    let (from, addr, request_id, payload) = wait_for(&mut bob_events, |event| match event {
        Event::TalkRequest {
            node,
            addr,
            request_id,
            protocol,
            request,
        } if protocol == b"echo" => Some((node, addr, request_id, request)),
        _ => None,
    })
    .await;
    assert_eq!(from, alice.local_enr().node_id());
    assert_eq!(payload, b"hello");
    bob.talk_response(from, addr, request_id, b"hello back".to_vec())
        .expect("driver up");
    let response = wait_for(&mut alice_events, |event| match event {
        Event::TalkResponse {
            node,
            request_id,
            response,
        } => Some((node, Some(request_id), response)),
        _ => None,
    })
    .await;
    assert_eq!(response, (bob_id, request, b"hello back".to_vec()));

    // Both tables hold the other node.
    assert_eq!(
        alice.table_entries().await.expect("driver up"),
        vec![bob.local_enr().clone()]
    );
    assert_eq!(
        bob.table_entries().await.expect("driver up"),
        vec![alice.local_enr().clone()]
    );
    alice.shutdown();
    bob.shutdown();
}
