//! Two tokio nodes over real TCP sockets: gossip, req/resp, identify, and disconnection.
//!
//! The scenario runs twice: over real Noise, the production channel, and over plaintext.

use std::{sync::Arc, time::Duration};

use axiom_p2p::{
    Keypair, PeerId,
    eth::{
        GossipKind, GossipTopic,
        reqresp::{Protocol, ResponseChunk, ResponseCode, Status},
    },
    gossipsub::{PublishError, ValidationOutcome},
    multiaddr::Protocol as Layer,
    secure::plaintext::PlaintextConfig,
    swarm::{self, NetworkConfig, NetworkEvent, NetworkEvents, NetworkHandle},
};
use axiom_ssz::Ssz;
use axiom_types::{Epoch, ForkDigest, Root, Slot};
use tokio::{
    runtime::Builder,
    time::{sleep, timeout},
};

/// A node's events, with the ones skipped so far kept for later waits.
struct Inbox {
    /// The live stream.
    events: NetworkEvents,
    /// Events received but not matched yet.
    backlog: Vec<NetworkEvent>,
}

impl Inbox {
    /// Waits for the first event a filter accepts, keeping the others.
    async fn wait_for<T>(&mut self, filter: impl Fn(&NetworkEvent) -> Option<T>) -> T {
        // Earlier events first, in arrival order.
        if let Some(found) = self
            .backlog
            .iter()
            .position(|event| filter(event).is_some())
        {
            let event = self.backlog.remove(found);
            return filter(&event).expect("matched just above");
        }
        loop {
            let event = self.events.next().await.expect("network still running");
            if let Some(found) = filter(&event) {
                return found;
            }
            self.backlog.push(event);
        }
    }
}

/// Which secure channel the nodes speak.
#[derive(Clone, Copy, Debug)]
enum Channel {
    /// Noise XX with secp256k1 identities, the default.
    Noise,
    /// The unauthenticated test channel.
    Plaintext,
}

/// Starts a node whose secp256k1 secret is 32 copies of a seed byte.
async fn node(seed: u8, channel: Channel) -> (NetworkHandle, Inbox) {
    let identity = Keypair::from_secret_bytes(&[seed; 32]).expect("seed is a valid scalar");
    let mut config = match channel {
        Channel::Noise => NetworkConfig::new(identity).expect("entropy available"),
        Channel::Plaintext => {
            let security = Arc::new(PlaintextConfig::new(identity.public_key().clone()));
            NetworkConfig::with_security(identity, security)
        }
    };
    config.seed = u64::from(seed);
    let (handle, events) = swarm::start(config).await.expect("listener binds");
    (
        handle,
        Inbox {
            events,
            backlog: Vec::new(),
        },
    )
}

#[test]
fn gossip_and_status_over_noise() {
    run(Channel::Noise);
}

#[test]
fn gossip_and_status_over_plaintext() {
    run(Channel::Plaintext);
}

/// Runs the scenario on a single-threaded runtime, where every task interleaves on one thread.
fn run(channel: Channel) {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds");
    runtime.block_on(async {
        timeout(Duration::from_secs(20), scenario(channel))
            .await
            .expect("scenario completes in time");
    });
}

/// Two connected nodes and their inboxes.
struct Pair {
    /// The dialing node.
    alice: NetworkHandle,
    /// Alice's events.
    alice_events: Inbox,
    /// The listening node.
    bob: NetworkHandle,
    /// Bob's events.
    bob_events: Inbox,
}

/// The whole exchange between two nodes, phase by phase.
async fn scenario(channel: Channel) {
    let mut pair = connect(channel).await;
    gossip(&mut pair).await;
    status(&mut pair).await;
    identify_and_disconnect(&mut pair).await;
}

/// Phase 1: alice dials bob and both see the connection.
async fn connect(channel: Channel) -> Pair {
    let (alice, mut alice_events) = node(1, channel).await;
    let (bob, mut bob_events) = node(2, channel).await;
    let alice_id = alice.local_peer().clone();
    let bob_id = bob.local_peer().clone();

    // Phase 1: alice dials bob's address, naming his identity in a /p2p layer.
    let address = bob.listen_addr().clone().with(Layer::P2p(bob_id.clone()));
    alice.dial(address).await.expect("dial queued");
    let connected = alice_events
        .wait_for(|event| match event {
            NetworkEvent::PeerConnected { peer, outbound, .. } => Some((peer.clone(), *outbound)),
            _ => None,
        })
        .await;
    assert_eq!(connected, (bob_id.clone(), true));
    let connected = bob_events
        .wait_for(|event| match event {
            NetworkEvent::PeerConnected { peer, outbound, .. } => Some((peer.clone(), *outbound)),
            _ => None,
        })
        .await;
    assert_eq!(connected, (alice_id, false));
    Pair {
        alice,
        alice_events,
        bob,
        bob_events,
    }
}

/// Phase 2: a block published by alice reaches bob.
async fn gossip(pair: &mut Pair) {
    let Pair {
        alice,
        bob,
        bob_events,
        ..
    } = pair;
    let alice_id = alice.local_peer().clone();
    // Both join the block topic of a made-up fork.
    let digest = ForkDigest([0xde, 0xad, 0xbe, 0xef]);
    let topic = GossipTopic {
        fork_digest: digest,
        kind: GossipKind::BeaconBlock,
    }
    .topic();
    alice
        .subscribe(topic.clone())
        .await
        .expect("subscribe queued");
    bob.subscribe(topic.clone())
        .await
        .expect("subscribe queued");

    // Alice publishes once she has heard bob's subscription; until then nobody is eligible.
    let block = b"a signed beacon block, as SSZ".repeat(20);
    let id = loop {
        match alice
            .publish(topic.clone(), block.clone())
            .await
            .expect("swarm running")
        {
            Ok(id) => break id,
            Err(PublishError::InsufficientPeers { .. }) => sleep(Duration::from_millis(50)).await,
            Err(error) => panic!("publish failed: {error}"),
        }
    };

    // Bob receives the decompressed payload, attributed to alice, and accepts it.
    let (received, source, data) = bob_events
        .wait_for(|event| match event {
            NetworkEvent::GossipMessage {
                id, source, data, ..
            } => Some((*id, source.clone(), data.clone())),
            _ => None,
        })
        .await;
    assert_eq!((received, &source, &data), (id, &alice_id, &block));
    bob.report_validation(received, ValidationOutcome::Accept)
        .await
        .expect("verdict queued");
}

/// Phase 3: a Status v2 exchange, then a malformed request.
async fn status(pair: &mut Pair) {
    let Pair {
        alice,
        alice_events,
        bob,
        bob_events,
    } = pair;
    let alice_id = alice.local_peer().clone();
    let bob_id = bob.local_peer().clone();
    // Alice sends Status v2; bob answers with his own.
    let alice_status = Status {
        fork_digest: ForkDigest([0xde, 0xad, 0xbe, 0xef]),
        finalized_root: Root::from([1; 32]),
        finalized_epoch: Epoch(10),
        head_root: Root::from([2; 32]),
        head_slot: Slot(330),
        earliest_available_slot: Slot(0),
    };
    let bob_status = Status {
        head_slot: Slot(331),
        ..alice_status
    };
    let request = alice
        .send_request(bob_id.clone(), Protocol::StatusV2, alice_status.encode())
        .await
        .expect("request queued");

    let (inbound, payload) = bob_events
        .wait_for(|event| match event {
            NetworkEvent::Request {
                peer,
                id,
                protocol: Protocol::StatusV2,
                payload,
            } if *peer == alice_id => Some((*id, payload.clone())),
            _ => None,
        })
        .await;
    assert_eq!(Status::decode(&payload), Ok(alice_status));
    bob.respond(
        inbound,
        vec![ResponseChunk::success(None, bob_status.encode())],
    )
    .await
    .expect("response queued");

    // Alice gets exactly one success chunk, then the end of the response.
    let chunk = alice_events
        .wait_for(|event| match event {
            NetworkEvent::Response {
                request: r, chunk, ..
            } if *r == request => Some(chunk.clone()),
            _ => None,
        })
        .await;
    assert_eq!(chunk.code, ResponseCode::Success);
    assert_eq!(Status::decode(&chunk.payload), Ok(bob_status));
    let responder = alice_events
        .wait_for(|event| match event {
            NetworkEvent::ResponseEnded { request: r, peer } if *r == request => Some(peer.clone()),
            _ => None,
        })
        .await;
    assert_eq!(responder, bob_id);

    // A malformed Ping (3 bytes instead of 8) is answered with InvalidRequest.
    let bad = alice
        .send_request(bob_id.clone(), Protocol::PingV1, vec![1, 2, 3])
        .await
        .expect("request queued");
    let chunk = alice_events
        .wait_for(|event| match event {
            NetworkEvent::Response { request, chunk, .. } if *request == bad => Some(chunk.clone()),
            _ => None,
        })
        .await;
    assert_eq!(chunk.code, ResponseCode::InvalidRequest);
}

/// Phase 4: identify reached bob, then alice disconnects.
async fn identify_and_disconnect(pair: &mut Pair) {
    let Pair {
        alice,
        bob,
        bob_events,
        ..
    } = pair;
    let alice_id = alice.local_peer().clone();
    let bob_id = bob.local_peer().clone();
    // Bob heard alice's identify message, bound to her proven identity.
    let info = bob_events
        .wait_for(|event| match event {
            NetworkEvent::PeerIdentified { peer, info } if *peer == alice_id => Some(info.clone()),
            _ => None,
        })
        .await;
    assert_eq!(PeerId::from_public_key(&info.public_key), alice_id);
    assert!(
        info.protocols
            .iter()
            .any(|p| p == Protocol::StatusV2.protocol_id())
    );

    // Alice disconnects; bob notices.
    alice
        .disconnect(bob_id.clone())
        .await
        .expect("disconnect queued");
    let gone = bob_events
        .wait_for(|event| match event {
            NetworkEvent::PeerDisconnected { peer } => Some(peer.clone()),
            _ => None,
        })
        .await;
    assert_eq!(gone, alice_id);
    alice.shutdown().await.expect("shutdown queued");
    bob.shutdown().await.expect("shutdown queued");
}
