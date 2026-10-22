//! The flooding policy over TCP: a peer that fills its share of the event queue is cut.

use std::time::Duration;

use axiom_p2p::{
    Keypair,
    eth::{GossipKind, GossipTopic},
    gossipsub::PublishError,
    multiaddr::Protocol as Layer,
    swarm::{self, EventLimits, NetworkConfig, NetworkEvent, NetworkEvents},
};
use axiom_types::ForkDigest;
use tokio::{
    runtime::Builder,
    time::{sleep, timeout},
};

/// Waits for the first event a filter accepts, discarding the others.
async fn wait_for<T>(events: &mut NetworkEvents, filter: impl Fn(&NetworkEvent) -> Option<T>) -> T {
    loop {
        let event = events.next().await.expect("network still running");
        if let Some(found) = filter(&event) {
            return found;
        }
    }
}

#[test]
fn flooding_peer_is_disconnected() {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds");
    runtime.block_on(async {
        timeout(Duration::from_secs(20), scenario())
            .await
            .expect("scenario completes in time");
    });
}

/// Alice publishes four blocks to a bob who reads nothing, with a share of two events per peer.
async fn scenario() {
    let alice_key = Keypair::from_secret_bytes(&[1; 32]).expect("valid scalar");
    let bob_key = Keypair::from_secret_bytes(&[2; 32]).expect("valid scalar");
    let (alice, mut alice_events) = swarm::start(NetworkConfig::new(alice_key).expect("entropy"))
        .await
        .expect("listener binds");
    // Fixture state: bob queues at most 2 traffic events per peer, 100 in all.
    let mut bob_config = NetworkConfig::new(bob_key).expect("entropy");
    bob_config.event_limits = EventLimits {
        total: 100,
        per_peer: 2,
    };
    let (bob, mut bob_events) = swarm::start(bob_config).await.expect("listener binds");
    let alice_id = alice.local_peer().clone();
    let bob_id = bob.local_peer().clone();

    // Phase 1: connect, and both join one topic.
    alice
        .dial(bob.listen_addr().clone().with(Layer::P2p(bob_id.clone())))
        .await
        .expect("dial queued");
    let connected = |event: &NetworkEvent| match event {
        NetworkEvent::PeerConnected { peer, .. } => Some(peer.clone()),
        _ => None,
    };
    assert_eq!(wait_for(&mut alice_events, connected).await, bob_id);
    assert_eq!(wait_for(&mut bob_events, connected).await, alice_id);
    let topic = GossipTopic {
        fork_digest: ForkDigest([1, 2, 3, 4]),
        kind: GossipKind::BeaconBlock,
    }
    .topic();
    alice.subscribe(topic.clone()).await.expect("subscribed");
    bob.subscribe(topic.clone()).await.expect("subscribed");

    // Phase 2: four distinct blocks; the first waits until alice knows bob's subscription.
    for index in 0u8..4 {
        let block = vec![index; 100];
        loop {
            match alice
                .publish(topic.clone(), block.clone())
                .await
                .expect("swarm running")
            {
                Ok(_) => break,
                Err(PublishError::InsufficientPeers { .. }) => {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("publish failed: {error}"),
            }
        }
    }

    // Phase 3: bob finds blocks 0 and 1, then alice's disconnection; blocks 2 and 3 never surface.
    let mut seen = Vec::new();
    loop {
        match bob_events.next().await.expect("network still running") {
            NetworkEvent::GossipMessage { data, source, .. } => {
                assert_eq!(source, alice_id);
                seen.push(data[0]);
            }
            NetworkEvent::PeerDisconnected { peer } => {
                assert_eq!(peer, alice_id);
                break;
            }
            _ => {}
        }
    }
    assert_eq!(seen, [0, 1]);

    // Alice sees bob go.
    let disconnected = |event: &NetworkEvent| match event {
        NetworkEvent::PeerDisconnected { peer } => Some(peer.clone()),
        _ => None,
    };
    assert_eq!(wait_for(&mut alice_events, disconnected).await, bob_id);
}
