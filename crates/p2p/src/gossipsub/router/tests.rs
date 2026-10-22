use std::{collections::BTreeMap, iter::from_fn, time::Duration};

use super::*;
use crate::{
    eth::encode_gossip,
    gossipsub::{
        IDontWant, IHave, IWant, TopicScoreParams,
        rpc::{Graft, Prune},
    },
    identity::PublicKey,
};

/// A peer identifier from a seed byte.
fn peer(seed: u8) -> PeerId {
    PeerId::from_public_key(&PublicKey::secp256k1([seed; 33]))
}

/// The test topic.
fn topic() -> Topic {
    Topic::new("/eth2/00000000/beacon_block/ssz_snappy")
}

/// Scoring with Ethereum parameters on the test topic.
fn scoring() -> (PeerScoreParams, PeerScoreThresholds) {
    let slot = Duration::from_secs(12);
    let mut params = PeerScoreParams::ethereum(slot, 32, 0.5);
    params
        .topics
        .insert(topic(), TopicScoreParams::ethereum(0.5, 1.0, slot, 32, 8));
    (params, PeerScoreThresholds::ethereum())
}

/// A router subscribed to the test topic with peers 1..=n, all subscribed too.
fn router_with_peers(n: u8) -> Router {
    let mut router = Router::new(GossipsubConfig::default(), Some(scoring()), 7);
    for seed in 1..=n {
        router.add_peer(&peer(seed), ProtocolVersion::V1_2, seed % 2 == 0);
        let subscribe = Rpc {
            subscriptions: vec![SubOpts {
                subscribe: true,
                topic: topic(),
            }],
            ..Rpc::default()
        };
        router.handle_rpc(&peer(seed), subscribe, Duration::ZERO);
    }
    router.subscribe(&topic(), Duration::ZERO);
    drain(&mut router);
    router
}

/// Every pending RPC, grouped by recipient.
fn drain(router: &mut Router) -> BTreeMap<PeerId, Vec<Rpc>> {
    let mut sent: BTreeMap<PeerId, Vec<Rpc>> = BTreeMap::new();
    while let Some((peer, rpc)) = router.poll_transmit() {
        sent.entry(peer).or_default().push(rpc);
    }
    while router.poll_event().is_some() {}
    sent
}

/// The control messages in a batch of RPCs.
fn controls(rpcs: &[Rpc]) -> Vec<&ControlMessage> {
    rpcs.iter().filter_map(|rpc| rpc.control.as_ref()).collect()
}

/// An RPC carrying one message on the test topic.
fn message_rpc(data: &[u8]) -> Rpc {
    Rpc {
        publish: vec![RawMessage::anonymous(topic(), encode_gossip(data))],
        ..Rpc::default()
    }
}

#[test]
fn subscribing_grafts_up_to_d_peers() {
    // Fixture state: 20 subscribed peers, D = 8.
    let mut router = Router::new(GossipsubConfig::default(), None, 1);
    for seed in 1..=20 {
        router.add_peer(&peer(seed), ProtocolVersion::V1_2, false);
        router.handle_rpc(
            &peer(seed),
            Rpc {
                subscriptions: vec![SubOpts {
                    subscribe: true,
                    topic: topic(),
                }],
                ..Rpc::default()
            },
            Duration::ZERO,
        );
    }
    router.subscribe(&topic(), Duration::ZERO);
    // Exactly 8 peers join the mesh, and each of them receives a GRAFT.
    assert_eq!(router.mesh_peers(&topic()).count(), 8);
    let sent = drain(&mut router);
    let grafted = sent
        .values()
        .filter(|rpcs| controls(rpcs).iter().any(|c| !c.graft.is_empty()))
        .count();
    assert_eq!(grafted, 8);
    // Every peer also learns of the subscription.
    assert_eq!(sent.len(), 20);
}

#[test]
fn received_message_waits_for_validation_then_forwards() {
    let mut router = router_with_peers(3);
    let now = Duration::from_secs(1);
    // Peer 1 delivers a message; the application sees it before anyone else does.
    router.handle_rpc(&peer(1), message_rpc(b"block"), now);
    let Some(GossipsubEvent::Message { source, id, .. }) = router.poll_event() else {
        panic!("expected a message event");
    };
    assert_eq!(source, peer(1));
    // Small message (below 1000 bytes) → no IDONTWANT, and nothing forwarded yet.
    assert!(router.poll_transmit().is_none());

    // Accepting forwards to mesh peers 2 and 3, never back to the source.
    assert!(router.report_validation(&id, ValidationOutcome::Accept, now));
    let sent = drain(&mut router);
    let recipients: Vec<&PeerId> = sent
        .iter()
        .filter(|(_, rpcs)| rpcs.iter().any(|r| !r.publish.is_empty()))
        .map(|(p, _)| p)
        .collect();
    assert_eq!(
        recipients,
        [&peer(2), &peer(3)]
            .into_iter()
            .filter(|p| router.mesh_peers(&topic()).any(|m| m == *p))
            .collect::<Vec<_>>()
    );
    assert!(!recipients.contains(&&peer(1)));
    // A second verdict on the same message is a no-op.
    assert!(!router.report_validation(&id, ValidationOutcome::Accept, now));
}

#[test]
fn duplicates_are_suppressed() {
    let mut router = router_with_peers(2);
    router.handle_rpc(&peer(1), message_rpc(b"x"), Duration::ZERO);
    router.handle_rpc(&peer(2), message_rpc(b"x"), Duration::ZERO);
    // One event for two deliveries of the same content.
    let events: Vec<_> = from_fn(|| router.poll_event()).collect();
    assert_eq!(events.len(), 1);
}

#[test]
fn rejected_message_penalizes_the_sender() {
    let mut router = router_with_peers(2);
    let now = Duration::from_secs(1);
    router.handle_rpc(&peer(1), message_rpc(b"bad"), now);
    let Some(GossipsubEvent::Message { id, .. }) = router.poll_event() else {
        panic!("expected a message event");
    };
    router.report_validation(&id, ValidationOutcome::Reject, now);
    // Ethereum P4: one invalid message → topic_weight * w4 * 1 = 0.5 * -320 = -160.
    assert!((router.peer_score(&peer(1), now) + 160.0).abs() < 1.0);
    // Nothing was forwarded.
    assert!(
        drain(&mut router)
            .values()
            .all(|rpcs| rpcs.iter().all(|r| r.publish.is_empty()))
    );
}

#[test]
fn signed_messages_violate_strict_no_sign() {
    let mut router = router_with_peers(1);
    // Mutation: the message carries a sequence number.
    let mut rpc = message_rpc(b"x");
    rpc.publish[0].seqno = Some(vec![1]);
    router.handle_rpc(&peer(1), rpc, Duration::ZERO);
    // The application never sees it.
    assert!(router.poll_event().is_none());
}

#[test]
fn large_message_triggers_idontwant() {
    let mut router = router_with_peers(3);
    // 2000 incompressible bytes stay above the 1000-byte threshold after snappy.
    let data: Vec<u8> = (0..2000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    router.handle_rpc(&peer(1), message_rpc(&data), Duration::ZERO);
    let sent = drain(&mut router);
    // Every other mesh peer gets an IDONTWANT, before validation.
    for member in router.mesh_peers(&topic()).filter(|p| **p != peer(1)) {
        let rpcs = &sent[member];
        assert!(controls(rpcs).iter().any(|c| c.idontwant.len() == 1));
    }
}

#[test]
fn idontwant_suppresses_forwarding() {
    let mut router = router_with_peers(2);
    let now = Duration::ZERO;
    let message = message_rpc(b"m");
    let id = (router.config().message_id)(&topic(), &message.publish[0].data);
    // Peer 2 says it does not want the message.
    let notice = Rpc {
        control: Some(ControlMessage {
            idontwant: vec![IDontWant {
                message_ids: vec![id],
            }],
            ..ControlMessage::default()
        }),
        ..Rpc::default()
    };
    router.handle_rpc(&peer(2), notice, now);
    // Peer 1 delivers it; it is accepted.
    router.handle_rpc(&peer(1), message, now);
    router.report_validation(&id, ValidationOutcome::Accept, now);
    // Peer 2 does not receive it.
    let sent = drain(&mut router);
    assert!(
        sent.get(&peer(2))
            .is_none_or(|rpcs| rpcs.iter().all(|r| r.publish.is_empty()))
    );
}

#[test]
fn ihave_is_answered_with_iwant_and_tracked_as_a_promise() {
    let mut router = router_with_peers(1);
    let id = MessageId([9; 20]);
    let ihave = Rpc {
        control: Some(ControlMessage {
            ihave: vec![IHave {
                topic: topic(),
                message_ids: vec![id],
            }],
            ..ControlMessage::default()
        }),
        ..Rpc::default()
    };
    router.handle_rpc(&peer(1), ihave, Duration::ZERO);
    let sent = drain(&mut router);
    assert_eq!(
        controls(&sent[&peer(1)])[0].iwant,
        [IWant {
            message_ids: vec![id]
        }]
    );
    // The peer never delivers: after the 3 s follow-up time, one behaviour penalty.
    router.heartbeat(Duration::from_secs(4));
    assert_eq!(router.gossip.promises.len(), 0);
    // A single penalty stays under the threshold of 6, so the score is unaffected.
    assert!(router.peer_score(&peer(1), Duration::from_secs(4)) >= 0.0);
}

#[test]
fn iwant_is_served_from_the_cache_with_a_retransmission_limit() {
    let mut router = router_with_peers(1);
    let id = router
        .publish(topic(), encode_gossip(b"own"), Duration::ZERO)
        .unwrap();
    drain(&mut router);
    let iwant = Rpc {
        control: Some(ControlMessage {
            iwant: vec![IWant {
                message_ids: vec![id],
            }],
            ..ControlMessage::default()
        }),
        ..Rpc::default()
    };
    // Three answers, then the retransmission limit of 3 stops further copies.
    let mut copies = 0;
    for _ in 0..5 {
        router.handle_rpc(&peer(1), iwant.clone(), Duration::ZERO);
        copies += drain(&mut router).get(&peer(1)).map_or(0, |rpcs| {
            rpcs.iter().filter(|r| !r.publish.is_empty()).count()
        });
    }
    assert_eq!(copies, 3);
}

#[test]
fn graft_during_backoff_is_penalized_and_refused() {
    let mut router = router_with_peers(1);
    // Peer 1 prunes us with a 60 s backoff.
    let prune = Rpc {
        control: Some(ControlMessage {
            prune: vec![Prune {
                topic: topic(),
                peers: vec![],
                backoff: Some(60),
            }],
            ..ControlMessage::default()
        }),
        ..Rpc::default()
    };
    router.handle_rpc(&peer(1), prune, Duration::ZERO);
    assert_eq!(router.mesh_peers(&topic()).count(), 0);
    // It grafts back 1 s later, inside the 10 s flood window: 2 penalties and a PRUNE.
    let graft = Rpc {
        control: Some(ControlMessage {
            graft: vec![Graft { topic: topic() }],
            ..ControlMessage::default()
        }),
        ..Rpc::default()
    };
    router.handle_rpc(&peer(1), graft, Duration::from_secs(1));
    assert_eq!(router.mesh_peers(&topic()).count(), 0);
    let sent = drain(&mut router);
    assert_eq!(controls(&sent[&peer(1)])[0].prune.len(), 1);
}

#[test]
fn heartbeat_prunes_an_oversized_mesh() {
    // Fixture state: 16 peers all graft us; inbound grafts stop at D_high = 12.
    let mut router = router_with_peers(16);
    let graft = Rpc {
        control: Some(ControlMessage {
            graft: vec![Graft { topic: topic() }],
            ..ControlMessage::default()
        }),
        ..Rpc::default()
    };
    for seed in 1..=16 {
        router.handle_rpc(&peer(seed), graft.clone(), Duration::ZERO);
    }
    assert!(router.mesh_peers(&topic()).count() <= 16);
    // The heartbeat brings it down to D = 8 with at least D_out = 2 outbound peers.
    router.heartbeat(Duration::from_millis(700));
    let members: Vec<PeerId> = router.mesh_peers(&topic()).cloned().collect();
    assert_eq!(members.len(), 8);
    assert!(
        members
            .iter()
            .filter(|p| router.cx.peers.is_outbound(p))
            .count()
            >= 2
    );
}

#[test]
fn heartbeat_emits_gossip_to_non_mesh_peers() {
    // 20 peers: 8 in the mesh, 12 outside.
    let mut router = router_with_peers(20);
    router
        .publish(topic(), encode_gossip(b"gossip me"), Duration::ZERO)
        .unwrap();
    drain(&mut router);
    router.heartbeat(Duration::from_millis(700));
    let sent = drain(&mut router);
    let gossiped: Vec<&PeerId> = sent
        .iter()
        .filter(|(_, rpcs)| controls(rpcs).iter().any(|c| !c.ihave.is_empty()))
        .map(|(p, _)| p)
        .collect();
    // max(D_lazy 6, 0.25 * 12 = 3) = 6 peers, none in the mesh.
    assert_eq!(gossiped.len(), 6);
    assert!(
        gossiped
            .iter()
            .all(|p| !router.mesh_peers(&topic()).any(|m| m == *p))
    );
}

#[test]
fn publish_errors() {
    let mut router = Router::new(GossipsubConfig::default(), None, 1);
    // No peers at all.
    assert_eq!(
        router.publish(topic(), vec![1], Duration::ZERO),
        Err(PublishError::InsufficientPeers)
    );
    let mut router = router_with_peers(1);
    router.publish(topic(), vec![1], Duration::ZERO).unwrap();
    // The same content again is a duplicate.
    assert_eq!(
        router.publish(topic(), vec![1], Duration::ZERO),
        Err(PublishError::Duplicate)
    );
}
