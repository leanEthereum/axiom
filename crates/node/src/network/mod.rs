//! The node on the network: gossip, requests, and sync over the libp2p stack.

mod discovery;
mod forks;
mod gossip;
mod identity;
mod requests;
mod responder;
mod server;
mod subnets;
mod sync;
mod topics;

use std::{
    collections::BTreeSet,
    future::pending,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axiom_das::NodeId;
use axiom_discv5::driver::Discv5Events;
use axiom_p2p::{
    Multiaddr, PeerId,
    eth::{
        GossipKind, GossipTopic,
        reqresp::{Protocol, ResponseCode, Status, StatusV1},
    },
    swarm::{NetworkEvent, NetworkEvents, NetworkHandle, RequestId},
};
use axiom_ssz::Ssz;
use axiom_telemetry::NodeMetrics;
use axiom_types::{ChainConfig, ColumnIndex, Preset, Root, Slot, SlotClock};
use tokio::{
    sync::{Semaphore, mpsc::UnboundedReceiver},
    task, time,
};
use tracing::{debug, info, warn};

pub use self::{discovery::DiscoverySettings, identity::NodeKey};
pub(crate) use self::{
    discovery::{Discovery, LocalRecord},
    server::LocalMetadata,
    subnets::AttestationSubnets,
};
use self::{
    forks::ForkDigests,
    gossip::GossipHandler,
    server::RequestServer,
    sync::{BatchOutcome, RangeSync},
    topics::Subscriptions,
};
use crate::{ChainHandle, Clock, ExecutionLayer, NodeError, race::Either};

/// Who the node is on the network, and what it custodies.
#[derive(Clone, Debug)]
pub(crate) struct NetworkIdentity {
    /// The discovery identifier, which fixes custody and attestation subnets.
    pub(crate) node_id: NodeId,
    /// Custody groups the node keeps and advertises.
    pub(crate) custody_group_count: u64,
    /// Peers to dial at startup.
    pub(crate) boot_nodes: Vec<Multiaddr>,
}

impl NetworkIdentity {
    /// The columns the node samples: those of its custody groups, and more if sampling needs it.
    ///
    /// A node samples at least the spec's samples per slot, whatever its custody.
    /// The draw is a prefix: the first groups drawn are exactly the custody groups.
    /// See `get_custody_groups` and "Custody sampling" in the Fulu DAS core spec.
    pub(crate) fn sampling_columns<P: Preset>(
        &self,
        config: &ChainConfig,
    ) -> Result<Vec<ColumnIndex>, NodeError> {
        let sampling_size = self.custody_group_count.max(config.samples_per_slot);
        let groups = self
            .node_id
            .custody_groups(sampling_size, config)
            .map_err(NodeError::Custody)?;
        let mut columns = Vec::new();
        for group in groups {
            columns.extend(group.columns::<P>(config).map_err(NodeError::Custody)?);
        }
        Ok(columns)
    }
}

/// The node's network service.
///
/// # Overview
///
/// One loop drains network events in order, and wakes once a slot for upkeep.
/// Gossip runs in spawned tasks, so a slow engine call never stalls the loop.
///
/// Each network event goes to one place:
///
/// - A gossip message goes to a spawned task that validates, reports, and imports it.
/// - A request goes to the server, which answers from the chain.
/// - A response goes to sync, which collects the batch.
/// - A new peer gets a status handshake, then goes to sync.
///
/// Every slot, the loop does two chores:
///
/// - It rotates topics on a fork or a subnet change.
/// - It asks peers for their status, every slot while behind and every epoch otherwise.
#[derive(Debug)]
pub(crate) struct NetworkService<P: Preset> {
    /// The network.
    network: NetworkHandle,
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The wall clock.
    clock: Arc<dyn Clock>,
    /// Genesis and the slot length.
    slots: SlotClock,
    /// Gossip validation and import.
    gossip: GossipHandler<P>,
    /// Answers to peers.
    server: Arc<RequestServer<P>>,
    /// Range sync.
    sync: RangeSync<P>,
    /// Processed batches, until the run loop takes them.
    sync_outcomes: Option<UnboundedReceiver<BatchOutcome>>,
    /// Inbound requests answered at once.
    requests: Arc<Semaphore>,
    /// Gossip messages in validation at once.
    validations: Arc<Semaphore>,
    /// Topics joined, and how they change.
    subscriptions: Subscriptions,
    /// What peers are told about this node.
    metadata: Arc<LocalMetadata>,
    /// Peers with a status request in flight.
    handshakes: Vec<(RequestId, PeerId)>,
    /// Connected peers, for the peer count and status refreshes.
    peers: BTreeSet<PeerId>,
    /// Peer counts and gossip outcomes.
    metrics: NodeMetrics,
    /// Peer discovery, when enabled.
    discovery: Option<Discovery>,
    /// Peers dialed at startup, and again whenever the node is alone.
    boot_nodes: Vec<Multiaddr>,
    /// Discovery's events, until the run loop takes them.
    discovery_events: Option<Discv5Events>,
}

/// How the node presents itself on the network, as the identity route reports it.
#[derive(Debug)]
pub(crate) struct NodeIdentity {
    /// The libp2p peer identifier.
    pub(crate) peer_id: String,
    /// The discovery record, in text form.
    pub(crate) enr: Option<String>,
    /// The libp2p listen address.
    pub(crate) p2p_address: String,
    /// The discovery UDP address.
    pub(crate) discovery_address: Option<String>,
    /// The metadata peers fetch.
    pub(crate) metadata: Arc<LocalMetadata>,
}

/// Inbound requests answered at once.
///
/// Each answer reads the chain and may encode megabytes, so the count is kept modest.
const MAX_CONCURRENT_REQUESTS: usize = 32;

/// Gossip messages validated at once.
///
/// Enough to keep the chain thread busy without letting a flood pile up tasks.
const MAX_CONCURRENT_VALIDATIONS: usize = 256;

/// Peers the node keeps looking for until it has them.
///
/// A mesh wants 6 to 12 peers, per the phase0 gossipsub parameters.
/// Sixty-four peers fill every topic's mesh and leave spares.
const TARGET_PEERS: usize = 64;

impl<P: Preset> NetworkService<P> {
    /// Joins the network: subscribes to the topics and dials the boot nodes.
    ///
    /// # Arguments
    ///
    /// - `network`: the started libp2p stack.
    /// - `identity`: the node identifier, custody, and boot nodes.
    /// - `chain`: the chain thread.
    /// - `setup`: the node's other services and chain facts.
    pub(crate) async fn start(
        network: NetworkHandle,
        identity: &NetworkIdentity,
        chain: ChainHandle<P>,
        setup: NetworkSetup,
    ) -> Self {
        let NetworkSetup {
            config,
            genesis_validators_root,
            custody,
            slots,
            execution,
            clock,
            metrics,
            discovery,
        } = setup;
        let forks = Arc::new(ForkDigests::new(&config, genesis_validators_root));
        let (discovery, discovery_events) = discovery
            .map_or((None, None), |(discovery, events)| {
                (Some(discovery), Some(events))
            });
        let (sync, sync_outcomes) = RangeSync::new(
            chain.clone(),
            Arc::clone(&execution),
            network.clone(),
            config.clone(),
            Arc::clone(&forks),
        );
        let metadata = Arc::new(LocalMetadata {
            seq_number: AtomicU64::new(0),
            attnets: AtomicU64::new(0),
            custody_group_count: identity.custody_group_count,
        });
        let mut service = Self {
            gossip: GossipHandler::new(
                chain.clone(),
                Arc::clone(&execution),
                Arc::clone(&clock),
                network.clone(),
                metrics.clone(),
                Arc::clone(&forks),
            ),
            server: Arc::new(RequestServer::new(
                chain.clone(),
                network.clone(),
                Arc::clone(&metadata),
            )),
            sync,
            sync_outcomes: Some(sync_outcomes),
            requests: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
            validations: Arc::new(Semaphore::new(MAX_CONCURRENT_VALIDATIONS)),
            subscriptions: Subscriptions::new(
                identity.node_id,
                config,
                genesis_validators_root,
                &custody,
            ),
            network,
            chain,
            clock,
            slots,
            metadata,
            handshakes: Vec::new(),
            peers: BTreeSet::new(),
            metrics,
            discovery,
            discovery_events,
            boot_nodes: identity.boot_nodes.clone(),
        };

        // The first upkeep joins the topics of the current epoch and dials the boot nodes.
        service.maintain().await;
        info!(
            peer = %service.network.local_peer(),
            address = %service.network.listen_addr(),
            custody_columns = custody.len(),
            "network started"
        );
        service
    }

    /// How the node presents itself, for the identity route.
    pub(crate) fn identity(&self) -> NodeIdentity {
        NodeIdentity {
            peer_id: self.network.local_peer().to_string(),
            enr: self
                .discovery
                .as_ref()
                .map(|discovery| discovery.enr().to_string()),
            p2p_address: self.network.listen_addr().to_string(),
            discovery_address: self.discovery.as_ref().map(|discovery| {
                // The multiaddr form of a UDP socket, as the identity route lists it.
                let address = discovery.local_addr();
                let family = if address.is_ipv4() { "ip4" } else { "ip6" };
                format!("/{family}/{}/udp/{}", address.ip(), address.port())
            }),
            metadata: Arc::clone(&self.metadata),
        }
    }

    /// Handles network and discovery events until the network stops, with upkeep once a slot.
    pub(crate) async fn run(mut self, mut events: NetworkEvents) {
        let mut upkeep = time::interval(Duration::from_millis(self.slots.slot_duration_ms()));
        let mut discovered = self.discovery_events.take();
        let mut outcomes = self.sync_outcomes.take();
        loop {
            // Without discovery, its branch simply never completes.
            let found = async {
                match &mut discovered {
                    Some(stream) => stream.next().await,
                    None => pending().await,
                }
            };
            // Processed sync batches come back through their own channel.
            let processed = async {
                match &mut outcomes {
                    Some(receiver) => receiver.recv().await,
                    None => pending().await,
                }
            };
            let others = Either::race(found, Either::race(processed, upkeep.tick()));
            match Either::race(events.next(), others).await {
                Either::Left(Some(event)) => self.handle(event).await,
                Either::Left(None) => break,
                Either::Right(Either::Left(Some(event))) => {
                    let addresses = self
                        .discovery
                        .as_mut()
                        .map(|discovery| discovery.on_event(event))
                        .unwrap_or_default();
                    for (peer, address) in addresses {
                        // A peer already connected needs no second connection.
                        if self.peers.contains(&peer) {
                            continue;
                        }
                        if let Err(error) = self.network.dial(address.clone()).await {
                            debug!(%error, %address, "could not dial a discovered peer");
                        }
                    }
                }
                // Discovery stopped: carry on with the peers already known.
                Either::Right(Either::Left(None)) => discovered = None,
                Either::Right(Either::Right(Either::Left(Some(outcome)))) => {
                    self.sync.on_outcome(outcome).await;
                }
                Either::Right(Either::Right(Either::Left(None))) => outcomes = None,
                Either::Right(Either::Right(Either::Right(_))) => self.maintain().await,
            }
        }
        if let Some(discovery) = &self.discovery {
            discovery.shutdown();
        }
        info!("network stopped");
    }

    /// Rotates topics and refreshes peer statuses.
    async fn maintain(&mut self) {
        let slot = self.slots.slot_at(self.clock.now_ms());
        let epoch = slot.epoch::<P>();
        let Ok((head, digest)) = self
            .chain
            .run(move |chain| (chain.head().slot, chain.fork_digest(epoch)))
            .await
        else {
            return;
        };

        // Join and leave topics as forks and subnet rotations require.
        let change = self.subscriptions.update::<P>(epoch);
        for topic in &change.join {
            if let Err(error) = self.network.subscribe(topic.topic()).await {
                warn!(%error, %topic, "could not subscribe");
            }
        }
        for topic in &change.leave {
            if let Err(error) = self.network.unsubscribe(topic.topic()).await {
                warn!(%error, %topic, "could not unsubscribe");
            }
        }
        // New attestation subnets are new metadata: bump the sequence so peers refetch it.
        if self
            .metadata
            .attnets
            .swap(change.attnets, Ordering::Relaxed)
            != change.attnets
        {
            self.metadata.seq_number.fetch_add(1, Ordering::Relaxed);
        }

        self.publish_light_client().await;

        // Alone, the node dials its boot nodes again: they may have been down before.
        if self.peers.is_empty() {
            for address in &self.boot_nodes {
                if let Err(error) = self.network.dial(address.clone()).await {
                    warn!(%error, %address, "could not dial boot node");
                }
            }
        }

        // Too few peers: look for more on this fork.
        if self.peers.len() < TARGET_PEERS
            && let Some(discovery) = &mut self.discovery
        {
            discovery.search(digest).await;
        }

        // Peers' heads move every slot; ask again often while behind, rarely once caught up.
        let behind = slot.0.saturating_sub(head.0) > 1;
        if behind || slot.index_in_epoch::<P>() == 0 {
            let peers: Vec<PeerId> = self.peers.iter().cloned().collect();
            for peer in peers {
                self.send_status(peer).await;
            }
        }
    }

    /// Gossips the light client updates this node derived, once each, when they are due.
    ///
    /// The checks a peer's update meets decide.
    /// It must advance, and its block must have had time to spread.
    async fn publish_light_client(&self) {
        let now = self.clock.now_ms();
        let Ok(updates) = self
            .chain
            .run(move |chain| {
                let config = chain.config().clone();
                let clock = chain.store().slot_clock();
                let mut updates = Vec::new();
                let server = chain.light_client();
                let finality = server.latest_finality_update().cloned();
                let optimistic = server.latest_optimistic_update().cloned();
                let server = chain.light_client_mut();
                if let Some(update) = finality
                    && server
                        .forward_finality_update(&update, &config, clock, now)
                        .is_ok()
                {
                    updates.push((
                        GossipKind::LightClientFinalityUpdate,
                        update.context_slot(),
                        update.encode(),
                    ));
                }
                if let Some(update) = optimistic
                    && server
                        .forward_optimistic_update(&update, &config, clock, now)
                        .is_ok()
                {
                    updates.push((
                        GossipKind::LightClientOptimisticUpdate,
                        update.context_slot(),
                        update.encode(),
                    ));
                }
                updates
                    .into_iter()
                    .map(|(kind, slot, bytes)| {
                        let fork_digest = chain.fork_digest(slot.epoch::<P>());
                        (GossipTopic { fork_digest, kind }, bytes)
                    })
                    .collect::<Vec<_>>()
            })
            .await
        else {
            return;
        };
        for (topic, bytes) in updates {
            if let Err(error) = self.network.publish(topic.topic(), bytes).await {
                debug!(%error, %topic, "could not publish a light client update");
            }
        }
    }

    /// Handles one event.
    async fn handle(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::PeerConnected { peer, outbound, .. } => {
                self.peers.insert(peer.clone());
                self.metrics.peers.set_count(self.peers.len() as u64);
                // The dialer opens the handshake; the listener answers it.
                if outbound {
                    self.send_status(peer).await;
                }
            }
            NetworkEvent::PeerDisconnected { peer } => {
                self.peers.remove(&peer);
                self.metrics.peers.set_count(self.peers.len() as u64);
                self.sync.on_disconnect(&peer).await;
            }
            NetworkEvent::GossipMessage {
                id, topic, data, ..
            } => {
                // Validation is bounded.
                // Past the limit, the loop waits and the swarm's queue absorbs the rest.
                let Ok(permit) = Arc::clone(&self.validations).acquire_owned().await else {
                    return;
                };
                let gossip = self.gossip.clone();
                task::spawn(async move {
                    gossip.handle(id, &topic, data).await;
                    drop(permit);
                });
            }
            NetworkEvent::Request {
                peer,
                id,
                protocol,
                payload,
            } => {
                // An inbound status is also the peer's half of the handshake.
                if let Some(status) = Self::inbound_status(protocol, &payload) {
                    self.sync.on_status(peer.clone(), status).await;
                }
                // Answers run in their own tasks, so one slow query never blocks the loop.
                let Ok(permit) = Arc::clone(&self.requests).acquire_owned().await else {
                    return;
                };
                let server = Arc::clone(&self.server);
                task::spawn(async move {
                    server.answer(&peer, id, protocol, payload).await;
                    drop(permit);
                });
            }
            NetworkEvent::Response {
                request,
                peer,
                chunk,
            } => {
                if let Some(position) = self.handshakes.iter().position(|(id, _)| *id == request) {
                    self.handshakes.swap_remove(position);
                    match Status::decode(&chunk.payload) {
                        Ok(status) if chunk.code == ResponseCode::Success => {
                            self.sync.on_status(peer, status).await;
                        }
                        _ => debug!(%peer, "peer sent no usable status"),
                    }
                } else if self.sync.owns(request) {
                    self.sync.on_chunk(request, &chunk);
                }
            }
            NetworkEvent::ResponseEnded { request, .. } => self.sync.on_end(request).await,
            NetworkEvent::RequestFailed {
                request,
                peer,
                error,
            } => {
                debug!(%peer, %error, "request failed");
                self.handshakes.retain(|(id, _)| *id != request);
                self.sync.on_failure(request).await;
            }
            NetworkEvent::ConnectionFailed { address, error } => {
                debug!(%address, %error, "connection failed");
            }
            _ => {}
        }
    }

    /// The status in an inbound status request, of either version.
    ///
    /// A first-version status names no earliest slot, so it reads as genesis.
    fn inbound_status(protocol: Protocol, payload: &[u8]) -> Option<Status> {
        match protocol {
            Protocol::StatusV2 => Status::decode(payload).ok(),
            Protocol::StatusV1 => StatusV1::decode(payload).ok().map(|status| Status {
                fork_digest: status.fork_digest,
                finalized_root: status.finalized_root,
                finalized_epoch: status.finalized_epoch,
                head_root: status.head_root,
                head_slot: status.head_slot,
                earliest_available_slot: Slot::GENESIS,
            }),
            _ => None,
        }
    }

    /// Opens the status handshake with a peer.
    ///
    /// The second version goes out whatever the fork: every current client answers it.
    async fn send_status(&mut self, peer: PeerId) {
        let status = match self.server.status().await {
            Ok(status) => status,
            Err(error) => return warn!(%error, "no status to send"),
        };
        match self
            .network
            .send_request(peer.clone(), Protocol::StatusV2, status.encode())
            .await
        {
            Ok(request) => self.handshakes.push((request, peer)),
            Err(error) => warn!(%error, "could not send status"),
        }
    }
}

/// The node's services and chain facts the network service starts from.
#[derive(Debug)]
pub(crate) struct NetworkSetup {
    /// The chain configuration.
    pub(crate) config: ChainConfig,
    /// The root that, with each fork version, gives the fork digests.
    pub(crate) genesis_validators_root: Root,
    /// The node's custody columns.
    pub(crate) custody: BTreeSet<ColumnIndex>,
    /// Genesis and the slot length, never zero.
    pub(crate) slots: SlotClock,
    /// The engine.
    pub(crate) execution: Arc<ExecutionLayer>,
    /// The wall clock.
    pub(crate) clock: Arc<dyn Clock>,
    /// The node's metrics.
    pub(crate) metrics: NodeMetrics,
    /// Peer discovery and its events, when enabled.
    pub(crate) discovery: Option<(Discovery, Discv5Events)>,
}
