//! The node on the network: gossip, requests, and sync over the libp2p stack.

mod discovery;
mod gossip;
mod identity;
mod requests;
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
    eth::reqresp::{Protocol, ResponseCode, Status},
    swarm::{NetworkEvent, NetworkEvents, NetworkHandle, RequestId},
};
use axiom_ssz::Ssz;
use axiom_telemetry::NodeMetrics;
use axiom_types::{ChainConfig, ColumnIndex, Preset, Slot};
use tokio::{task, time};
use tracing::{debug, info, warn};

pub use self::{discovery::DiscoverySettings, identity::NodeKey};
pub(crate) use self::{
    discovery::{Discovery, LocalRecord},
    server::LocalMetadata,
    subnets::AttestationSubnets,
};
use self::{gossip::GossipHandler, server::RequestServer, sync::RangeSync, topics::Subscriptions};
use crate::{ChainHandle, Clock, ExecutionLayer, race::Either};

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

/// The node's network service.
///
/// # Overview
///
/// One loop drains network events in order, and wakes once a slot for upkeep.
/// Gossip runs in spawned tasks, so a slow engine call never stalls the loop.
///
/// ```text
///     network events ──┬── gossip message ──> spawned: validate, report, import
///                      ├── request ─────────> server: answer from the chain
///                      ├── response ────────> sync: collect the batch
///                      └── peer connected ──> status handshake ──> sync
///
///     every slot ──> rotate topics on a fork or a subnet change
///                ──> ask peers for their status: every slot while behind, every epoch otherwise
/// ```
#[derive(Debug)]
pub(crate) struct NetworkService<P: Preset> {
    /// The network.
    network: NetworkHandle,
    /// The chain thread.
    chain: ChainHandle<P>,
    /// The wall clock.
    clock: Arc<dyn Clock>,
    /// Genesis, in milliseconds since the Unix epoch.
    genesis_time_ms: u64,
    /// Slot length in milliseconds.
    slot_ms: u64,
    /// Gossip validation and import.
    gossip: GossipHandler<P>,
    /// Answers to peers.
    server: RequestServer<P>,
    /// Range sync.
    sync: RangeSync<P>,
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

/// Peers the node keeps looking for until it has them.
///
/// Enough to fill every gossip mesh with spares, as lighthouse aims for by default.
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
            custody,
            genesis_time_ms,
            execution,
            clock,
            metrics,
            discovery,
        } = setup;
        let (discovery, discovery_events) = discovery
            .map_or((None, None), |(discovery, events)| {
                (Some(discovery), Some(events))
            });
        let slot_ms = config.slot_duration_ms;
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
            ),
            server: RequestServer::new(chain.clone(), network.clone(), Arc::clone(&metadata)),
            sync: RangeSync::new(chain.clone(), execution, network.clone()),
            subscriptions: Subscriptions::new(identity.node_id, config, &custody),
            network,
            chain,
            clock,
            genesis_time_ms,
            slot_ms,
            metadata,
            handshakes: Vec::new(),
            peers: BTreeSet::new(),
            metrics,
            discovery,
            discovery_events,
        };

        // The first upkeep joins the topics of the current epoch.
        service.maintain().await;
        for address in &identity.boot_nodes {
            if let Err(error) = service.network.dial(address.clone()).await {
                warn!(%error, %address, "could not dial boot node");
            }
        }
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
        let mut upkeep = time::interval(Duration::from_millis(self.slot_ms.max(1)));
        let mut discovered = self.discovery_events.take();
        loop {
            // Without discovery, its branch simply never completes.
            let found = async {
                match &mut discovered {
                    Some(stream) => stream.next().await,
                    None => pending().await,
                }
            };
            match Either::race(events.next(), Either::race(found, upkeep.tick())).await {
                Either::Left(Some(event)) => self.handle(event).await,
                Either::Left(None) => break,
                Either::Right(Either::Left(Some(event))) => {
                    let addresses = self
                        .discovery
                        .as_mut()
                        .map(|discovery| discovery.on_event(event))
                        .unwrap_or_default();
                    for address in addresses {
                        if let Err(error) = self.network.dial(address.clone()).await {
                            debug!(%error, %address, "could not dial a discovered peer");
                        }
                    }
                }
                // Discovery stopped: carry on with the peers already known.
                Either::Right(Either::Left(None)) => discovered = None,
                Either::Right(Either::Right(_)) => self.maintain().await,
            }
        }
        if let Some(discovery) = &self.discovery {
            discovery.shutdown();
        }
        info!("network stopped");
    }

    /// Rotates topics and refreshes peer statuses.
    async fn maintain(&mut self) {
        let elapsed = self.clock.now_ms().saturating_sub(self.genesis_time_ms);
        let slot = Slot(elapsed / self.slot_ms.max(1));
        let epoch = slot.epoch::<P>();
        let Ok((head, digest)) = self
            .chain
            .run(move |chain| (chain.head().slot, chain.fork_digest(epoch)))
            .await
        else {
            return;
        };

        // Join and leave topics as forks and subnet rotations require.
        let change = self.subscriptions.update::<P>(epoch, digest);
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
                let gossip = self.gossip.clone();
                task::spawn(async move { gossip.handle(id, &topic, data).await });
            }
            NetworkEvent::Request {
                peer,
                id,
                protocol,
                payload,
            } => {
                // An inbound status is also the peer's half of the handshake.
                if protocol == Protocol::StatusV2
                    && let Ok(status) = Status::decode(&payload)
                {
                    self.sync.on_status(peer.clone(), status).await;
                }
                self.server.answer(&peer, id, protocol, payload).await;
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

    /// Opens the status handshake with a peer.
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
    /// The node's custody columns.
    pub(crate) custody: BTreeSet<ColumnIndex>,
    /// Genesis, in milliseconds since the Unix epoch.
    pub(crate) genesis_time_ms: u64,
    /// The engine.
    pub(crate) execution: Arc<ExecutionLayer>,
    /// The wall clock.
    pub(crate) clock: Arc<dyn Clock>,
    /// The node's metrics.
    pub(crate) metrics: NodeMetrics,
    /// Peer discovery and its events, when enabled.
    pub(crate) discovery: Option<(Discovery, Discv5Events)>,
}
