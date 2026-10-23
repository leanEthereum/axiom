//! The node on the network: gossip, requests, and sync over the libp2p stack.

mod discovery;
mod engine_blobs;
mod forks;
mod gossip;
mod handshake;
mod identity;
mod nat;
mod peers;
mod record;
mod requests;
mod responder;
mod server;
mod subnets;
mod sync;
mod topics;

use std::{
    collections::{BTreeSet, HashMap},
    future::pending,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use axiom_das::NodeId;
use axiom_discv5::{driver::Discv5Events, service::EnrFilter};
use axiom_p2p::{
    Multiaddr, PeerId,
    eth::{
        GossipKind, GossipTopic,
        reqresp::{GoodbyeReason, Protocol, ResponseChunk, ResponseCode, StatusVersion},
    },
    swarm::{NetworkEvent, NetworkEvents, NetworkHandle, RequestError, RequestId},
};
use axiom_telemetry::NodeMetrics;
use axiom_types::{ChainConfig, ColumnIndex, ForkDigest, Preset, Root, SlotClock};
use tokio::{
    sync::{Semaphore, mpsc::UnboundedReceiver, watch},
    task, time,
};
use tracing::{debug, info, warn};

pub use self::{discovery::DiscoverySettings, identity::NodeKey, nat::PortMappingSettings};
pub(crate) use self::{
    discovery::{DialPlan, Discovery, RecordSetup},
    forks::ForkDigests,
    nat::NatMetrics,
    peers::{PeerLimits, PeerMetrics, PeerRecord},
    server::LocalMetadata,
    subnets::AttestationSubnets,
};
use self::{
    gossip::GossipHandler,
    handshake::Handshakes,
    peers::{PeerAction, PeerBook, PeerManager, PeerSubnets},
    server::RequestServer,
    sync::{
        BackfillOutcome, BackfillPacer, BackfillSync, BatchOutcome, BlockLookups, LookupEvent,
        RangeSync,
    },
    topics::Subscriptions,
};
use crate::{ChainHandle, Clock, EventSender, ExecutionLayer, NodeError, race::Either};

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
    /// Backfill below the stored history.
    backfill: BackfillSync<P>,
    /// Processed backfill batches, until the run loop takes them.
    backfill_outcomes: Option<UnboundedReceiver<BackfillOutcome>>,
    /// Blocks fetched by root for gossip that named them.
    lookups: BlockLookups<P>,
    /// Missing blocks and processed lookups, until the run loop takes them.
    lookup_events: Option<UnboundedReceiver<LookupEvent<P>>>,
    /// Inbound requests answered at once.
    requests: Arc<Semaphore>,
    /// Gossip messages in validation at once.
    validations: Arc<Semaphore>,
    /// Topics joined, and how they change.
    subscriptions: Subscriptions,
    /// What peers are told about this node.
    metadata: Arc<LocalMetadata>,
    /// Status requests in flight, and the version each peer speaks.
    handshakes: Handshakes,
    /// Connected peers and the rules that shape the set.
    peers: PeerManager,
    /// Peer management metrics.
    peer_metrics: PeerMetrics,
    /// Pings in flight.
    pings: HashMap<RequestId, PeerId>,
    /// Goodbye requests in flight; each peer is disconnected once its goodbye is done.
    goodbyes: HashMap<RequestId, PeerId>,
    /// Metadata requests in flight, with the version asked.
    metadata_requests: HashMap<RequestId, (PeerId, Protocol)>,
    /// The chain configuration, for subnet lookups.
    config: ChainConfig,
    /// Which starved subnet the next lookup serves, rotating.
    subnet_turn: usize,
    /// Peers met, published for the node routes.
    peer_book: PeerBook,
    /// A reader of the published peers, handed to the identity.
    peer_reader: watch::Receiver<Arc<Vec<PeerRecord>>>,
    /// Peer counts and gossip outcomes.
    metrics: NodeMetrics,
    /// Peer discovery, when enabled.
    discovery: Option<Discovery>,
    /// Peers dialed at startup, and again whenever the node is alone.
    boot_nodes: Vec<Multiaddr>,
    /// Discovery's events, until the run loop takes them.
    discovery_events: Option<Discv5Events>,
    /// TCP addresses to try when the QUIC dial to the same peer fails, by QUIC address.
    fallbacks: HashMap<Multiaddr, Multiaddr>,
}

/// How the node presents itself on the network, as the identity route reports it.
#[derive(Debug)]
pub(crate) struct NodeIdentity {
    /// The libp2p peer identifier.
    pub(crate) peer_id: String,
    /// The discovery record in text form, kept current as it changes.
    pub(crate) enr: Option<watch::Receiver<String>>,
    /// The libp2p listen address.
    pub(crate) p2p_address: String,
    /// The discovery UDP address.
    pub(crate) discovery_address: Option<String>,
    /// The metadata peers fetch.
    pub(crate) metadata: Arc<LocalMetadata>,
    /// The peers met, as the network task last published them.
    pub(crate) peers: watch::Receiver<Arc<Vec<PeerRecord>>>,
}

/// Inbound requests answered at once.
///
/// Each answer reads the chain and may encode megabytes, so the count is kept modest.
const MAX_CONCURRENT_REQUESTS: usize = 32;

/// Gossip messages validated at once.
///
/// Enough to keep the chain thread busy without letting a flood pile up tasks.
const MAX_CONCURRENT_VALIDATIONS: usize = 256;

/// Dials awaiting their outcome whose fallback address is remembered.
///
/// A dial reports success or failure within the handshake timeout, so a few hundred cover a lookup's worth.
const MAX_PENDING_FALLBACKS: usize = 256;

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
            peer_metrics,
            peer_limits,
            discovery,
            events,
            subscribe_all_subnets,
            backfill_rate_limiting,
            get_blobs,
        } = setup;
        let forks = Arc::new(ForkDigests::new(&config, genesis_validators_root));
        let (discovery, discovery_events) = discovery.unzip();
        let (sync, sync_outcomes) = RangeSync::new(
            chain.clone(),
            Arc::clone(&execution),
            network.clone(),
            config.clone(),
            Arc::clone(&forks),
        );
        let pacer = backfill_rate_limiting.then(|| BackfillPacer::new(Arc::clone(&clock), slots));
        let (backfill, backfill_outcomes) = BackfillSync::new(
            chain.clone(),
            network.clone(),
            config.clone(),
            Arc::clone(&forks),
            pacer,
        );
        let (lookups, lookup_events) = sync.lookups(metrics.clone());
        let metadata = Arc::new(LocalMetadata::new(identity.custody_group_count));
        let (peer_book, peer_reader) = PeerBook::new();
        let mut service = Self {
            gossip: GossipHandler::new(
                chain.clone(),
                Arc::clone(&execution),
                Arc::clone(&clock),
                network.clone(),
                metrics.clone(),
                Arc::clone(&forks),
                lookups.sinks(events),
            )
            .fetching_engine_blobs(get_blobs),
            server: Arc::new(RequestServer::new(
                chain.clone(),
                network.clone(),
                Arc::clone(&metadata),
            )),
            sync,
            sync_outcomes: Some(sync_outcomes),
            backfill,
            backfill_outcomes: Some(backfill_outcomes),
            lookups,
            lookup_events: Some(lookup_events),
            requests: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
            validations: Arc::new(Semaphore::new(MAX_CONCURRENT_VALIDATIONS)),
            subscriptions: Subscriptions::new(
                identity.node_id,
                config.clone(),
                genesis_validators_root,
                &custody,
            )
            .subscribing_all(subscribe_all_subnets),
            network,
            chain,
            clock,
            slots,
            metadata,
            handshakes: Handshakes::default(),
            peers: PeerManager::new(peer_limits),
            peer_metrics,
            pings: HashMap::new(),
            goodbyes: HashMap::new(),
            metadata_requests: HashMap::new(),
            config,
            subnet_turn: 0,
            peer_book,
            peer_reader,
            metrics,
            discovery,
            discovery_events,
            boot_nodes: identity.boot_nodes.clone(),
            fallbacks: HashMap::new(),
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
            enr: self.discovery.as_ref().map(Discovery::published),
            p2p_address: self.network.listen_addr().to_string(),
            discovery_address: self.discovery.as_ref().map(|discovery| {
                // The multiaddr form of a UDP socket, as the identity route lists it.
                let address = discovery.local_addr();
                let family = if address.is_ipv4() { "ip4" } else { "ip6" };
                format!("/{family}/{}/udp/{}", address.ip(), address.port())
            }),
            metadata: Arc::clone(&self.metadata),
            peers: self.peer_reader.clone(),
        }
    }

    /// Handles network and discovery events until the network stops, with upkeep once a slot.
    pub(crate) async fn run(mut self, mut events: NetworkEvents) {
        let mut upkeep = time::interval(Duration::from_millis(self.slots.slot_duration_ms()));
        let mut discovered = self.discovery_events.take();
        let mut outcomes = self.sync_outcomes.take();
        let mut backfilled = self.backfill_outcomes.take();
        let mut looked_up = self.lookup_events.take();
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
            let backfill = async {
                match &mut backfilled {
                    Some(receiver) => receiver.recv().await,
                    None => pending().await,
                }
            };
            let lookup = async {
                match &mut looked_up {
                    Some(receiver) => receiver.recv().await,
                    None => pending().await,
                }
            };
            let others = Either::race(
                found,
                Either::race(processed, Either::race(backfill, upkeep.tick())),
            );
            let network = Either::race(events.next(), lookup);
            match Either::race(network, others).await {
                Either::Left(Either::Left(Some(event))) => self.handle(event).await,
                Either::Left(Either::Left(None)) => break,
                Either::Left(Either::Right(Some(event))) => {
                    self.lookups.on_event(event, self.clock.now_ms()).await;
                    self.hand_off().await;
                }
                Either::Left(Either::Right(None)) => looked_up = None,
                Either::Right(Either::Left(Some(event))) => {
                    let plans = self
                        .discovery
                        .as_mut()
                        .map(|discovery| discovery.on_event(event))
                        .unwrap_or_default();
                    let now = self.now();
                    for plan in plans {
                        // A peer already connected needs no second connection; a banned one none at all.
                        if self.peers.contains(&plan.peer)
                            || !self.peers.may_dial(&plan.peer, &plan.primary, now)
                        {
                            continue;
                        }
                        self.dial_plan(plan).await;
                    }
                }
                // Discovery stopped: carry on with the peers already known.
                Either::Right(Either::Left(None)) => discovered = None,
                Either::Right(Either::Right(Either::Left(Some(outcome)))) => {
                    self.sync.on_outcome(outcome).await;
                    self.punish_dropped().await;
                }
                Either::Right(Either::Right(Either::Left(None))) => outcomes = None,
                Either::Right(Either::Right(Either::Right(Either::Left(Some(outcome))))) => {
                    self.backfill.on_outcome(outcome).await;
                }
                Either::Right(Either::Right(Either::Right(Either::Left(None)))) => {
                    backfilled = None;
                }
                Either::Right(Either::Right(Either::Right(Either::Right(_)))) => {
                    self.maintain().await;
                }
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
        // The record states the same subnets, and the fork of the wall-clock epoch.
        if let Some(discovery) = &mut self.discovery {
            discovery.refresh(epoch, change.attnets).await;
            discovery.publish_external().await;
        }

        self.publish_light_client().await;

        // Alone, the node dials its boot nodes again: they may have been down before.
        if self.peers.len() == 0 {
            for address in &self.boot_nodes {
                if let Err(error) = self.network.dial(address.clone()).await {
                    warn!(%error, %address, "could not dial boot node");
                }
            }
        }

        self.manage_peers(digest).await;

        // Peers' heads move every slot; ask again often while behind, rarely once caught up.
        let behind = slot.0.saturating_sub(head.0) > 1;
        if behind || slot.index_in_epoch::<P>() == 0 {
            let peers: Vec<PeerId> = self.peers.connected().cloned().collect();
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
            NetworkEvent::PeerConnected {
                peer,
                address,
                outbound,
            } => {
                // The dial succeeded: its fallback is no longer needed.
                self.fallbacks.remove(&address);
                let now = self.now();
                if let Err(reason) = self.peers.on_connected(&peer, &address, outbound, now) {
                    debug!(%peer, %address, reason = reason.0, "refusing a peer");
                    self.say_goodbye(peer, reason).await;
                    return;
                }
                self.peer_book.connected(&peer, &address, outbound);
                self.metrics.peers.set_count(self.peers.len() as u64);
                // The dialer opens the handshake; the listener answers it.
                if outbound {
                    self.send_status(peer.clone()).await;
                }
                self.request_metadata(peer, Protocol::MetaDataV3).await;
            }
            NetworkEvent::PeerDisconnected { peer } => self.on_disconnected(&peer).await,
            NetworkEvent::GossipMessage {
                id,
                source,
                topic,
                data,
            } => {
                // Validation is bounded.
                // Past the limit, the loop waits and the swarm's queue absorbs the rest.
                let Ok(permit) = Arc::clone(&self.validations).acquire_owned().await else {
                    return;
                };
                let gossip = self.gossip.clone();
                task::spawn(async move {
                    gossip.handle(id, &topic, data, source).await;
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
                if let Some(status) =
                    StatusVersion::of(protocol).and_then(|version| version.decode(&payload).ok())
                {
                    self.sync.on_status(peer.clone(), status).await;
                    self.backfill.on_status(peer.clone(), status).await;
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
            NetworkEvent::Response { request, chunk, .. } => {
                self.on_response(request, &chunk).await;
            }
            NetworkEvent::ResponseEnded { request, .. } => self.on_response_end(request).await,
            NetworkEvent::RequestFailed {
                request,
                peer,
                error,
            } => self.on_request_failure(request, peer, error).await,
            NetworkEvent::RateLimited { peer, protocol } => {
                debug!(%peer, ?protocol, "peer over its rate limit");
                // The handshake methods are cheap and rarely needed: overusing them costs more.
                let action = match protocol {
                    Protocol::GoodbyeV1
                    | Protocol::MetaDataV2
                    | Protocol::MetaDataV3
                    | Protocol::StatusV1
                    | Protocol::StatusV2 => PeerAction::LowTolerance,
                    _ => PeerAction::MidTolerance,
                };
                self.report(&peer, action).await;
            }
            NetworkEvent::ConnectionFailed { address, error } => {
                debug!(%address, %error, "connection failed");
                // A failed QUIC dial falls back to the peer's TCP endpoint.
                if let Some(fallback) = self.fallbacks.remove(&address)
                    && let Err(error) = self.network.dial(fallback.clone()).await
                {
                    debug!(%error, address = %fallback, "could not dial the fallback");
                }
            }
            _ => {}
        }
    }

    /// Forgets a peer that left, in peer management and in every sync.
    async fn on_disconnected(&mut self, peer: &PeerId) {
        let now = self.now();
        self.peers.on_disconnected(peer, now);
        self.goodbyes.retain(|_, known| known != peer);
        self.pings.retain(|_, known| known != peer);
        self.metadata_requests.retain(|_, (known, _)| known != peer);
        self.peer_book.disconnected(peer);
        self.handshakes.forget(peer);
        self.metrics.peers.set_count(self.peers.len() as u64);
        self.sync.on_disconnect(peer).await;
        self.backfill.on_disconnect(peer).await;
        self.lookups.on_disconnect(peer, self.clock.now_ms()).await;
    }

    /// Routes a response chunk to the ping, metadata, handshake or sync request it answers.
    async fn on_response(&mut self, request: RequestId, chunk: &ResponseChunk) {
        if let Some(peer) = self.pings.remove(&request) {
            // A pong carries the peer's metadata sequence number: a higher one means new metadata.
            let seq = <[u8; 8]>::try_from(chunk.payload.as_slice()).map(u64::from_le_bytes);
            match seq {
                Ok(seq) if chunk.code == ResponseCode::Success => {
                    if self.peers.on_pong(&peer, seq) {
                        self.request_metadata(peer, Protocol::MetaDataV3).await;
                    }
                }
                Ok(_) => {}
                Err(_) => self.report(&peer, PeerAction::Fatal).await,
            }
        } else if let Some((peer, _)) = self.metadata_requests.get(&request) {
            // A metadata response states the peer's subnets.
            if chunk.code == ResponseCode::Success {
                let peer = peer.clone();
                match PeerSubnets::from_metadata::<P>(&peer, &chunk.payload, &self.config) {
                    Some(subnets) => self.peers.set_subnets(&peer, subnets),
                    None => self.report(&peer, PeerAction::LowTolerance).await,
                }
            }
        } else if let Some((peer, status)) = self.handshakes.answered(request, chunk) {
            match status {
                Some(status) => {
                    self.sync.on_status(peer.clone(), status).await;
                    self.backfill.on_status(peer, status).await;
                }
                None => debug!(%peer, "peer sent no usable status"),
            }
        } else if self.sync.owns(request) {
            self.sync.on_chunk(request, chunk);
        } else if self.backfill.owns(request) {
            self.backfill.on_chunk(request, chunk);
        } else if self.lookups.owns(request) {
            self.lookups.on_chunk(request, chunk);
        }
    }

    /// Ends a request: a goodbye's end closes the connection.
    async fn on_response_end(&mut self, request: RequestId) {
        self.metadata_requests.remove(&request);
        if let Some(peer) = self.goodbyes.remove(&request) {
            let _ = self.network.disconnect(peer).await;
            return;
        }
        self.sync.on_end(request).await;
        self.backfill.on_end(request).await;
        self.lookups.on_end(request, self.clock.now_ms()).await;
        self.punish_dropped().await;
        self.hand_off().await;
    }

    /// Handles a failed request, scoring the peer for faults a failure reveals.
    async fn on_request_failure(&mut self, request: RequestId, peer: PeerId, error: RequestError) {
        debug!(%peer, %error, "request failed");
        if let Some(peer) = self.goodbyes.remove(&request) {
            let _ = self.network.disconnect(peer).await;
            return;
        }
        // A broken answer to any request is malice or breakage, whatever the method.
        if matches!(error, RequestError::InvalidResponse { .. }) {
            self.report(&peer, PeerAction::Fatal).await;
        }
        if self.pings.remove(&request).is_some() {
            match error {
                // A peer must answer pings in time, and must serve them at all.
                RequestError::Timeout { .. } => self.report(&peer, PeerAction::LowTolerance).await,
                RequestError::Unsupported { .. } => self.report(&peer, PeerAction::Fatal).await,
                _ => {}
            }
            return;
        }
        if let Some((peer, protocol)) = self.metadata_requests.remove(&request) {
            if matches!(error, RequestError::Unsupported { .. }) {
                // A peer that refuses the third metadata version may speak the second; one that
                // serves neither breaks the protocol.
                if protocol == Protocol::MetaDataV3 {
                    self.request_metadata(peer, Protocol::MetaDataV2).await;
                } else {
                    self.report(&peer, PeerAction::Fatal).await;
                }
            }
            return;
        }
        if self.handshakes.owns(request) {
            // A peer that refused the newest status version gets the older one right away.
            // One that serves no status version breaks the protocol.
            match self.handshakes.failed(request, &error) {
                Some(peer) => self.send_status(peer).await,
                None if matches!(error, RequestError::Unsupported { .. }) => {
                    self.report(&peer, PeerAction::Fatal).await;
                }
                None => {}
            }
            return;
        }
        if self.sync.owns(request) || self.backfill.owns(request) || self.lookups.owns(request) {
            match error {
                // A block, blob or column request that times out costs a mid-tolerance fault.
                RequestError::Timeout { .. } => self.report(&peer, PeerAction::MidTolerance).await,
                RequestError::Negotiation { .. } => {
                    self.report(&peer, PeerAction::LowTolerance).await;
                }
                // A stream that broke mid-answer may be the network's doing.
                RequestError::StreamClosed => {
                    self.report(&peer, PeerAction::HighTolerance).await;
                }
                _ => {}
            }
        }
        self.sync.on_failure(request).await;
        self.backfill.on_failure(request).await;
        self.lookups.on_failure(request, self.clock.now_ms()).await;
        self.punish_dropped().await;
        self.hand_off().await;
    }

    /// Reports the peers lookups dropped, and asks for the status of those too deep for a lookup.
    ///
    /// The status answers show range sync how far ahead those peers are.
    async fn hand_off(&mut self) {
        for peer in self.lookups.take_dropped() {
            self.report(&peer, PeerAction::LowTolerance).await;
        }
        for peer in self.lookups.take_handoffs() {
            self.send_status(peer).await;
        }
    }

    /// The wall clock, as the peer manager measures time.
    fn now(&self) -> Duration {
        Duration::from_millis(self.clock.now_ms())
    }

    /// Keeps the peer set in shape: prunes past the target, pings, and seeks peers.
    ///
    /// A lookup serves the most starved subnet first; with every subnet served, it seeks any peer.
    async fn manage_peers(&mut self, digest: ForkDigest) {
        let now = self.now();
        let needed = self.subscriptions.needed_subnets();
        // The router's gossip scores count towards each peer's standing.
        if let Ok(scores) = self.network.gossip_scores().await {
            for (peer, reason) in self.peers.update_gossip_scores(scores, now) {
                self.say_goodbye(peer, reason).await;
            }
        }
        let upkeep = self.peers.upkeep(&needed, now);
        for (peer, reason) in upkeep.disconnect {
            self.say_goodbye(peer, reason).await;
        }
        for peer in upkeep.pings {
            self.ping(peer).await;
        }
        if let Some(discovery) = &mut self.discovery {
            if upkeep.starved.is_empty() {
                if upkeep.dials > 0 {
                    discovery.search(EnrFilter::ForkDigest(digest)).await;
                }
            } else {
                // Rotate, so one hard-to-serve subnet does not starve the others of lookups.
                let subnet = upkeep.starved[self.subnet_turn % upkeep.starved.len()];
                self.subnet_turn = self.subnet_turn.wrapping_add(1);
                discovery
                    .search(subnet.filter::<P>(digest, &self.config))
                    .await;
            }
        }
        self.peer_metrics.observe(self.peers.census(now));
        for (subnet, peers) in self.peers.subnet_peers(&needed) {
            self.peer_metrics.observe_subnet(subnet, peers);
        }
        self.metrics.peers.set_count(self.peers.len() as u64);
    }

    /// Records a fault, and says goodbye when it pushed the peer out.
    async fn report(&mut self, peer: &PeerId, action: PeerAction) {
        self.peer_metrics.fault(action);
        let now = self.now();
        if let Some(reason) = self.peers.report(peer, action, now) {
            debug!(%peer, ?action, reason = reason.0, "peer pushed out by its score");
            self.say_goodbye(peer.clone(), reason).await;
        }
    }

    /// Scores the peers sync dropped for a faulty batch: a low-tolerance fault each.
    async fn punish_dropped(&mut self) {
        for peer in self.sync.take_dropped() {
            self.report(&peer, PeerAction::LowTolerance).await;
        }
    }

    /// Sends a goodbye; the connection closes once it is delivered or fails.
    async fn say_goodbye(&mut self, peer: PeerId, reason: GoodbyeReason) {
        self.peer_metrics.goodbye(reason.0);
        match self
            .network
            .send_request(peer.clone(), Protocol::GoodbyeV1, reason.to_ssz().to_vec())
            .await
        {
            Ok(request) => {
                self.goodbyes.insert(request, peer);
            }
            Err(_) => {
                let _ = self.network.disconnect(peer).await;
            }
        }
    }

    /// Pings a peer with this node's metadata sequence number.
    async fn ping(&mut self, peer: PeerId) {
        let seq = self.metadata.seq_number.load(Ordering::Relaxed);
        match self
            .network
            .send_request(peer.clone(), Protocol::PingV1, seq.to_le_bytes().to_vec())
            .await
        {
            Ok(request) => {
                self.pings.insert(request, peer);
            }
            Err(error) => debug!(%error, %peer, "could not ping"),
        }
    }

    /// Asks a peer for its metadata, which states the subnets it serves.
    async fn request_metadata(&mut self, peer: PeerId, protocol: Protocol) {
        // Metadata requests carry no body.
        match self
            .network
            .send_request(peer.clone(), protocol, Vec::new())
            .await
        {
            Ok(request) => {
                self.metadata_requests.insert(request, (peer, protocol));
            }
            Err(error) => debug!(%error, %peer, "could not request metadata"),
        }
    }

    /// Dials a discovered peer at its best address, remembering the fallback.
    async fn dial_plan(&mut self, plan: DialPlan) {
        let DialPlan {
            primary, fallback, ..
        } = plan;
        if let Some(fallback) = fallback {
            // Threshold: fallbacks of dials that never report back are forgotten past a bound.
            if self.fallbacks.len() >= MAX_PENDING_FALLBACKS {
                self.fallbacks.clear();
            }
            self.fallbacks.insert(primary.clone(), fallback);
        }
        let transport = if primary.quic_socket_addr().is_some() {
            "quic"
        } else {
            "tcp"
        };
        self.peer_metrics.dials.with_label_values([transport]).inc();
        if let Err(error) = self.network.dial(primary.clone()).await {
            debug!(%error, address = %primary, "could not dial a discovered peer");
        }
    }

    /// Opens the status handshake with a peer, in the newest version it has not refused.
    async fn send_status(&mut self, peer: PeerId) {
        let status = match self.server.status().await {
            Ok(status) => status,
            Err(error) => return warn!(%error, "no status to send"),
        };
        let version = self.handshakes.version_for(&peer);
        match self
            .network
            .send_request(peer.clone(), version.protocol(), version.encode(&status))
            .await
        {
            Ok(request) => self.handshakes.sent(request, peer, version),
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
    /// Peer management metrics.
    pub(crate) peer_metrics: PeerMetrics,
    /// The peer set's targets.
    pub(crate) peer_limits: PeerLimits,
    /// Peer discovery and its events, when enabled.
    pub(crate) discovery: Option<(Discovery, Discv5Events)>,
    /// Where accepted gossip goes out to event stream clients.
    pub(crate) events: EventSender,
    /// Whether every attestation and sync committee subnet is joined.
    pub(crate) subscribe_all_subnets: bool,
    /// Whether backfill batches wait for quiet moments of the slot.
    pub(crate) backfill_rate_limiting: bool,
    /// Whether new blocks' columns are built from the engine's blobs.
    pub(crate) get_blobs: bool,
}
