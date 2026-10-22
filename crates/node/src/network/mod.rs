//! The node on the network: gossip, requests, and sync over the libp2p stack.

mod gossip;
mod identity;
mod requests;
mod server;
mod subnets;
mod sync;

use std::{
    collections::BTreeSet,
    sync::{Arc, atomic::AtomicU64},
};

use axiom_das::NodeId;
use axiom_p2p::{
    Multiaddr, PeerId,
    eth::{
        GossipKind, GossipTopic,
        reqresp::{Protocol, ResponseCode, Status},
    },
    swarm::{NetworkEvent, NetworkEvents, NetworkHandle, RequestId},
};
use axiom_ssz::Ssz;
use axiom_telemetry::NodeMetrics;
use axiom_types::{ChainConfig, ColumnIndex, Epoch, ForkDigest, Preset, SubnetId};
use tokio::task;
use tracing::{debug, info, warn};

pub use self::identity::NodeKey;
use self::{
    gossip::GossipHandler,
    server::{LocalMetadata, RequestServer},
    subnets::AttestationSubnets,
    sync::RangeSync,
};
use crate::{ChainHandle, Clock, ExecutionLayer};

/// Who the node is on the network, and what it custodies.
#[derive(Clone, Debug)]
pub struct NetworkIdentity {
    /// The discovery identifier, which fixes custody and attestation subnets.
    pub node_id: NodeId,
    /// Custody groups the node keeps and advertises.
    pub custody_group_count: u64,
    /// Peers to dial at startup.
    pub boot_nodes: Vec<Multiaddr>,
}

/// The node's network service.
///
/// # Overview
///
/// One loop drains network events in order.
/// Gossip runs in spawned tasks, so a slow engine call never stalls the loop.
///
/// ```text
///     network events ──┬── gossip message ──> spawned: validate, report, import
///                      ├── request ─────────> server: answer from the chain
///                      ├── response ────────> sync: collect the batch
///                      └── peer connected ──> status handshake ──> sync
/// ```
#[derive(Debug)]
pub struct NetworkService<P: Preset> {
    /// The network.
    network: NetworkHandle,
    /// Gossip validation and import.
    gossip: GossipHandler<P>,
    /// Answers to peers.
    server: RequestServer<P>,
    /// Range sync.
    sync: RangeSync<P>,
    /// Peers with a status request in flight.
    handshakes: Vec<(RequestId, PeerId)>,
    /// Connected peers, for the peer count.
    peers: BTreeSet<PeerId>,
    /// Peer counts and gossip outcomes.
    metrics: NodeMetrics,
}

impl<P: Preset> NetworkService<P> {
    /// Joins the network: subscribes to the topics and dials the boot nodes.
    ///
    /// # Arguments
    ///
    /// - `network`: the started libp2p stack.
    /// - `identity`: the node identifier, custody, and boot nodes.
    /// - `chain`, `execution`, `clock`, `metrics`: the node's services.
    #[must_use]
    pub fn start(
        network: NetworkHandle,
        identity: &NetworkIdentity,
        chain: ChainHandle<P>,
        setup: NetworkSetup,
    ) -> Self {
        let NetworkSetup {
            config,
            fork_digest,
            epoch,
            custody,
            execution,
            clock,
            metrics,
        } = setup;

        // Long-lived attestation subnets, from the node identifier.
        let subnets = AttestationSubnets::new(identity.node_id).at::<P>(epoch, &config);
        let mut attnets = [false; 64];
        for subnet in &subnets {
            if let Some(bit) = usize::try_from(subnet.0)
                .ok()
                .and_then(|index| attnets.get_mut(index))
            {
                *bit = true;
            }
        }
        for topic in Self::topics(fork_digest, &config, &custody, &subnets) {
            if let Err(error) = network.subscribe(topic.topic()) {
                warn!(%error, %topic, "could not subscribe");
            }
        }
        for address in &identity.boot_nodes {
            if let Err(error) = network.dial(address.clone()) {
                warn!(%error, %address, "could not dial boot node");
            }
        }
        info!(
            peer = %network.local_peer(),
            address = %network.listen_addr(),
            subnets = ?subnets,
            custody_columns = custody.len(),
            "network started"
        );

        let metadata = LocalMetadata {
            seq_number: AtomicU64::new(1),
            attnets,
            custody_group_count: identity.custody_group_count,
        };
        Self {
            gossip: GossipHandler::new(
                chain.clone(),
                Arc::clone(&execution),
                clock,
                network.clone(),
                metrics.clone(),
            ),
            server: RequestServer::new(chain.clone(), network.clone(), metadata),
            sync: RangeSync::new(chain, execution, network.clone()),
            network,
            handshakes: Vec::new(),
            peers: BTreeSet::new(),
            metrics,
        }
    }

    /// Handles network events until the network stops.
    pub async fn run(mut self, mut events: NetworkEvents) {
        while let Some(event) = events.next().await {
            self.handle(event).await;
        }
        info!("network stopped");
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
        {
            Ok(request) => self.handshakes.push((request, peer)),
            Err(error) => warn!(%error, "could not send status"),
        }
    }

    /// Every topic the node joins.
    ///
    /// The global topics, its custody columns' subnets, and its long-lived attestation subnets.
    fn topics(
        fork_digest: ForkDigest,
        config: &ChainConfig,
        custody: &BTreeSet<ColumnIndex>,
        subnets: &[SubnetId],
    ) -> Vec<GossipTopic> {
        let mut kinds = vec![
            GossipKind::BeaconBlock,
            GossipKind::BeaconAggregateAndProof,
            GossipKind::VoluntaryExit,
            GossipKind::ProposerSlashing,
            GossipKind::AttesterSlashing,
            GossipKind::SyncCommitteeContributionAndProof,
            GossipKind::BlsToExecutionChange,
        ];
        // Columns map onto subnets by index modulo the subnet count.
        let column_subnets: BTreeSet<u64> = custody
            .iter()
            .map(|column| column.0 % config.data_column_sidecar_subnet_count)
            .collect();
        kinds.extend(
            column_subnets
                .into_iter()
                .map(GossipKind::DataColumnSidecar),
        );
        kinds.extend(
            subnets
                .iter()
                .map(|subnet| GossipKind::BeaconAttestation(subnet.0)),
        );
        kinds
            .into_iter()
            .map(|kind| GossipTopic { fork_digest, kind })
            .collect()
    }
}

/// The node's services and chain facts the network service starts from.
#[derive(Debug)]
pub struct NetworkSetup {
    /// The chain configuration.
    pub config: ChainConfig,
    /// The current fork digest.
    pub fork_digest: ForkDigest,
    /// The current epoch.
    pub epoch: Epoch,
    /// The node's custody columns.
    pub custody: BTreeSet<ColumnIndex>,
    /// The engine.
    pub execution: Arc<ExecutionLayer>,
    /// The wall clock.
    pub clock: Arc<dyn Clock>,
    /// The node's metrics.
    pub metrics: NodeMetrics,
}
