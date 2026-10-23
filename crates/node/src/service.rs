//! The running node: every service started, wired, and stopped together.

use std::{future::Future, marker::PhantomData, sync::Arc};

use axiom_builder_client::RelaySet;
use axiom_p2p::swarm::NetworkHandle;
use axiom_telemetry::{NodeMetrics, Registry};
use axiom_types::{ChainConfig, Preset, SlotClock};
use tokio::task::{self, JoinHandle};

use crate::{
    ChainHandle, Clock, EventSender, ExecutionLayer, NetworkSettings, NodeConfig, NodeError,
    NodeKey, ProposerService, ProposerSettings,
    network::{
        AttestationSubnets, Discovery, ForkDigests, NatMetrics, NetworkIdentity, NetworkService,
        NetworkSetup, NodeIdentity, PeerLimits, PeerMetrics, RecordSetup,
    },
    running::{OpenedChain, Telemetry},
    tasks::PayloadPreparer,
};

/// The running chain, as the services started after it see it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StartedChain<'a, P: Preset> {
    /// The chain thread.
    pub(crate) handle: &'a ChainHandle<P>,
    /// Genesis and the slot length.
    pub(crate) slots: SlotClock,
}

impl<P: Preset> StartedChain<'_, P> {
    /// Starts the proposal desk, and the task that prepares payloads before each slot.
    pub(crate) fn start_proposer(
        self,
        execution: &Arc<ExecutionLayer>,
        clock: &Arc<dyn Clock>,
        settings: &ProposerSettings,
    ) -> Result<(Arc<ProposerService<P>>, JoinHandle<()>), NodeError> {
        let relays = if settings.builders.is_empty() {
            None
        } else {
            let clients = settings.builder_client.connect(&settings.builders)?;
            Some(RelaySet::new(clients))
        };
        let proposer = ProposerService::new(
            self.handle.clone(),
            Arc::clone(execution),
            Arc::clone(clock),
            settings.default_fee_recipient,
            relays,
        )
        .with_breaker(settings.builder_fallback.breaker::<P>())
        .with_graffiti(settings.graffiti)
        .with_reorgs(settings.reorgs);
        let proposer = Arc::new(if settings.always_prepare_payload {
            proposer.preparing_always()
        } else {
            proposer
        });
        let preparer = PayloadPreparer::new(
            Arc::clone(&proposer),
            Arc::clone(clock),
            self.slots,
            settings.prepare_lookahead,
        );
        let preparer = task::spawn(preparer.run());
        Ok((proposer, preparer))
    }

    /// Starts libp2p and the network service over it.
    ///
    /// # Returns
    ///
    /// The network handle, for shutdown and publishing.
    /// Then the service's task, and the node's identity.
    pub(crate) async fn start_network(
        self,
        key: NodeKey,
        identity: NetworkIdentity,
        settings: &NetworkSettings,
        services: SharedServices,
    ) -> Result<(NetworkHandle, JoinHandle<()>, NodeIdentity), NodeError> {
        let SharedServices {
            events: api_events,
            execution,
            clock,
            metrics,
            peer_metrics,
            nat,
        } = services;
        // The record is stated for the wall clock's epoch, not the anchor's.
        let epoch = self.slots.slot_at(clock.now_ms()).epoch::<P>();
        let (config, custody, genesis_validators_root) = self
            .handle
            .run(|chain| {
                (
                    chain.config().clone(),
                    chain.custody().clone(),
                    chain.genesis_validators_root(),
                )
            })
            .await
            .map_err(|_| NodeError::ChainStopped)?;

        // Phase0 topics identify messages by payload alone, later forks by topic too.
        let message_ids = ForkDigests::new(&config, genesis_validators_root).message_ids();
        let (network, events) = settings.start_p2p(&key, message_ids).await?;
        let discovery = match &settings.discovery {
            Some(discovery) => {
                let record = RecordSetup {
                    tcp_port: settings.listen_address.port(),
                    quic_port: settings.quic_port,
                    epoch,
                    genesis_validators_root,
                    attnets: if settings.subscribe_all_subnets {
                        AttestationSubnets::all(&config)
                    } else {
                        AttestationSubnets::new(identity.node_id).bits::<P>(epoch, &config)
                    },
                    custody_group_count: identity.custody_group_count,
                };
                let (mut started, events) = Discovery::start(&key, discovery, &config, record)
                    .await
                    .map_err(|error| NodeError::Io {
                        context: "starting discovery",
                        error,
                    })?;
                // Port mapping runs only when the operator turned it on.
                started.start_nat(settings.port_mapping, nat);
                Some((started, events))
            }
            None => None,
        };
        let service = NetworkService::start(
            network.clone(),
            &identity,
            self.handle.clone(),
            NetworkSetup {
                config,
                genesis_validators_root,
                custody,
                slots: self.slots,
                execution,
                clock,
                metrics,
                peer_metrics,
                peer_limits: PeerLimits {
                    target: settings.target_peers,
                    // Threshold: ten percent of headroom, at least one, for new peers to come in.
                    excess: (settings.target_peers / 10).max(1),
                    ..PeerLimits::default()
                },
                discovery,
                events: api_events,
                subscribe_all_subnets: settings.subscribe_all_subnets,
                backfill_rate_limiting: settings.backfill_rate_limiting,
                get_blobs: settings.get_blobs,
            },
        )
        .await;
        let identity = service.identity();
        Ok((network, task::spawn(service.run(events)), identity))
    }
}

/// The services every network component shares.
#[derive(Clone, Debug)]
pub(crate) struct SharedServices {
    /// Where accepted gossip goes out to event stream clients.
    events: EventSender,
    /// The execution engine.
    execution: Arc<ExecutionLayer>,
    /// The wall clock.
    clock: Arc<dyn Clock>,
    /// The node's metrics.
    metrics: NodeMetrics,
    /// Peer management metrics.
    peer_metrics: PeerMetrics,
    /// The port mapping and external address metrics.
    nat: NatMetrics,
}

impl SharedServices {
    /// The shared services, with the network's own metrics registered beside the node's.
    pub(crate) fn new(
        events: EventSender,
        execution: Arc<ExecutionLayer>,
        clock: Arc<dyn Clock>,
        metrics: NodeMetrics,
        registry: &Registry,
    ) -> Result<Self, NodeError> {
        Ok(Self {
            events,
            execution,
            clock,
            metrics,
            peer_metrics: PeerMetrics::register(registry).map_err(NodeError::Metrics)?,
            nat: NatMetrics::register(registry).map_err(NodeError::Metrics)?,
        })
    }
}

/// A beacon node for one preset.
///
/// # Overview
///
/// - The ticker and the beacon API feed the chain thread.
/// - The chain thread emits events.
/// - Events drive fork choice updates to the engine, and logs and metrics.
/// - A metrics server exposes the metrics for Prometheus to scrape.
///
/// Shutdown stops the servers, then the tasks, then drains the chain thread.
#[derive(Debug)]
pub struct Node<P: Preset> {
    /// The preset every component is built for.
    preset: PhantomData<P>,
}

impl<P: Preset> Node<P> {
    /// Runs a node until a shutdown future completes.
    ///
    /// 1. Telemetry and the event hub, so every later component records and publishes.
    /// 2. The chain thread, with its slasher, monitor, and custody.
    /// 3. The engine, the network, the proposal desk, the servers, and the loops over the chain.
    /// 4. Shutdown, or a chain crash, stops everything in reverse dependency order.
    ///
    /// # Errors
    ///
    /// Fails when a component cannot start, or the chain stops on its own.
    pub async fn run(
        chain_config: ChainConfig,
        config: NodeConfig,
        clock: Arc<dyn Clock>,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), NodeError> {
        let telemetry = Telemetry::start()?;
        let opened = Box::pin(OpenedChain::<P>::open(
            &config,
            chain_config,
            clock.as_ref(),
            &telemetry,
        ))
        .await?;
        let running = Box::pin(opened.serve(&config, clock, telemetry)).await?;
        running
            .run_until(shutdown, config.shutdown_after_sync)
            .await
    }
}
