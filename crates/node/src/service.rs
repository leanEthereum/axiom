//! The running node: every service started, wired, and stopped together.

use std::{future::Future, marker::PhantomData, sync::Arc};

use axiom_builder_client::{RelayClient, RelaySet};
use axiom_p2p::swarm::NetworkHandle;
use axiom_telemetry::{NodeMetrics, Registry};
use axiom_types::{ChainConfig, Preset, SlotClock};
use tokio::{
    sync::watch,
    task::{self, JoinHandle},
};
use tracing::{error, info, warn};

use crate::{
    ChainHandle, Clock, EventHub, EventSender, ExecutionLayer, NetworkSettings, NodeConfig,
    NodeError, NodeKey, ProposerService, ProposerSettings, Publisher,
    api::ApiServices,
    network::{
        AttestationSubnets, Discovery, ForkDigests, NatMetrics, NetworkIdentity, NetworkService,
        NetworkSetup, NodeIdentity, PeerLimits, PeerMetrics, RecordSetup,
    },
    race::Either,
    tasks::{EngineFollower, PayloadPreparer, Ticker},
};

/// The running chain, as the services started after it see it.
#[derive(Clone, Copy, Debug)]
struct StartedChain<'a, P: Preset> {
    /// The chain thread.
    handle: &'a ChainHandle<P>,
    /// Genesis and the slot length.
    slots: SlotClock,
}

impl<P: Preset> StartedChain<'_, P> {
    /// Starts the proposal desk, and the task that prepares payloads before each slot.
    fn start_proposer(
        self,
        execution: &Arc<ExecutionLayer>,
        clock: &Arc<dyn Clock>,
        settings: &ProposerSettings,
    ) -> Result<(Arc<ProposerService<P>>, JoinHandle<()>), NodeError> {
        let relays = if settings.builders.is_empty() {
            None
        } else {
            let clients = settings
                .builders
                .iter()
                .map(|url| {
                    RelayClient::new(url).map_err(|error| NodeError::Builder {
                        url: url.clone(),
                        error: Box::new(error),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Some(RelaySet::new(clients))
        };
        let proposer = Arc::new(ProposerService::new(
            self.handle.clone(),
            Arc::clone(execution),
            settings.default_fee_recipient,
            relays,
        ));
        let preparer = task::spawn(
            PayloadPreparer::new(Arc::clone(&proposer), Arc::clone(clock), self.slots).run(),
        );
        Ok((proposer, preparer))
    }

    /// Starts libp2p and the network service over it.
    ///
    /// # Returns
    ///
    /// The network handle, for shutdown and publishing.
    /// Then the service's task, and the node's identity.
    async fn start_network(
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
                    attnets: AttestationSubnets::new(identity.node_id).bits::<P>(epoch, &config),
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
            },
        )
        .await;
        let identity = service.identity();
        Ok((network, task::spawn(service.run(events)), identity))
    }
}

/// The services every network component shares.
#[derive(Clone, Debug)]
struct SharedServices {
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
    fn new(
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
    /// # Errors
    ///
    /// Fails when a component cannot start, or the chain stops on its own.
    pub async fn run(
        chain_config: ChainConfig,
        config: NodeConfig,
        clock: Arc<dyn Clock>,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), NodeError> {
        // Telemetry comes first, so every later component records into the same registry.
        let registry = Registry::new();
        let metrics = NodeMetrics::register(&registry).map_err(NodeError::Metrics)?;
        if let Err(error) = registry.register_process_metrics() {
            warn!(%error, "process metrics unavailable");
        }

        // The event stream: the chain and the network publish, the API subscribes.
        let (hub, event_sender, streams) = EventHub::new();
        let hub = task::spawn(hub.run());

        // The chain, with its slasher, telemetry, event feed, and the network identity's custody.
        let (chain, identity) = Box::pin(config.start_chain::<P>(
            chain_config,
            clock.as_ref(),
            metrics.clone(),
            event_sender.clone(),
        ))
        .await?;
        let events = chain.subscribe();
        let schedule = chain.config().clone();
        // A zero slot length would divide by zero, so the node's timers clamp it to one.
        let store_slots = chain.store().slot_clock();
        let slots = SlotClock::new(
            store_slots.genesis_ms(),
            store_slots.slot_duration_ms().max(1),
        );
        let (handle, chain_thread) = ChainHandle::spawn(chain).map_err(|error| NodeError::Io {
            context: "spawning the chain thread",
            error,
        })?;

        // The engine, or a stand-in that keeps every payload optimistic.
        let execution = Arc::new(config.open_engine()?.with_metrics(metrics.clone()));

        // The network, when configured, runs its own event loop.
        let network = match (identity, &config.network) {
            (Some(identity), Some(settings)) => {
                let started = StartedChain {
                    handle: &handle,
                    slots,
                };
                let services = SharedServices::new(
                    event_sender,
                    Arc::clone(&execution),
                    Arc::clone(&clock),
                    metrics,
                    &registry,
                )?;
                let (key, identity) = identity;
                // The network's start holds every service's state; boxing keeps this future small.
                let starting = Box::pin(started.start_network(key, identity, settings, services));
                Some(starting.await?)
            }
            _ => None,
        };
        let (network, identity) = match network {
            Some((p2p, service, identity)) => (Some((p2p, service)), Some(Arc::new(identity))),
            None => (None, None),
        };

        // The proposal desk builds payloads ahead of prepared validators' slots.
        let started = StartedChain {
            handle: &handle,
            slots,
        };
        let (proposer, preparer) = started.start_proposer(&execution, &clock, &config.proposer)?;

        // Proposed blocks go out on the network, when there is one, before import.
        let api = ApiServices {
            publisher: Arc::new(Publisher::new(
                handle.clone(),
                Arc::clone(&execution),
                Arc::clone(&clock),
                network.as_ref().map(|(p2p, _)| p2p.clone()),
            )),
            proposer,
            identity,
            events: streams,
        };

        // Every server watches one shutdown signal.
        let (stop, stopped) = watch::channel(false);
        let servers = Box::pin(config.start_servers(&handle, api, registry, &stopped)).await?;

        // Background loops run until aborted.
        let mut ticker = task::spawn(Ticker::new(handle.clone(), clock, slots).run());
        let follower =
            task::spawn(EngineFollower::new(handle.clone(), events, execution, schedule).run());

        // The ticker only ends when the chain thread is gone, such as after a panic.
        // The node then stops too, rather than serving from a dead chain.
        let crashed = matches!(Either::race(shutdown, &mut ticker).await, Either::Right(_));
        if crashed {
            error!("chain thread stopped; shutting down");
        } else {
            info!("shutting down");
        }

        // Servers first, so no request reaches a chain that is going away.
        let _unwatched = stop.send(true);
        for server in servers {
            let _finished = server.await;
        }
        if let Some((p2p, service)) = network {
            // A swarm that already stopped needs no second notice.
            let _stopped = p2p.shutdown().await;
            service.abort();
            let _cancelled = service.await;
        }
        Self::abort_all([ticker, follower, preparer, hub]).await;

        // The chain thread ends once the last handle is gone and its queue drains.
        drop(handle);
        let joined = task::spawn_blocking(move || chain_thread.join()).await;
        if crashed || !matches!(joined, Ok(Ok(_))) {
            return Err(NodeError::ChainStopped);
        }
        info!("stopped");
        Ok(())
    }

    /// Aborts background loops and waits until each has stopped.
    async fn abort_all(tasks: impl IntoIterator<Item = JoinHandle<()>>) {
        for task in tasks {
            task.abort();
            let _cancelled = task.await;
        }
    }
}
