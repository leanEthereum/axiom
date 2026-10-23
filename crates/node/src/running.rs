//! The node's lifecycle in steps: the chain opened, the services started over it, then stopped.

use std::{future::Future, iter, sync::Arc, thread};

use axiom_p2p::swarm::NetworkHandle;
use axiom_telemetry::{NodeMetrics, Registry};
use axiom_types::{ChainConfig, Preset, SlotClock};
use tokio::{
    sync::{broadcast, mpsc::UnboundedReceiver, watch},
    task::{self, JoinHandle},
};
use tracing::{error, info, warn};

use crate::{
    Chain, ChainEvent, ChainHandle, Clock, EventHub, EventSender, NodeConfig, NodeError, NodeKey,
    Publisher,
    api::ApiServices,
    events::EventSubscriptions,
    network::NetworkIdentity,
    race::Either,
    service::{SharedServices, StartedChain},
    slasher::{FoundSlashing, SlashingBroadcaster},
    tasks::{EngineFollower, SyncWatcher, Ticker},
};

/// What every component records into and publishes through.
#[derive(Debug)]
pub(crate) struct Telemetry {
    /// The metrics registry the servers expose.
    registry: Registry,
    /// The node's metrics.
    metrics: NodeMetrics,
    /// The event hub's task.
    hub: JoinHandle<()>,
    /// Where the chain and the network publish events.
    events: EventSender,
    /// Where the beacon API opens event streams.
    streams: EventSubscriptions,
}

impl Telemetry {
    /// Registers the node's metrics and starts the event hub.
    ///
    /// Telemetry comes first, so every later component records into the same registry.
    ///
    /// # Errors
    ///
    /// Fails when a metric cannot register.
    pub(crate) fn start() -> Result<Self, NodeError> {
        let registry = Registry::new();
        let metrics = NodeMetrics::register(&registry).map_err(NodeError::Metrics)?;
        if let Err(error) = registry.register_process_metrics() {
            warn!(%error, "process metrics unavailable");
        }
        let (hub, events, streams) = EventHub::new();
        Ok(Self {
            registry,
            metrics,
            hub: task::spawn(hub.run()),
            events,
            streams,
        })
    }
}

/// The chain on its own thread, and what the services started after it read from it.
#[derive(Debug)]
pub(crate) struct OpenedChain<P: Preset> {
    /// The chain thread's handle.
    handle: ChainHandle<P>,
    /// The chain thread, which returns the chain once its queue drains.
    thread: thread::JoinHandle<Chain<P>>,
    /// The node key and network identity, when the node has a network.
    identity: Option<(NodeKey, NetworkIdentity)>,
    /// The chain's events, for the engine follower.
    events: broadcast::Receiver<ChainEvent>,
    /// The fork schedule.
    schedule: ChainConfig,
    /// Genesis and a slot length of at least one millisecond.
    slots: SlotClock,
    /// Evidence the slasher finds, when the node broadcasts it.
    found_slashings: Option<UnboundedReceiver<FoundSlashing>>,
}

impl<P: Preset> OpenedChain<P> {
    /// Opens the chain with its slasher, monitor, telemetry, event feed, and custody, then spawns it.
    ///
    /// # Errors
    ///
    /// Fails when the chain, a component of it, or its thread cannot start.
    pub(crate) async fn open(
        config: &NodeConfig,
        chain_config: ChainConfig,
        clock: &dyn Clock,
        telemetry: &Telemetry,
    ) -> Result<Self, NodeError> {
        let (chain, identity) = Box::pin(config.start_chain::<P>(
            chain_config,
            clock,
            telemetry.metrics.clone(),
            telemetry.events.clone(),
        ))
        .await?;
        let chain = config.attach_monitor(chain, &telemetry.registry)?;
        let (chain, found_slashings) = config.attach_slashing_broadcast(chain);
        let events = chain.subscribe();
        let schedule = chain.config().clone();
        // A zero slot length would divide by zero, so the node's timers clamp it to one.
        let store_slots = chain.store().slot_clock();
        let slots = SlotClock::new(
            store_slots.genesis_ms(),
            store_slots.slot_duration_ms().max(1),
        );
        let (handle, thread) = ChainHandle::spawn(chain).map_err(|error| NodeError::Io {
            context: "spawning the chain thread",
            error,
        })?;
        Ok(Self {
            handle,
            thread,
            identity,
            events,
            schedule,
            slots,
            found_slashings,
        })
    }

    /// Starts every service over the chain: the engine, the network, the proposal desk, and the servers.
    ///
    /// # Errors
    ///
    /// Fails when a service cannot start.
    pub(crate) async fn serve(
        self,
        config: &NodeConfig,
        clock: Arc<dyn Clock>,
        telemetry: Telemetry,
    ) -> Result<RunningNode<P>, NodeError> {
        let Telemetry {
            registry,
            metrics,
            hub,
            events,
            streams,
        } = telemetry;
        let started = StartedChain {
            handle: &self.handle,
            slots: self.slots,
        };

        // The engine, or a stand-in that keeps every payload optimistic.
        let execution = Arc::new(config.open_engine()?.with_metrics(metrics.clone()));
        let stats = config.start_client_stats(&self.handle, &clock, metrics.clone())?;

        // The network, when configured, runs its own event loop.
        let network = match (self.identity, &config.network) {
            (Some((key, identity)), Some(settings)) => {
                let services = SharedServices::new(
                    events,
                    Arc::clone(&execution),
                    Arc::clone(&clock),
                    metrics,
                    &registry,
                )?;
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
        let (proposer, preparer) = started.start_proposer(&execution, &clock, &config.proposer)?;

        // Proposed blocks go out on the network, when there is one, before import.
        let publisher = Arc::new(Publisher::new(
            self.handle.clone(),
            Arc::clone(&execution),
            Arc::clone(&clock),
            network.as_ref().map(|(p2p, _)| p2p.clone()),
        ));
        let broadcaster = SlashingBroadcaster::spawn(self.found_slashings, &publisher);
        let api = ApiServices {
            publisher,
            proposer: Arc::clone(&proposer),
            identity,
            events: streams,
            execution: Arc::clone(&execution),
        };

        // Every server watches one shutdown signal.
        let (stop, stopped) = watch::channel(false);
        let servers = Box::pin(config.start_servers(&self.handle, api, registry, &stopped)).await?;

        // Background loops run until aborted.
        let ticker = task::spawn(Ticker::new(self.handle.clone(), clock, self.slots).run());
        let follower = EngineFollower::new(
            self.handle.clone(),
            self.events,
            execution,
            proposer,
            self.schedule,
        );
        let mut loops = vec![task::spawn(follower.run()), preparer, hub];
        loops.extend(stats);
        loops.extend(broadcaster);
        Ok(RunningNode {
            handle: self.handle,
            thread: self.thread,
            slots: self.slots,
            stop,
            servers,
            network,
            ticker,
            loops,
        })
    }
}

/// A started node: what it runs, in the order it stops.
#[derive(Debug)]
pub(crate) struct RunningNode<P: Preset> {
    /// The chain thread's handle, dropped last so the queue drains.
    handle: ChainHandle<P>,
    /// The chain thread.
    thread: thread::JoinHandle<Chain<P>>,
    /// Genesis and the slot length.
    slots: SlotClock,
    /// Tells every server to stop.
    stop: watch::Sender<bool>,
    /// The servers, awaited until they finish.
    servers: Vec<JoinHandle<()>>,
    /// The network handle and service, when the node has a network.
    network: Option<(NetworkHandle, JoinHandle<()>)>,
    /// The ticker, which ends only when the chain thread is gone.
    ticker: JoinHandle<()>,
    /// Every other background loop, aborted at shutdown.
    loops: Vec<JoinHandle<()>>,
}

impl<P: Preset> RunningNode<P> {
    /// Runs until shutdown, until synced when asked, or until the chain thread stops, then stops.
    ///
    /// # Errors
    ///
    /// Fails when the chain thread stopped on its own or did not end cleanly.
    pub(crate) async fn run_until(
        mut self,
        shutdown: impl Future<Output = ()>,
        shutdown_after_sync: bool,
    ) -> Result<(), NodeError> {
        // An operator who only wants the chain synced stops the node once it is.
        let synced = SyncWatcher::new(self.handle.clone(), self.slots).stop(shutdown_after_sync);
        let shutdown = Either::race(shutdown, synced);

        // The ticker only ends when the chain thread is gone, such as after a panic.
        // The node then stops too, rather than serving from a dead chain.
        let crashed = matches!(
            Either::race(shutdown, &mut self.ticker).await,
            Either::Right(_)
        );
        if crashed {
            error!("chain thread stopped; shutting down");
        } else {
            info!("shutting down");
        }
        self.stop(crashed).await
    }

    /// Stops the servers, the network, the loops, then drains the chain thread.
    async fn stop(self, crashed: bool) -> Result<(), NodeError> {
        // Servers first, so no request reaches a chain that is going away.
        let _unwatched = self.stop.send(true);
        for server in self.servers {
            let _finished = server.await;
        }
        if let Some((p2p, service)) = self.network {
            // A swarm that already stopped needs no second notice.
            let _stopped = p2p.shutdown().await;
            service.abort();
            let _cancelled = service.await;
        }
        for task in iter::once(self.ticker).chain(self.loops) {
            task.abort();
            let _cancelled = task.await;
        }

        // The chain thread ends once the last handle is gone and its queue drains.
        drop(self.handle);
        let thread = self.thread;
        let joined = task::spawn_blocking(move || thread.join()).await;
        if crashed || !matches!(joined, Ok(Ok(_))) {
            return Err(NodeError::ChainStopped);
        }
        info!("stopped");
        Ok(())
    }
}
