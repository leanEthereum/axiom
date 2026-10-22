//! A resolved run: logging, the runtime, the node, and the signals that stop it.

use std::{
    io::{self, Write},
    sync::Arc,
};

use axiom_node::{Node, NodeConfig, NodeError, SystemClock};
use axiom_telemetry::LogConfig;
use axiom_types::{ChainConfig, Mainnet, Minimal};
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tokio::{runtime::Builder, signal::ctrl_c, sync::Notify, task};

/// The compile-time preset a run uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PresetName {
    /// The production preset.
    Mainnet,
    /// The small preset for testing.
    Minimal,
}

/// A fully resolved node run.
#[derive(Debug)]
pub(crate) struct Run {
    /// The preset to compile against.
    pub(crate) preset: PresetName,
    /// The chain's runtime configuration.
    pub(crate) chain: ChainConfig,
    /// The node's services.
    pub(crate) node: NodeConfig,
    /// The logger.
    pub(crate) log: LogConfig,
}

impl Run {
    /// Starts logging and the runtime, then runs the node until a signal stops it.
    ///
    /// # Errors
    ///
    /// Fails when the runtime cannot start or the node fails.
    pub(crate) fn execute(self) -> Result<(), NodeError> {
        if let Err(error) = self.log.init() {
            let _unwritable = writeln!(io::stderr(), "error: logging: {error}");
        }
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .thread_name("axiom")
            .build()
            .map_err(|error| NodeError::Io {
                context: "starting the runtime",
                error,
            })?;
        runtime.block_on(async move {
            let clock = Arc::new(SystemClock);
            let shutdown = Self::shutdown_signal();
            // The preset is a compile-time choice, so each one is its own monomorphized node.
            // A node's future holds every service's state, so it lives on the heap.
            match self.preset {
                PresetName::Mainnet => {
                    Box::pin(Node::<Mainnet>::run(self.chain, self.node, clock, shutdown)).await
                }
                PresetName::Minimal => {
                    Box::pin(Node::<Minimal>::run(self.chain, self.node, clock, shutdown)).await
                }
            }
        })
    }

    /// A future that completes on the first interrupt or termination signal.
    async fn shutdown_signal() {
        let notify = Arc::new(Notify::new());

        // Ctrl-C from a terminal.
        let interrupted = Arc::clone(&notify);
        task::spawn(async move {
            if ctrl_c().await.is_ok() {
                interrupted.notify_one();
            }
        });

        // SIGTERM from a service manager or a container runtime.
        #[cfg(unix)]
        {
            let terminated = Arc::clone(&notify);
            task::spawn(async move {
                if let Ok(mut stream) = signal(SignalKind::terminate()) {
                    stream.recv().await;
                    terminated.notify_one();
                }
            });
        }

        notify.notified().await;
    }
}
