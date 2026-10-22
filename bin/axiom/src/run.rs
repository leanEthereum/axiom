//! A resolved run: logging, the runtime, the node, and the signals that stop it.

use std::{
    io::{self, Write},
    sync::Arc,
};

use axiom_node::{Node, NodeConfig, NodeError, SystemClock};
use axiom_telemetry::LogConfig;
use axiom_types::{ChainConfig, Gnosis, Mainnet, Minimal};
use axiom_yaml::Yaml;
use thiserror::Error;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tokio::{runtime::Builder, signal::ctrl_c, sync::Notify, task};
use tracing::{info, warn};

use crate::{
    cli::Purge,
    startup::{Dumps, StartupError},
};

/// The compile-time preset a run uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PresetName {
    /// The production preset.
    Mainnet,
    /// The small preset for testing.
    Minimal,
    /// The preset of the gnosis chain.
    Gnosis,
}

impl PresetName {
    /// The name a configuration's preset base gives.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Minimal => "minimal",
            Self::Gnosis => "gnosis",
        }
    }

    /// The preset a chain configuration names as its base, mainnet when it names none.
    ///
    /// An unknown base is left for the configuration reader to refuse.
    pub(crate) fn of_config(yaml: &Yaml) -> Self {
        match yaml.get("PRESET_BASE").and_then(Yaml::as_str) {
            Some("minimal") => Self::Minimal,
            Some("gnosis") => Self::Gnosis,
            _ => Self::Mainnet,
        }
    }
}

/// A fully resolved node run.
#[derive(Debug)]
pub(crate) struct Run {
    /// The preset to compile against.
    pub(crate) preset: PresetName,
    /// The chain's runtime configuration.
    pub(crate) chain: ChainConfig,
    /// The execution block that deployed the deposit contract, logged at startup.
    pub(crate) deposit_contract_block: u64,
    /// The node's services.
    pub(crate) node: NodeConfig,
    /// How the database is deleted before the node starts, if it is.
    pub(crate) purge: Option<Purge>,
    /// Files the configurations are written to at startup.
    pub(crate) dumps: Dumps,
    /// The logger.
    pub(crate) log: LogConfig,
    /// Flags given that no longer have an effect, warned about once logging starts.
    pub(crate) deprecated: Vec<&'static str>,
}

/// Why a run stopped with an error.
#[derive(Debug, Error)]
pub(crate) enum RunError {
    /// Startup work before the node failed.
    #[error("{0}")]
    Startup(#[from] StartupError),
    /// The node failed.
    #[error("{0}")]
    Node(#[from] NodeError),
}

impl Run {
    /// Starts logging and the runtime, then runs the node until a signal stops it.
    ///
    /// # Errors
    ///
    /// - The purge is declined, or a dump cannot be written.
    /// - The runtime cannot start, or the node fails.
    pub(crate) fn execute(self) -> Result<(), RunError> {
        if let Err(error) = self.log.init() {
            let _unwritable = writeln!(io::stderr(), "error: logging: {error}");
        }
        info!(
            network = %self.chain.config_name,
            preset = self.preset.name(),
            deposit_contract_block = self.deposit_contract_block,
            "network"
        );
        for flag in &self.deprecated {
            warn!(flag, "deprecated flag has no effect");
        }
        if let (Some(purge), Some(datadir)) = (self.purge, &self.node.data_dir) {
            purge.apply(datadir)?;
        }
        self.dumps.write(&self.node, &self.chain, self.preset)?;
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
                PresetName::Gnosis => {
                    Box::pin(Node::<Gnosis>::run(self.chain, self.node, clock, shutdown)).await
                }
            }
        })?;
        Ok(())
    }

    /// A future that completes on the first interrupt or termination signal.
    pub(crate) async fn shutdown_signal() {
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
