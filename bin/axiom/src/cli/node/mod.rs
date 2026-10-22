//! The beacon node's flags, gathered by concern and resolved into a run.

mod behaviour;
mod chain;
mod peers;
mod proposer;
mod services;
mod slasher;
mod storage;

use axiom_node::NodeConfig;
use behaviour::{BEHAVIOUR_USAGE, BehaviourFlags};
use chain::{CHAIN_USAGE, ChainFlags};
use peers::{PEER_USAGE, PeerFlags};
use proposer::{PROPOSER_USAGE, ProposerFlags};
use services::{SERVICE_USAGE, ServiceFlags};
use slasher::{SLASHER_USAGE, SlasherFlags};
pub(crate) use storage::Purge;
use storage::{STORAGE_USAGE, StorageFlags};

use crate::{
    cli::{
        CliError, Command,
        arguments::Arguments,
        log::{LOG_USAGE, LogFlags},
    },
    run::Run,
    startup::Dumps,
};

/// The beacon node's flags, in the order the help text lists them.
pub(crate) const NODE_USAGE: [&str; 8] = [
    CHAIN_USAGE,
    STORAGE_USAGE,
    SERVICE_USAGE,
    PEER_USAGE,
    PROPOSER_USAGE,
    SLASHER_USAGE,
    BEHAVIOUR_USAGE,
    LOG_USAGE,
];

/// The beacon node's flags as given, one group per concern.
#[derive(Debug, Default)]
pub(crate) struct NodeFlags {
    /// The chain and its anchor.
    chain: ChainFlags,
    /// The data directory and database upkeep.
    storage: StorageFlags,
    /// The servers and the engine.
    services: ServiceFlags,
    /// The peer-to-peer network.
    peers: PeerFlags,
    /// Block production.
    proposer: ProposerFlags,
    /// The slasher.
    slasher: SlasherFlags,
    /// The chain thread and startup output.
    behaviour: BehaviourFlags,
    /// Logging.
    log: LogFlags,
}

impl NodeFlags {
    /// Parses the beacon node's flags.
    ///
    /// # Errors
    ///
    /// Fails on an unknown flag, a missing value, or a value that does not parse.
    pub(crate) fn parse<I: Iterator<Item = String>>(
        mut words: Arguments<I>,
    ) -> Result<Command, CliError> {
        let mut flags = Self::default();
        while let Some(flag) = words.next_flag() {
            match flag.as_str() {
                "-h" | "--help" => return Ok(Command::Help),
                "-V" | "--version" => return Ok(Command::Version),
                _ => {}
            }
            // Each group either takes the flag or passes it on.
            let taken = flags.chain.read(&flag, &mut words)?
                || flags.storage.read(&flag, &mut words)?
                || flags.services.read(&flag, &mut words)?
                || flags.peers.read(&flag, &mut words)?
                || flags.proposer.read(&flag, &mut words)?
                || flags.slasher.read(&flag, &mut words)?
                || flags.behaviour.read(&flag, &mut words)?
                || flags.log.read(&flag, &mut words)?;
            if !taken {
                return Err(CliError::UnknownFlag(flag));
            }
        }
        flags.resolve().map(|run| Command::Run(Box::new(run)))
    }

    /// Turns the flags into a run, reading the network's files if a directory is named.
    fn resolve(self) -> Result<Run, CliError> {
        let chain = self.chain.resolve()?;
        let storage = self.storage.resolve();
        let services = self.services.resolve()?;
        let proposer = self.proposer.resolve(services.engine.is_some())?;
        let (slasher, slasher_setup) = self.slasher.resolve()?;
        let network = self
            .peers
            .resolve(&chain.network.chain, chain.network.boot_enrs.clone());
        // Logs land beside the database unless told otherwise.
        let log_directory = storage.datadir.as_ref().map(|data| data.join("logs"));
        Ok(Run {
            preset: chain.network.preset,
            deposit_contract_block: chain.network.deposit_contract_block,
            node: NodeConfig {
                data_dir: storage.datadir,
                anchor: chain.anchor,
                http_address: services.http_address,
                metrics_address: services.metrics_address,
                engine: services.engine,
                network,
                history: chain.history,
                proposer,
                slasher,
                slasher_setup,
                chain: self.behaviour.chain_settings(storage.pruning),
                database: storage.database,
                http_allow_origin: services.http_allow_origin,
                metrics_allow_origin: services.metrics_allow_origin,
                shutdown_after_sync: self.behaviour.shutdown_after_sync,
            },
            chain: chain.network.chain,
            purge: storage.purge,
            dumps: Dumps {
                config: self.behaviour.dump_config,
                chain_config: self.behaviour.dump_chain_config,
            },
            log: self.log.resolve(log_directory, "beacon"),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use axiom_http::Cors;
    use axiom_node::{
        AnchorSource, ChainSettings, DatabaseSettings, DiscoverySettings, EngineConfig,
        GenesisState, HistorySettings, NetworkSettings, PortMappingSettings, SidecarPruning,
        SlasherSetup,
    };
    use axiom_telemetry::{LogConfig, LogFile, LogFormat};
    use axiom_types::ChainConfig;

    use super::*;
    use crate::{
        cli::Cli,
        network::{BuiltInNetwork, Network},
        run::PresetName,
    };

    /// The example record of EIP-778.
    const EIP_778_RECORD: &str = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";

    fn parse(arguments: &[&str]) -> Result<Command, CliError> {
        Cli::parse(arguments.iter().map(|argument| (*argument).to_owned()))
    }

    fn run(arguments: &[&str]) -> Run {
        match parse(arguments).unwrap() {
            Command::Run(run) => *run,
            other => panic!("expected a run, got {other:?}"),
        }
    }

    #[test]
    fn no_flags_follow_mainnet_from_its_genesis_with_its_boot_nodes() {
        let run = run(&[]);
        let mainnet = Network::built_in(BuiltInNetwork::Mainnet).unwrap();

        assert_eq!(run.preset, PresetName::Mainnet);
        assert_eq!(run.chain, ChainConfig::mainnet());
        assert_eq!(run.deposit_contract_block, 11_052_984);
        assert!(matches!(
            run.node.anchor,
            Some(AnchorSource::Genesis(GenesisState::Embedded(_)))
        ));
        assert_eq!(
            run.node.network,
            Some(NetworkSettings {
                listen_address: "0.0.0.0:9000".parse().unwrap(),
                quic_port: Some(9001),
                port_mapping: PortMappingSettings::default(),
                boot_nodes: Vec::new(),
                custody_group_count: 4,
                discovery: Some(DiscoverySettings {
                    udp_port: 9000,
                    enr_address: None,
                    boot_enrs: mainnet.boot_enrs,
                }),
                target_peers: 64,
                subscribe_all_subnets: false,
            })
        );
        assert_eq!(
            run.node.http_address,
            Some("127.0.0.1:5052".parse().unwrap())
        );
        assert_eq!(run.node.chain, ChainSettings::default());
        assert_eq!(run.node.database, DatabaseSettings::default());
        assert_eq!(run.purge, None);
        assert_eq!(run.dumps, Dumps::default());
        // Without a data directory there is nowhere to keep log files.
        assert_eq!(run.log, LogConfig::default());
    }

    #[test]
    fn service_and_peer_flags_reach_the_configuration() {
        let node = run(&[
            "--network",
            "minimal",
            "--http-address",
            "127.0.0.1:5053",
            "--http-allow-origin",
            "*",
            "--metrics-address",
            "0.0.0.0:5054",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
            "--jwt-secret",
            "jwt.hex",
            "--execution-timeout-multiplier",
            "2",
            "--listen-address",
            "127.0.0.1:9001",
            "--quic-port",
            "9101",
            "--nat",
            "--boot-node",
            "/ip4/10.0.0.1/tcp/9000",
            "--custody-groups",
            "128",
            "--discovery-port",
            "9002",
            "--enr-address",
            "203.0.113.7",
            "--boot-enr",
            EIP_778_RECORD,
            "--target-peers",
            "100",
            "--subscribe-all-subnets",
            "--suggested-fee-recipient",
            "0x00000000219ab540356cbb839cbe05303d7705fa",
        ])
        .node;

        assert_eq!(node.http_address, Some("127.0.0.1:5053".parse().unwrap()));
        assert_eq!(node.http_allow_origin, Some(Cors::parse("*").unwrap()));
        assert_eq!(node.metrics_address, Some("0.0.0.0:5054".parse().unwrap()));
        assert_eq!(
            node.engine,
            Some(EngineConfig {
                url: "http://127.0.0.1:8551".to_owned(),
                jwt_secret: "jwt.hex".into(),
                timeout_multiplier: 2,
            })
        );
        // The minimal configuration has no network, so only the given record bootstraps.
        assert_eq!(
            node.network,
            Some(NetworkSettings {
                listen_address: "127.0.0.1:9001".parse().unwrap(),
                quic_port: Some(9101),
                port_mapping: PortMappingSettings { enabled: true },
                boot_nodes: vec!["/ip4/10.0.0.1/tcp/9000".parse().unwrap()],
                custody_group_count: 128,
                discovery: Some(DiscoverySettings {
                    udp_port: 9002,
                    enr_address: Some(Ipv4Addr::new(203, 0, 113, 7)),
                    boot_enrs: vec![EIP_778_RECORD.parse().unwrap()],
                }),
                target_peers: 100,
                subscribe_all_subnets: true,
            })
        );
        assert_eq!(
            node.proposer.default_fee_recipient.to_string(),
            "0x00000000219ab540356cbb839cbe05303d7705fa"
        );
    }

    #[test]
    fn storage_and_behaviour_flags_reach_the_configuration() {
        let run = run(&[
            "--network",
            "minimal",
            "--genesis-state",
            "genesis.ssz",
            "--datadir",
            "data",
            "--purge-db-force",
            "--compact-db",
            "--prune-blobs",
            "false",
            "--slasher",
            "--slasher-update-period",
            "6",
            "--max-skip-slots",
            "64",
            "--shutdown-after-sync",
            "--dump-chain-config",
            "config.yaml",
            "--log",
            "debug",
            "--log-format",
            "json",
        ]);

        assert_eq!(run.preset, PresetName::Minimal);
        assert_eq!(run.chain, ChainConfig::minimal());
        assert_eq!(run.purge, Some(Purge::Forced));
        assert_eq!(
            run.dumps,
            Dumps {
                config: None,
                chain_config: Some("config.yaml".into()),
            }
        );
        let node = run.node;
        assert_eq!(node.data_dir, Some("data".into()));
        assert_eq!(
            node.anchor,
            Some(AnchorSource::Genesis(GenesisState::File(
                "genesis.ssz".into()
            )))
        );
        assert_eq!(node.history, HistorySettings::default());
        assert!(node.slasher.is_some());
        assert_eq!(
            node.slasher_setup,
            SlasherSetup {
                directory: None,
                update_period: Some(Duration::from_secs(6)),
            }
        );
        assert_eq!(
            node.chain,
            ChainSettings {
                max_skip_slots: Some(64),
                sidecar_pruning: SidecarPruning {
                    enabled: false,
                    ..SidecarPruning::default()
                },
                ..ChainSettings::default()
            }
        );
        assert_eq!(
            node.database,
            DatabaseSettings {
                auto_compact: true,
                compact_on_start: true,
            }
        );
        assert!(node.shutdown_after_sync);
        // The data directory holds the log files, which follow the terminal's JSON.
        assert_eq!(
            run.log,
            LogConfig {
                filter: "debug".to_owned(),
                format: LogFormat::Json,
                file: Some(LogFile {
                    format: LogFormat::Json,
                    ..LogFile::new("data/logs".into(), "beacon".to_owned())
                }),
            }
        );
    }

    #[test]
    fn quic_can_be_turned_off() {
        // Over TCP alone there is no QUIC port.
        let network = run(&["--no-quic"]).node.network.unwrap();
        assert_eq!(network.quic_port, None);
    }

    #[test]
    fn help_and_version_stop_parsing() {
        // A help flag wins even when a bad flag follows it.
        assert!(matches!(parse(&["--help", "--bogus"]), Ok(Command::Help)));
        assert!(matches!(parse(&["-V"]), Ok(Command::Version)));
    }

    #[test]
    fn malformed_command_lines_are_refused() {
        assert!(
            matches!(parse(&["--bogus"]), Err(CliError::UnknownFlag(flag)) if flag == "--bogus")
        );
        assert!(matches!(
            parse(&["--datadir"]),
            Err(CliError::MissingValue("--datadir"))
        ));
        assert!(matches!(
            parse(&["--http-address", "localhost"]),
            Err(CliError::InvalidValue {
                flag: "--http-address",
                ..
            })
        ));
        assert!(matches!(
            parse(&["--boot-enr", "enr:not-base64!"]),
            Err(CliError::InvalidValue {
                flag: "--boot-enr",
                ..
            })
        ));
        assert!(matches!(
            parse(&["--execution-endpoint", "http://127.0.0.1:8551"]),
            Err(CliError::IncompleteEngine)
        ));
    }

    #[test]
    fn the_usage_lists_every_group() {
        // One flag from each group, and the subcommands.
        let usage = Cli::usage();
        for flag in [
            "--testnet-dir",
            "--purge-db",
            "--staking",
            "--target-peers",
            "--builder-user-agent",
            "--slasher-dir",
            "--dump-chain-config",
            "--logfile-max-size",
            "axiom db",
        ] {
            assert!(usage.contains(flag), "{flag}");
        }
    }
}
