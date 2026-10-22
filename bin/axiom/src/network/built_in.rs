//! The networks compiled into the binary, with where each file was taken from.
//!
//! # Sources
//!
//! Every file is copied byte for byte from its maintainers' repository, pinned by commit:
//!
//! ```text
//!     network  repository                     path        commit
//!     mainnet  github.com/eth-clients/mainnet  metadata/   8cad4805e9cb5aa5e8e74d30e3f5029a7f133372
//!     sepolia  github.com/eth-clients/sepolia  metadata/   7b1b9d9549787b6bbf538f943304c4cf84f7e39e
//!     holesky  github.com/eth-clients/holesky  metadata/   64e379f3ed110dbd5f018ae512e25564eaa293c5
//!     hoodi    github.com/eth-clients/hoodi    metadata/   2a7efb3c530cce7c71702cc98d0f965df2411c11
//!     gnosis   github.com/gnosischain/configs  mainnet/    2dd5746292ca298ae0695f1ee221098074574e04
//!     chiado   github.com/gnosischain/configs  chiado/     2dd5746292ca298ae0695f1ee221098074574e04
//! ```
//!
//! The gnosis repository names its boot node file `bootnodes.yaml`.
//! It is stored here under the common name.
//!
//! # Genesis states
//!
//! The mainnet, sepolia, and gnosis genesis states weigh 3 to 6 MB.
//! They ship as snappy frame streams, decompressed when a node first starts.
//! The holesky, hoodi, and chiado states are larger or rarely needed.
//!
//! For those only the SHA-256 is compiled in, and a beacon API serves the bytes.
//! The holesky and hoodi digests are the large file pointers their repositories commit.
//! The chiado digest is that of the committed `genesis.ssz`.

use std::{fmt, str::FromStr};

use axiom_types::Hash32;
use thiserror::Error;

/// A network whose files are compiled into the binary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum BuiltInNetwork {
    /// The Ethereum mainnet.
    #[default]
    Mainnet,
    /// The long-lived application test network.
    Sepolia,
    /// The large validator test network, being retired.
    Holesky,
    /// The validator and staking test network that succeeds holesky.
    Hoodi,
    /// The gnosis chain, on the gnosis preset.
    Gnosis,
    /// The gnosis chain's test network.
    Chiado,
    /// No network: the minimal preset's configuration, for local tests.
    Minimal,
}

/// The published files of a compiled-in network.
#[derive(Clone, Copy, Debug)]
pub(super) struct NetworkFiles {
    /// The chain configuration.
    pub(super) config: &'static str,
    /// The boot node records.
    pub(super) boot_nodes: &'static str,
    /// The deposit contract's deployment block.
    pub(super) deposit_block: &'static str,
    /// The genesis state as a snappy frame stream, when it ships.
    pub(super) genesis: Option<&'static [u8]>,
    /// SHA-256 of the genesis state, when only its digest ships.
    pub(super) genesis_checksum: Option<Hash32>,
}

impl BuiltInNetwork {
    /// Every compiled-in network, in the order the help text lists them.
    pub(crate) const ALL: [Self; 7] = [
        Self::Mainnet,
        Self::Sepolia,
        Self::Holesky,
        Self::Hoodi,
        Self::Gnosis,
        Self::Chiado,
        Self::Minimal,
    ];

    /// The name an operator types.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Sepolia => "sepolia",
            Self::Holesky => "holesky",
            Self::Hoodi => "hoodi",
            Self::Gnosis => "gnosis",
            Self::Chiado => "chiado",
            Self::Minimal => "minimal",
        }
    }

    /// The network's files, or none for the minimal test configuration.
    pub(super) const fn files(self) -> Option<NetworkFiles> {
        Some(match self {
            Self::Mainnet => NetworkFiles {
                config: include_str!("../../networks/mainnet/config.yaml"),
                boot_nodes: include_str!("../../networks/mainnet/bootstrap_nodes.yaml"),
                deposit_block: include_str!("../../networks/mainnet/deposit_contract_block.txt"),
                genesis: Some(include_bytes!("../../networks/mainnet/genesis.ssz.snappy")),
                genesis_checksum: None,
            },
            Self::Sepolia => NetworkFiles {
                config: include_str!("../../networks/sepolia/config.yaml"),
                boot_nodes: include_str!("../../networks/sepolia/bootstrap_nodes.yaml"),
                deposit_block: include_str!("../../networks/sepolia/deposit_contract_block.txt"),
                genesis: Some(include_bytes!("../../networks/sepolia/genesis.ssz.snappy")),
                genesis_checksum: None,
            },
            Self::Holesky => NetworkFiles {
                config: include_str!("../../networks/holesky/config.yaml"),
                boot_nodes: include_str!("../../networks/holesky/bootstrap_nodes.yaml"),
                deposit_block: include_str!("../../networks/holesky/deposit_contract_block.txt"),
                genesis: None,
                genesis_checksum: Some(Hash32([
                    0xd7, 0x50, 0x63, 0x96, 0x07, 0xc3, 0x37, 0xbb, 0xb1, 0x92, 0xb1, 0x5c, 0x27,
                    0xf4, 0x47, 0x73, 0x22, 0x67, 0xbf, 0x72, 0xd1, 0x65, 0x01, 0x80, 0xa0, 0xe4,
                    0x4c, 0x2d, 0x93, 0xa8, 0x07, 0x41,
                ])),
            },
            Self::Hoodi => NetworkFiles {
                config: include_str!("../../networks/hoodi/config.yaml"),
                boot_nodes: include_str!("../../networks/hoodi/bootstrap_nodes.yaml"),
                deposit_block: include_str!("../../networks/hoodi/deposit_contract_block.txt"),
                genesis: None,
                genesis_checksum: Some(Hash32([
                    0x7f, 0x42, 0x25, 0x7e, 0xf6, 0x9e, 0x05, 0x54, 0x96, 0xc9, 0x64, 0xa7, 0x53,
                    0xbb, 0x07, 0xe5, 0x40, 0x01, 0xcc, 0xd5, 0x7a, 0xb4, 0x67, 0xef, 0x72, 0xd6,
                    0x7a, 0xf0, 0x86, 0xbc, 0xfc, 0xe7,
                ])),
            },
            Self::Gnosis => NetworkFiles {
                config: include_str!("../../networks/gnosis/config.yaml"),
                boot_nodes: include_str!("../../networks/gnosis/bootstrap_nodes.yaml"),
                deposit_block: include_str!("../../networks/gnosis/deposit_contract_block.txt"),
                genesis: Some(include_bytes!("../../networks/gnosis/genesis.ssz.snappy")),
                genesis_checksum: None,
            },
            Self::Chiado => NetworkFiles {
                config: include_str!("../../networks/chiado/config.yaml"),
                boot_nodes: include_str!("../../networks/chiado/bootstrap_nodes.yaml"),
                deposit_block: include_str!("../../networks/chiado/deposit_contract_block.txt"),
                genesis: None,
                genesis_checksum: Some(Hash32([
                    0xd4, 0xa0, 0x39, 0x45, 0x4c, 0x74, 0x29, 0xf1, 0xdf, 0xaa, 0x7e, 0x11, 0xe3,
                    0x97, 0xef, 0x3d, 0x0f, 0x50, 0xd2, 0xd5, 0xe4, 0xc0, 0xe4, 0xdc, 0x04, 0x91,
                    0x9d, 0x15, 0x3a, 0xa1, 0x3a, 0xf1,
                ])),
            },
            Self::Minimal => return None,
        })
    }
}

impl fmt::Display for BuiltInNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for BuiltInNetwork {
    type Err = UnknownNetwork;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|network| network.name() == name)
            .ok_or_else(|| UnknownNetwork(name.to_owned()))
    }
}

/// A network name no compiled-in network answers to.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("unknown network {0}")]
pub(crate) struct UnknownNetwork(pub(crate) String);

#[cfg(test)]
mod tests {
    use axiom_node::GenesisState;
    use axiom_types::{ChainConfig, Gnosis, Mainnet, Preset, accessors::CoreState};
    use tokio::runtime::Builder;

    use super::*;
    use crate::{
        network::{Network, NetworkGenesis},
        run::PresetName,
    };

    /// Decodes an embedded genesis state into its root and its genesis validators root, in hex.
    fn embedded_roots<P: Preset>(network: &Network) -> (String, String) {
        let NetworkGenesis::Known(source @ GenesisState::Embedded(_)) = &network.genesis else {
            panic!("expected an embedded genesis, got {:?}", network.genesis);
        };
        let runtime = Builder::new_current_thread().build().unwrap();
        let state = runtime.block_on(source.load::<P>(&network.chain)).unwrap();
        (
            state.hash_tree_root().to_string(),
            state.genesis_validators_root().to_string(),
        )
    }

    #[test]
    fn names_round_trip() {
        for network in BuiltInNetwork::ALL {
            assert_eq!(network.name().parse(), Ok(network));
        }
        assert_eq!(
            "goerli".parse::<BuiltInNetwork>(),
            Err(UnknownNetwork("goerli".to_owned()))
        );
    }

    #[test]
    fn every_network_parses_with_its_preset_and_boot_nodes() {
        // Preset, configuration name, boot node count, and deposit block, as published.
        let expected = [
            (
                BuiltInNetwork::Mainnet,
                PresetName::Mainnet,
                "mainnet",
                11_052_984,
            ),
            (
                BuiltInNetwork::Sepolia,
                PresetName::Mainnet,
                "sepolia",
                1_273_020,
            ),
            (BuiltInNetwork::Holesky, PresetName::Mainnet, "holesky", 0),
            (BuiltInNetwork::Hoodi, PresetName::Mainnet, "hoodi", 0),
            (
                BuiltInNetwork::Gnosis,
                PresetName::Gnosis,
                "gnosis",
                19_469_077,
            ),
            (
                BuiltInNetwork::Chiado,
                PresetName::Gnosis,
                "chiado",
                155_435,
            ),
        ];
        for (network, preset, name, deposit_block) in expected {
            let parsed = Network::built_in(network).unwrap();
            assert_eq!(parsed.preset, preset, "{network}");
            assert_eq!(parsed.chain.config_name, name, "{network}");
            assert_eq!(parsed.deposit_contract_block, deposit_block, "{network}");
            assert!(!parsed.boot_enrs.is_empty(), "{network} has no boot nodes");
        }
    }

    #[test]
    fn the_mainnet_files_match_the_compiled_configuration() {
        // The published file and the spec's configuration agree on every field.
        let mainnet = Network::built_in(BuiltInNetwork::Mainnet).unwrap();
        assert_eq!(mainnet.chain, ChainConfig::mainnet());
    }

    #[test]
    fn gnosis_slots_last_five_seconds() {
        // The gnosis files give the slot only as SECONDS_PER_SLOT: 5.
        let gnosis = Network::built_in(BuiltInNetwork::Gnosis).unwrap();
        assert_eq!(gnosis.chain.slot_duration_ms, 5000);
    }

    #[test]
    fn large_genesis_states_ship_as_digests() {
        // The digests the network repositories publish for their genesis states.
        for network in [
            BuiltInNetwork::Holesky,
            BuiltInNetwork::Hoodi,
            BuiltInNetwork::Chiado,
        ] {
            let parsed = Network::built_in(network).unwrap();
            assert!(
                matches!(parsed.genesis, NetworkGenesis::Published(_)),
                "{network}"
            );
        }
        let minimal = Network::built_in(BuiltInNetwork::Minimal).unwrap();
        assert_eq!(minimal.genesis, NetworkGenesis::Unknown);
    }

    #[test]
    fn embedded_genesis_states_have_their_published_roots() {
        // State roots and genesis validators roots each network's genesis is known by.
        let mainnet = Network::built_in(BuiltInNetwork::Mainnet).unwrap();
        assert_eq!(
            embedded_roots::<Mainnet>(&mainnet),
            (
                "0x7e76880eb67bbdc86250aa578958e9d0675e64e714337855204fb5abaaf82c2b".to_owned(),
                "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95".to_owned(),
            )
        );
        let sepolia = Network::built_in(BuiltInNetwork::Sepolia).unwrap();
        assert_eq!(
            embedded_roots::<Mainnet>(&sepolia).1,
            "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"
        );
        let gnosis = Network::built_in(BuiltInNetwork::Gnosis).unwrap();
        assert_eq!(
            embedded_roots::<Gnosis>(&gnosis).1,
            "0xf5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47"
        );
    }
}
