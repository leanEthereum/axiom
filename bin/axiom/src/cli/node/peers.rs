//! How the node joins the peer-to-peer network.

use std::net::{Ipv4Addr, SocketAddr};

use axiom_discv5::Enr;
use axiom_node::{DiscoverySettings, NetworkSettings, PortMappingSettings};
use axiom_p2p::Multiaddr;
use axiom_types::ChainConfig;

use crate::cli::{Cli, CliError, arguments::Arguments};

/// Default libp2p address, the port every client uses.
const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:9000";

/// Default peer count target.
///
/// A mesh wants 6 to 12 peers per topic, per the phase0 gossipsub parameters.
/// Sixty-four peers fill every topic's mesh and leave spares.
const DEFAULT_TARGET_PEERS: usize = 64;

/// Whether and where libp2p listens on QUIC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum QuicChoice {
    /// The UDP port after the libp2p TCP port.
    #[default]
    Default,
    /// A chosen UDP port.
    Port(u16),
    /// TCP only.
    Off,
}

/// The usage lines of the peer flags.
pub(crate) const PEER_USAGE: &str = "\
    --listen-address <ADDR>      libp2p TCP address [default: 0.0.0.0:9000]
    --quic-port <PORT>           libp2p QUIC UDP port [default: the libp2p port + 1]
    --no-quic                    listen and dial over TCP only
    --boot-node <MULTIADDR>      peer to dial at startup, repeatable
    --target-peers <COUNT>       peers to keep connected [default: 64]
    --nat                        map the ports on the gateway, over NAT-PMP or UPnP
    --custody-groups <COUNT>     custody groups to keep [default: the spec's requirement]
    --discovery-port <PORT>      discv5 UDP port [default: the libp2p port]
    --enr-address <IP>           public IPv4 address announced in the node record
    --boot-enr <ENR>             discovery record to bootstrap from, repeatable,
                                 besides the network's boot nodes
    --no-discovery               find peers through boot nodes only
    --no-network                 run without peers
    --subscribe-all-subnets      join every attestation and sync committee subnet
    --disable-backfill-rate-limiting
                                 process backfill batches as fast as peers serve them
";

/// The peer flags as given.
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each switch is an independent operator flag"
)]
pub(crate) struct PeerFlags {
    /// The libp2p address.
    listen_address: Option<SocketAddr>,
    /// The libp2p QUIC choice.
    quic: QuicChoice,
    /// Gateway port mapping.
    port_mapping: PortMappingSettings,
    /// Peers to dial at startup.
    boot_nodes: Vec<Multiaddr>,
    /// Custody groups to keep.
    custody_groups: Option<u64>,
    /// Whether the network is off.
    no_network: bool,
    /// The discovery UDP port.
    discovery_port: Option<u16>,
    /// The address announced in the node record.
    enr_address: Option<Ipv4Addr>,
    /// Discovery records to bootstrap from.
    boot_enrs: Vec<Enr>,
    /// Whether discovery is off.
    no_discovery: bool,
    /// Peers to keep connected.
    target_peers: Option<usize>,
    /// Whether every subnet is joined.
    subscribe_all_subnets: bool,
    /// Whether backfill runs unpaced.
    no_backfill_rate_limiting: bool,
}

impl PeerFlags {
    /// Takes a peer flag, returning whether the flag was one.
    pub(crate) fn read<I: Iterator<Item = String>>(
        &mut self,
        flag: &str,
        words: &mut Arguments<I>,
    ) -> Result<bool, CliError> {
        match flag {
            "--listen-address" => self.listen_address = Some(words.parsed("--listen-address")?),
            "--quic-port" => self.quic = QuicChoice::Port(words.parsed("--quic-port")?),
            "--no-quic" => self.quic = QuicChoice::Off,
            "--nat" => self.port_mapping.enabled = true,
            "--boot-node" => self.boot_nodes.push(words.parsed("--boot-node")?),
            "--custody-groups" => self.custody_groups = Some(words.parsed("--custody-groups")?),
            "--no-network" => self.no_network = true,
            "--discovery-port" => self.discovery_port = Some(words.parsed("--discovery-port")?),
            "--enr-address" => self.enr_address = Some(words.parsed("--enr-address")?),
            "--boot-enr" => self.boot_enrs.push(words.parsed("--boot-enr")?),
            "--no-discovery" => self.no_discovery = true,
            "--target-peers" => self.target_peers = Some(words.parsed("--target-peers")?),
            "--subscribe-all-subnets" => self.subscribe_all_subnets = true,
            "--disable-backfill-rate-limiting" => self.no_backfill_rate_limiting = true,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The network settings, or none without a network.
    ///
    /// The network's own boot records follow the operator's, unless discovery is off.
    pub(crate) fn resolve(
        self,
        chain: &ChainConfig,
        network_boot_enrs: Vec<Enr>,
    ) -> Option<NetworkSettings> {
        if self.no_network {
            return None;
        }
        let listen_address = self
            .listen_address
            .unwrap_or_else(|| Cli::default_address(DEFAULT_LISTEN_ADDRESS));
        // Discovery shares the libp2p port number by default, over UDP.
        let discovery = (!self.no_discovery).then(|| {
            let mut boot_enrs = self.boot_enrs;
            boot_enrs.extend(network_boot_enrs);
            DiscoverySettings {
                udp_port: self.discovery_port.unwrap_or_else(|| listen_address.port()),
                enr_address: self.enr_address,
                boot_enrs,
            }
        });
        // QUIC takes the next UDP port by default, since discovery holds the libp2p one.
        let quic_port = match self.quic {
            QuicChoice::Default => Some(listen_address.port().wrapping_add(1)),
            QuicChoice::Port(port) => Some(port),
            QuicChoice::Off => None,
        };
        Some(NetworkSettings {
            listen_address,
            quic_port,
            boot_nodes: self.boot_nodes,
            port_mapping: self.port_mapping,
            discovery,
            // Every node keeps at least the spec's minimum.
            custody_group_count: self
                .custody_groups
                .unwrap_or(chain.custody_requirement)
                .max(chain.custody_requirement),
            target_peers: self.target_peers.unwrap_or(DEFAULT_TARGET_PEERS),
            subscribe_all_subnets: self.subscribe_all_subnets,
            backfill_rate_limiting: !self.no_backfill_rate_limiting,
        })
    }
}
