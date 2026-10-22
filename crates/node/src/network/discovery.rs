//! Finding peers: the node's record on discv5, and lookups for peers on its fork.

use std::{
    collections::HashSet,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use axiom_crypto::secp256k1::SecretKey;
use axiom_discv5::{
    Csprng, Enr, NodeId,
    driver::{Discv5, Discv5Events},
    service::{Config, EnrFilter, Event},
};
use axiom_p2p::{Multiaddr, PeerId, PublicKey};
use axiom_types::{ChainConfig, Epoch, Root};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::{
    NodeKey,
    record::{LocalRecord, RecordEntries},
};

/// Records a lookup asks for: enough to fill the peer table in a few rounds.
const LOOKUP_PEERS: usize = 16;

/// Upkeeps a lookup may run before a new one replaces it.
///
/// A lookup ends within a few request timeouts; several slots without an answer means it was lost.
const LOOKUP_PATIENCE: u32 = 4;

/// Where the node listens and what it announces, as the discovery record says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoverySettings {
    /// UDP port discv5 binds.
    pub udp_port: u16,
    /// Address announced to peers, when the node knows its public one.
    pub enr_address: Option<Ipv4Addr>,
    /// Records to bootstrap the routing table from.
    pub boot_enrs: Vec<Enr>,
}

/// What the node's record states at startup.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RecordSetup {
    /// The libp2p TCP port peers dial.
    pub(crate) tcp_port: u16,
    /// The libp2p QUIC port peers dial first, when QUIC listens.
    pub(crate) quic_port: Option<u16>,
    /// The wall-clock epoch.
    pub(crate) epoch: Epoch,
    /// The genesis validators root.
    pub(crate) genesis_validators_root: Root,
    /// Long-lived attestation subnets, one bit per subnet.
    pub(crate) attnets: u64,
    /// Custody groups the node keeps.
    pub(crate) custody_group_count: u64,
}

/// The addresses to try for a discovered peer, best first.
///
/// QUIC is the primary transport, so a peer reachable over both is dialed over QUIC first.
/// TCP is the fallback when the QUIC dial fails.
/// See "Transport" in the phase0 p2p-interface specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DialPlan {
    /// The peer the record names.
    pub(crate) peer: PeerId,
    /// The first address to dial.
    pub(crate) primary: Multiaddr,
    /// The address to dial when the first fails.
    pub(crate) fallback: Option<Multiaddr>,
}

impl DialPlan {
    /// The plan for a record, or nothing when it advertises no dialable endpoint.
    ///
    /// # Arguments
    ///
    /// - `quic`: whether this node speaks QUIC; without it, QUIC endpoints are ignored.
    fn new(peer: PeerId, enr: &Enr, quic: bool) -> Option<Self> {
        let endpoints = enr.endpoints();
        let quic = endpoints
            .quic_socket()
            .filter(|_| quic)
            .map(Multiaddr::from_quic);
        let tcp = endpoints.tcp_socket().map(Multiaddr::from_tcp);
        let (primary, fallback) = match (quic, tcp) {
            (Some(quic), tcp) => (quic, tcp),
            (None, Some(tcp)) => (tcp, None),
            (None, None) => return None,
        };
        Some(Self {
            peer,
            primary,
            fallback,
        })
    }
}

/// The node's discovery service.
///
/// # Overview
///
/// The node's record names its addresses, its fork, and its subnets and custody.
///
/// 1. With few peers, the service looks up a random target, keeping only records on this fork.
/// 2. It dials each found record's TCP endpoint once.
///
/// The record follows the chain: each fork, blob step, and subnet rotation re-signs it.
#[derive(Debug)]
pub(crate) struct Discovery {
    /// The discv5 driver.
    discv5: Discv5,
    /// The node's record and the consensus entries it states.
    record: LocalRecord,
    /// The key that signs the record.
    key: SecretKey,
    /// The chain configuration, for the fork schedule.
    config: ChainConfig,
    /// The root that, with each fork version, gives the fork digests.
    genesis_validators_root: Root,
    /// The record in text form, for readers outside the network loop.
    published: watch::Sender<String>,
    /// Upkeeps since the running lookup started, if one is running.
    searching: Option<u32>,
    /// Records handed out for dialing since the last lookup started.
    dialed: HashSet<NodeId>,
    /// Randomness for lookup targets.
    rng: Csprng,
    /// Whether this node speaks QUIC, so records' QUIC endpoints come first.
    quic: bool,
}

impl Discovery {
    /// Builds the local record and starts discv5.
    ///
    /// # Errors
    ///
    /// Fails when the socket cannot bind, randomness is unavailable, or the record is invalid.
    pub(crate) async fn start(
        key: &NodeKey,
        settings: &DiscoverySettings,
        config: &ChainConfig,
        setup: RecordSetup,
    ) -> io::Result<(Self, Discv5Events)> {
        let record = Self::record(key, settings, config, setup)?;
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, settings.udp_port));
        let (discv5, events) = Discv5::start(
            key.secret().clone(),
            record.enr().clone(),
            Config::default(),
            bind,
        )
        .await?;
        for boot in &settings.boot_enrs {
            if discv5.add_enr(boot.clone()).await.is_err() {
                warn!("discovery stopped while adding boot records");
            }
        }
        info!(enr = %discv5.local_enr(), "discovery started");
        let mut seed = [0; 32];
        seed.copy_from_slice(&key.node_id().0.to_le_bytes());
        Ok((
            Self {
                discv5,
                published: watch::Sender::new(record.enr().to_string()),
                record,
                key: key.secret().clone(),
                config: config.clone(),
                genesis_validators_root: setup.genesis_validators_root,
                searching: None,
                dialed: HashSet::new(),
                rng: Csprng::from_seed(seed),
                quic: setup.quic_port.is_some(),
            },
            events,
        ))
    }

    /// Re-signs the record when its consensus entries change, and hands it to discv5.
    ///
    /// The entries follow the wall-clock epoch, as the p2p specs ask.
    pub(crate) async fn refresh(&mut self, epoch: Epoch, attnets: u64) {
        let entries = RecordEntries::at(&self.config, self.genesis_validators_root, epoch, attnets);
        match self.record.update(entries, &self.key) {
            Ok(false) => {}
            Ok(true) => match self.discv5.set_local_enr(self.record.enr().clone()).await {
                Ok(()) => {
                    let text = self.record.enr().to_string();
                    info!(enr = %text, "discovery record updated");
                    self.published.send_replace(text);
                }
                Err(error) => warn!(%error, "could not update the discovery record"),
            },
            Err(error) => warn!(%error, "could not sign the discovery record"),
        }
    }

    /// Starts a lookup for peers meeting a condition, unless one is already running.
    pub(crate) async fn search(&mut self, filter: EnrFilter) {
        // A lookup that never reports back is given up after a few upkeeps.
        if let Some(waited) = &mut self.searching {
            *waited += 1;
            if *waited < LOOKUP_PATIENCE {
                return;
            }
        }
        // Peers dialed before may have left since, so each lookup may dial them again.
        self.dialed.clear();
        // A random target spreads lookups across the whole identifier space.
        let target = NodeId(self.rng.bytes());
        match self.discv5.lookup(target, filter, LOOKUP_PEERS).await {
            Ok(_) => self.searching = Some(0),
            Err(_) => warn!("discovery stopped"),
        }
    }

    /// Takes a discovery event, returning how to dial the new peers worth dialing.
    pub(crate) fn on_event(&mut self, event: Event) -> Vec<DialPlan> {
        match event {
            Event::LookupFinished { peers, .. } => {
                self.searching = None;
                debug!(found = peers.len(), "lookup finished");
                peers.iter().filter_map(|enr| self.dialable(enr)).collect()
            }
            Event::Discovered(enr) => self.dialable(&enr).into_iter().collect(),
            _ => Vec::new(),
        }
    }

    /// The node's record in text form, kept current as it changes.
    pub(crate) fn published(&self) -> watch::Receiver<String> {
        self.published.subscribe()
    }

    /// The UDP address discv5 is bound to.
    pub(crate) const fn local_addr(&self) -> SocketAddr {
        self.discv5.local_addr()
    }

    /// Stops discv5.
    pub(crate) fn shutdown(&self) {
        self.discv5.shutdown();
    }

    /// How to dial a record not dialed since the last lookup.
    ///
    /// Discovery and libp2p share the secp256k1 key, so the record names the peer too.
    fn dialable(&mut self, enr: &Enr) -> Option<DialPlan> {
        let peer = PeerId::from_public_key(&PublicKey::secp256k1(enr.public_key().to_compressed()));
        let plan = DialPlan::new(peer, enr, self.quic)?;
        self.dialed.insert(enr.node_id()).then_some(plan)
    }

    /// The node's first signed record.
    ///
    /// See "The discovery domain: discv5" in the phase0, Altair, and Fulu p2p specs.
    fn record(
        key: &NodeKey,
        settings: &DiscoverySettings,
        config: &ChainConfig,
        setup: RecordSetup,
    ) -> io::Result<LocalRecord> {
        let mut base = Enr::builder()
            .seq(1)
            .tcp4(setup.tcp_port)
            .udp4(settings.udp_port)
            .custody_group_count(setup.custody_group_count);
        if let Some(port) = setup.quic_port {
            base = base.quic4(port);
        }
        // Without a known public address, peers learn this node's address from its packets.
        if let Some(address) = settings.enr_address {
            base = base.ip4(address);
        }
        let entries = RecordEntries::at(
            config,
            setup.genesis_validators_root,
            setup.epoch,
            setup.attnets,
        );
        LocalRecord::new(base, entries, key.secret())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    /// A record at 10.0.0.1 with the given ports, signed by a fixed key.
    fn record(tcp: Option<u16>, quic: Option<u16>) -> Enr {
        let key = SecretKey::from_bytes(&[7; 32]).unwrap();
        let mut builder = Enr::builder().ip4(Ipv4Addr::new(10, 0, 0, 1));
        if let Some(port) = tcp {
            builder = builder.tcp4(port);
        }
        if let Some(port) = quic {
            builder = builder.quic4(port);
        }
        builder.build(&key).unwrap()
    }

    fn peer() -> PeerId {
        let key = SecretKey::from_bytes(&[7; 32]).unwrap();
        PeerId::from_public_key(&PublicKey::secp256k1(key.public_key().to_compressed()))
    }

    #[test]
    fn quic_comes_first_with_tcp_as_the_fallback() {
        let tcp = Multiaddr::from_tcp(SocketAddr::from(([10, 0, 0, 1], 9000)));
        let quic = Multiaddr::from_quic(SocketAddr::from(([10, 0, 0, 1], 9001)));

        // Both endpoints: QUIC first, TCP behind it.
        let both = record(Some(9000), Some(9001));
        assert_eq!(
            DialPlan::new(peer(), &both, true),
            Some(DialPlan {
                peer: peer(),
                primary: quic.clone(),
                fallback: Some(tcp.clone()),
            })
        );

        // A node without QUIC ignores the QUIC endpoint.
        assert_eq!(
            DialPlan::new(peer(), &both, false),
            Some(DialPlan {
                peer: peer(),
                primary: tcp,
                fallback: None,
            })
        );

        // QUIC alone has no fallback; a record without either is not dialable.
        assert_eq!(
            DialPlan::new(peer(), &record(None, Some(9001)), true),
            Some(DialPlan {
                peer: peer(),
                primary: quic,
                fallback: None,
            })
        );
        assert_eq!(DialPlan::new(peer(), &record(None, None), true), None);
    }
}
