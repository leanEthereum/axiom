//! Finding peers: the node's record on discv5, and lookups for peers on its fork.

use std::{
    collections::HashSet,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use axiom_discv5::{
    Csprng, Enr, NodeId,
    driver::{Discv5, Discv5Events},
    enr::EnrForkId,
    service::{Config, EnrFilter, Event},
};
use axiom_p2p::{Multiaddr, PeerId, PublicKey};
use axiom_ssz::BitVector;
use axiom_types::{ChainConfig, Epoch, ForkDigest, Root};
use tracing::{debug, info, warn};

use super::NodeKey;

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

/// What the node's record states, fixed at startup.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LocalRecord {
    /// The libp2p TCP port peers dial.
    pub(crate) tcp_port: u16,
    /// The fork digest of the current epoch.
    pub(crate) fork_digest: ForkDigest,
    /// The current epoch.
    pub(crate) epoch: Epoch,
    /// The genesis validators root.
    pub(crate) genesis_validators_root: Root,
    /// Long-lived attestation subnets, one bit per subnet.
    pub(crate) attnets: u64,
    /// Custody groups the node keeps.
    pub(crate) custody_group_count: u64,
}

/// The node's discovery service.
///
/// # Overview
///
/// ```text
///     record: ip, tcp, udp, eth2 fork id, attnets, custody group count, next fork digest
///     few peers ──> lookup for a random target, only records on this fork
///     found ──────> dial each record's TCP endpoint once
/// ```
///
/// The record is built once at startup.
/// It does not yet follow subnet rotations or forks, so it can go stale on a long run.
#[derive(Debug)]
pub(crate) struct Discovery {
    /// The discv5 driver.
    discv5: Discv5,
    /// Upkeeps since the running lookup started, if one is running.
    searching: Option<u32>,
    /// Records handed out for dialing since the last lookup started.
    dialed: HashSet<NodeId>,
    /// Randomness for lookup targets.
    rng: Csprng,
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
        record: LocalRecord,
    ) -> io::Result<(Self, Discv5Events)> {
        let enr = Self::record(key, settings, config, record)?;
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, settings.udp_port));
        let (discv5, events) =
            Discv5::start(key.secret().clone(), enr, Config::default(), bind).await?;
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
                searching: None,
                dialed: HashSet::new(),
                rng: Csprng::from_seed(seed),
            },
            events,
        ))
    }

    /// Starts a lookup for peers on a fork, unless one is already running.
    pub(crate) async fn search(&mut self, fork_digest: ForkDigest) {
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
        match self
            .discv5
            .lookup(target, EnrFilter::ForkDigest(fork_digest), LOOKUP_PEERS)
            .await
        {
            Ok(_) => self.searching = Some(0),
            Err(_) => warn!("discovery stopped"),
        }
    }

    /// Takes a discovery event, returning the addresses of new peers worth dialing.
    pub(crate) fn on_event(&mut self, event: Event) -> Vec<(PeerId, Multiaddr)> {
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

    /// The node's signed record.
    pub(crate) const fn enr(&self) -> &Enr {
        self.discv5.local_enr()
    }

    /// The UDP address discv5 is bound to.
    pub(crate) const fn local_addr(&self) -> SocketAddr {
        self.discv5.local_addr()
    }

    /// Stops discv5.
    pub(crate) fn shutdown(&self) {
        self.discv5.shutdown();
    }

    /// The peer and TCP address of a record not dialed since the last lookup.
    ///
    /// Discovery and libp2p share the secp256k1 key, so the record names the peer too.
    fn dialable(&mut self, enr: &Enr) -> Option<(PeerId, Multiaddr)> {
        let address = enr.endpoints().tcp_socket()?;
        let peer = PeerId::from_public_key(&PublicKey::secp256k1(enr.public_key().to_compressed()));
        self.dialed
            .insert(enr.node_id())
            .then(|| (peer, Multiaddr::from_tcp(address)))
    }

    /// The node's signed record.
    ///
    /// See "The discovery domain: discv5" in the phase0, Altair, and Fulu p2p specs.
    fn record(
        key: &NodeKey,
        settings: &DiscoverySettings,
        config: &ChainConfig,
        record: LocalRecord,
    ) -> io::Result<Enr> {
        // The next fork, regular or blob-only, and the version in force once it comes.
        let next_epoch = config.next_fork_epoch(record.epoch);
        let next_version = if next_epoch == Epoch::FAR_FUTURE {
            config.fork_version_at(record.epoch)
        } else {
            config.fork_version_at(next_epoch)
        };
        // With no fork scheduled, the next digest is all zeros.
        let next_digest = if next_epoch == Epoch::FAR_FUTURE {
            ForkDigest::ZERO
        } else {
            config.fork_digest(record.genesis_validators_root, next_epoch)
        };
        let mut attnets = BitVector::default();
        for index in 0..64 {
            attnets.set(index, record.attnets >> index & 1 == 1);
        }

        let mut builder = Enr::builder()
            .seq(1)
            .tcp4(record.tcp_port)
            .udp4(settings.udp_port)
            .fork_id(&EnrForkId {
                fork_digest: record.fork_digest,
                next_fork_version: next_version,
                next_fork_epoch: next_epoch,
            })
            .attnets(&attnets)
            .syncnets(&BitVector::default())
            .custody_group_count(record.custody_group_count)
            .next_fork_digest(next_digest);
        // Without a known public address, peers learn this node's address from its packets.
        if let Some(address) = settings.enr_address {
            builder = builder.ip4(address);
        }
        builder
            .build(key.secret())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))
    }
}
