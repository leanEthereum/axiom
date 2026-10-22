//! Which subnets a peer serves, and which subnets the node needs peers on.
//!
//! A peer states its long-lived attestation and sync committee subnets in its metadata.
//! Its data column subnets follow from its node id and custody group count, per the Fulu DAS spec.

use std::collections::BTreeSet;

use axiom_crypto::{keccak::Keccak256, secp256k1::PublicKey as Secp256k1Key};
use axiom_das::{CustodyGroup, NodeId};
use axiom_discv5::service::EnrFilter;
use axiom_p2p::{
    KeyType, PeerId,
    eth::{GossipKind, reqresp::MetaData},
};
use axiom_ssz::{Ssz, U256};
use axiom_types::{ChainConfig, ForkDigest, Preset};

/// Bytes of MetaData v2: v3 without the custody group count.
const METADATA_V2_LEN: usize = 17;

/// A gossip subnet the node may need peers on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Subnet {
    /// An attestation subnet.
    Attestation(u64),
    /// A sync committee subnet.
    SyncCommittee(u64),
    /// A data column sidecar subnet.
    DataColumn(u64),
}

impl Subnet {
    /// The subnet a gossip topic kind belongs to, if any.
    pub(crate) const fn of(kind: GossipKind) -> Option<Self> {
        match kind {
            GossipKind::BeaconAttestation(subnet) => Some(Self::Attestation(subnet)),
            GossipKind::SyncCommittee(subnet) => Some(Self::SyncCommittee(subnet)),
            GossipKind::DataColumnSidecar(subnet) => Some(Self::DataColumn(subnet)),
            _ => None,
        }
    }

    /// The kind and index labels metrics use.
    pub(crate) const fn kind_label(self) -> &'static str {
        match self {
            Self::Attestation(_) => "attestation",
            Self::SyncCommittee(_) => "sync_committee",
            Self::DataColumn(_) => "data_column",
        }
    }

    /// The subnet's index within its kind.
    pub(crate) const fn index(self) -> u64 {
        match self {
            Self::Attestation(index) | Self::SyncCommittee(index) | Self::DataColumn(index) => {
                index
            }
        }
    }

    /// A discovery condition for records serving the subnet on a fork.
    ///
    /// A column subnet is served by the custody groups whose columns land on it.
    /// The condition asks for the first such group; any one serves.
    pub(crate) fn filter<P: Preset>(
        self,
        fork_digest: ForkDigest,
        config: &ChainConfig,
    ) -> EnrFilter {
        let subnet = match self {
            Self::Attestation(index) => EnrFilter::AttestationSubnet(index as usize),
            Self::SyncCommittee(index) => EnrFilter::SyncCommitteeSubnet(index as usize),
            Self::DataColumn(index) => {
                let groups = config.number_of_custody_groups;
                let group = (0..groups).map(CustodyGroup).find(|group| {
                    group.columns::<P>(config).is_ok_and(|columns| {
                        columns.iter().any(|column| {
                            column.0 % config.data_column_sidecar_subnet_count == index
                        })
                    })
                });
                match group {
                    Some(group) => EnrFilter::CustodyGroup(group),
                    None => EnrFilter::Any,
                }
            }
        };
        EnrFilter::All(vec![EnrFilter::ForkDigest(fork_digest), subnet])
    }
}

/// The subnets a peer serves.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PeerSubnets {
    /// Long-lived attestation subnets, one bit per subnet.
    attestation: u64,
    /// Sync committee subnets, one bit per subnet.
    sync: u8,
    /// Data column subnets.
    columns: BTreeSet<u64>,
    /// The metadata sequence number they came from.
    pub(crate) seq_number: u64,
}

impl PeerSubnets {
    /// Reads the subnets of a metadata response, version 2 or 3.
    ///
    /// Version 2 carries no custody group count; the peer then counts as custodying the minimum.
    ///
    /// # Returns
    ///
    /// The subnets, or nothing when the bytes do not decode.
    pub(crate) fn from_metadata<P: Preset>(
        peer: &PeerId,
        bytes: &[u8],
        config: &ChainConfig,
    ) -> Option<Self> {
        let metadata = if bytes.len() == METADATA_V2_LEN {
            // The v2 layout is the v3 layout without its last field.
            let mut padded = bytes.to_vec();
            padded.extend_from_slice(&config.custody_requirement.to_le_bytes());
            MetaData::decode(&padded).ok()?
        } else {
            MetaData::decode(bytes).ok()?
        };
        let attestation = metadata
            .attnets
            .iter()
            .enumerate()
            .fold(0_u64, |bits, (index, set)| bits | (u64::from(set) << index));
        let sync = metadata
            .syncnets
            .iter()
            .enumerate()
            .fold(0_u8, |bits, (index, set)| bits | (u8::from(set) << index));
        let columns = Self::column_subnets::<P>(peer, metadata.custody_group_count, config)
            .unwrap_or_default();
        Some(Self {
            attestation,
            sync,
            columns,
            seq_number: metadata.seq_number,
        })
    }

    /// The column subnets of a peer's custody, from its identity.
    fn column_subnets<P: Preset>(
        peer: &PeerId,
        count: u64,
        config: &ChainConfig,
    ) -> Option<BTreeSet<u64>> {
        let node_id = Self::node_id(peer)?;
        let mut subnets = BTreeSet::new();
        // A peer claiming more groups than exist is held to all of them.
        let count = count.min(config.number_of_custody_groups);
        for group in node_id.custody_groups(count, config).ok()? {
            for column in group.columns::<P>(config).ok()? {
                subnets.insert(column.0 % config.data_column_sidecar_subnet_count);
            }
        }
        Some(subnets)
    }

    /// The discovery node id of a secp256k1 peer: keccak256 of its uncompressed key, as EIP-778 defines.
    fn node_id(peer: &PeerId) -> Option<NodeId> {
        let key = peer.public_key()?;
        if key.key_type != KeyType::Secp256k1 {
            return None;
        }
        let point = Secp256k1Key::from_sec1_bytes(&key.data)
            .ok()?
            .to_uncompressed();
        let mut digest = Keccak256::digest(&point[1..]);
        // The digest reads as a big-endian integer; the stored form is little-endian.
        digest.reverse();
        Some(NodeId(U256(digest)))
    }

    /// Whether the peer serves a subnet.
    pub(crate) fn covers(&self, subnet: Subnet) -> bool {
        match subnet {
            Subnet::Attestation(index) => index < 64 && self.attestation >> index & 1 == 1,
            Subnet::SyncCommittee(index) => index < 8 && self.sync >> index & 1 == 1,
            Subnet::DataColumn(index) => self.columns.contains(&index),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_p2p::{
        Keypair,
        eth::reqresp::{Attnets, Syncnets},
    };
    use axiom_types::Mainnet;

    use super::*;

    fn metadata(attnets: &[usize], syncnets: &[usize], custody: u64) -> MetaData {
        let mut bits = Attnets::default();
        for subnet in attnets {
            bits.set(*subnet, true);
        }
        let mut sync = Syncnets::default();
        for subnet in syncnets {
            sync.set(*subnet, true);
        }
        MetaData {
            seq_number: 7,
            attnets: bits,
            syncnets: sync,
            custody_group_count: custody,
        }
    }

    #[test]
    fn reads_attestation_sync_and_column_subnets() {
        let config = ChainConfig::mainnet();
        let peer = Keypair::from_secret_bytes(&[3; 32]).unwrap().peer_id();
        // Subnets 0 and 63, sync subnet 2, and all 128 custody groups.
        let bytes = metadata(&[0, 63], &[2], 128).encode();
        let subnets = PeerSubnets::from_metadata::<Mainnet>(&peer, &bytes, &config).unwrap();
        assert_eq!(subnets.seq_number, 7);
        assert!(subnets.covers(Subnet::Attestation(0)));
        assert!(subnets.covers(Subnet::Attestation(63)));
        assert!(!subnets.covers(Subnet::Attestation(1)));
        assert!(!subnets.covers(Subnet::Attestation(64)));
        assert!(subnets.covers(Subnet::SyncCommittee(2)));
        assert!(!subnets.covers(Subnet::SyncCommittee(3)));
        // Full custody serves every column subnet.
        assert!((0..128).all(|subnet| subnets.covers(Subnet::DataColumn(subnet))));
    }

    #[test]
    fn version_two_counts_the_minimum_custody() {
        let config = ChainConfig::mainnet();
        let peer = Keypair::from_secret_bytes(&[3; 32]).unwrap().peer_id();
        let mut bytes = metadata(&[5], &[], 0).encode();
        bytes.truncate(METADATA_V2_LEN);
        let subnets = PeerSubnets::from_metadata::<Mainnet>(&peer, &bytes, &config).unwrap();
        assert!(subnets.covers(Subnet::Attestation(5)));
        // The custody requirement of 4 groups gives 4 of the 128 column subnets.
        assert_eq!(subnets.columns.len(), 4);
        // Garbage does not decode.
        assert_eq!(
            PeerSubnets::from_metadata::<Mainnet>(&peer, &[1, 2, 3], &config),
            None
        );
    }

    #[test]
    fn subnets_of_gossip_topics() {
        assert_eq!(
            Subnet::of(GossipKind::BeaconAttestation(9)),
            Some(Subnet::Attestation(9))
        );
        assert_eq!(
            Subnet::of(GossipKind::DataColumnSidecar(3)),
            Some(Subnet::DataColumn(3))
        );
        assert_eq!(Subnet::of(GossipKind::BeaconBlock), None);
        // On mainnet 128 groups map one to one onto 128 column subnets.
        let config = ChainConfig::mainnet();
        let filter = Subnet::DataColumn(17).filter::<Mainnet>(ForkDigest([1, 2, 3, 4]), &config);
        assert_eq!(
            filter,
            EnrFilter::All(vec![
                EnrFilter::ForkDigest(ForkDigest([1, 2, 3, 4])),
                EnrFilter::CustodyGroup(CustodyGroup(17)),
            ])
        );
    }
}
