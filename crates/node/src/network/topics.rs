//! Which gossip topics the node belongs in, and how that set changes over time.

use std::collections::BTreeSet;

use axiom_das::NodeId;
use axiom_gossip::BlobSubnets;
use axiom_p2p::eth::{GossipKind, GossipTopic};
use axiom_types::{
    ChainConfig, ColumnIndex, Epoch, ForkName, Preset, Root, constants::SYNC_COMMITTEE_SUBNET_COUNT,
};

use super::{peers::Subnet, subnets::AttestationSubnets};

/// Epochs a fork's topics are kept after the next fork starts.
///
/// See "Transitioning the gossip" in the Altair p2p spec.
const EPOCHS_KEPT_AFTER_FORK: u64 = 2;

/// Epochs a fork's topics are joined before the fork starts.
///
/// The spec asks for a join in advance of the fork, so meshes form before the first message.
const EPOCHS_JOINED_BEFORE_FORK: u64 = 1;

/// The topics to join and leave, after a change of epoch or fork.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TopicChange {
    /// Topics to subscribe to.
    pub(crate) join: Vec<GossipTopic>,
    /// Topics to unsubscribe from.
    pub(crate) leave: Vec<GossipTopic>,
    /// The long-lived attestation subnets, as a 64-bit field for the metadata.
    pub(crate) attnets: u64,
}

/// The node's gossip subscriptions.
///
/// # Overview
///
/// Four things decide the set, and three of them move:
///
/// ```text
///     fork digest          changes at forks and blob steps   renames every topic
///     fork                 changes at forks                  adds and drops topics
///     attestation subnets  rotate every 256 epochs           swaps two topics
///     custody columns      fixed by the node identifier      never changes
/// ```
///
/// The set is recomputed each slot and diffed against what the node joined.
/// It is the union of the sets of a few epochs around the current one.
/// So a fork's topics are joined an epoch early, and kept two epochs after the next fork.
#[derive(Debug)]
pub(crate) struct Subscriptions {
    /// The node's attestation subnet assignment.
    subnets: AttestationSubnets,
    /// The chain configuration.
    config: ChainConfig,
    /// The root that, with the fork version, gives each digest.
    genesis_validators_root: Root,
    /// Subnets of the custody columns.
    column_subnets: BTreeSet<u64>,
    /// Topics currently joined.
    joined: BTreeSet<GossipTopic>,
    /// Whether every attestation and sync committee subnet is joined.
    all_subnets: bool,
}

impl Subscriptions {
    /// Nothing joined yet, for a node with an identifier and custody.
    pub(crate) fn new(
        node_id: NodeId,
        config: ChainConfig,
        genesis_validators_root: Root,
        custody: &BTreeSet<ColumnIndex>,
    ) -> Self {
        // Columns map onto subnets by index modulo the subnet count.
        let column_subnets = custody
            .iter()
            .map(|column| column.0 % config.data_column_sidecar_subnet_count)
            .collect();
        Self {
            subnets: AttestationSubnets::new(node_id),
            config,
            genesis_validators_root,
            column_subnets,
            joined: BTreeSet::new(),
            all_subnets: false,
        }
    }

    /// Joins every attestation and sync committee subnet, as aggregating services need.
    #[must_use]
    pub(crate) const fn subscribing_all(mut self) -> Self {
        self.all_subnets = true;
        self
    }

    /// Moves to the set for an epoch, returning what to join and leave.
    pub(crate) fn update<P: Preset>(&mut self, epoch: Epoch) -> TopicChange {
        let first = epoch.0.saturating_sub(EPOCHS_KEPT_AFTER_FORK);
        let last = epoch.0.saturating_add(EPOCHS_JOINED_BEFORE_FORK);
        let mut wanted = BTreeSet::new();
        for around in first..=last {
            wanted.extend(self.topics_at::<P>(Epoch(around)));
        }

        let change = TopicChange {
            join: wanted.difference(&self.joined).copied().collect(),
            leave: self.joined.difference(&wanted).copied().collect(),
            attnets: if self.all_subnets {
                AttestationSubnets::all(&self.config)
            } else {
                self.subnets.bits::<P>(epoch, &self.config)
            },
        };
        self.joined = wanted;
        change
    }

    /// The subnets of the topics joined, which peer management keeps served.
    pub(crate) fn needed_subnets(&self) -> BTreeSet<Subnet> {
        self.joined
            .iter()
            .filter_map(|topic| Subnet::of(topic.kind))
            .collect()
    }

    /// The topics of one epoch: its fork's global topics and the node's subnets, under its digest.
    fn topics_at<P: Preset>(&self, epoch: Epoch) -> impl Iterator<Item = GossipTopic> {
        let fork = self.config.fork_at(epoch);
        let fork_digest = self.config.fork_digest(self.genesis_validators_root, epoch);
        let mut kinds = Self::global_kinds(fork);
        if self.all_subnets {
            kinds.extend(
                (0..self.config.attestation_subnet_count).map(GossipKind::BeaconAttestation),
            );
            // Sync committee subnets exist from the fork that brought sync contributions.
            if kinds.contains(&GossipKind::SyncCommitteeContributionAndProof) {
                kinds.extend((0..SYNC_COMMITTEE_SUBNET_COUNT).map(GossipKind::SyncCommittee));
            }
        } else {
            kinds.extend(
                self.subnets
                    .at::<P>(epoch, &self.config)
                    .iter()
                    .map(|subnet| GossipKind::BeaconAttestation(subnet.0)),
            );
        }
        // Sidecars carry no custody before Fulu: a node takes every blob of every block.
        if let Some(blobs) = BlobSubnets::of(fork, &self.config) {
            kinds.extend((0..blobs.subnet_count).map(GossipKind::BlobSidecar));
        }
        if fork.blob_data().is_columns() {
            kinds.extend(
                self.column_subnets
                    .iter()
                    .copied()
                    .map(GossipKind::DataColumnSidecar),
            );
        }
        kinds
            .into_iter()
            .map(move |kind| GossipTopic { fork_digest, kind })
    }

    /// The global topics of a fork: those of the fork before it, and its own.
    ///
    /// No fork removed a global topic; Fulu only removed the blob subnets.
    /// See the topics sections of each fork's p2p spec.
    fn global_kinds(fork: ForkName) -> Vec<GossipKind> {
        let mut kinds = fork.previous().map_or_else(Vec::new, Self::global_kinds);
        kinds.extend_from_slice(match fork {
            ForkName::Phase0 => &[
                GossipKind::BeaconBlock,
                GossipKind::BeaconAggregateAndProof,
                GossipKind::VoluntaryExit,
                GossipKind::ProposerSlashing,
                GossipKind::AttesterSlashing,
            ],
            ForkName::Altair => &[
                GossipKind::SyncCommitteeContributionAndProof,
                GossipKind::LightClientFinalityUpdate,
                GossipKind::LightClientOptimisticUpdate,
            ],
            ForkName::Capella => &[GossipKind::BlsToExecutionChange],
            ForkName::Gloas => &[
                GossipKind::ExecutionPayload,
                GossipKind::PayloadAttestationMessage,
                GossipKind::ExecutionPayloadBid,
                GossipKind::ProposerPreferences,
            ],
            ForkName::Bellatrix | ForkName::Deneb | ForkName::Electra | ForkName::Fulu => &[],
        });
        kinds
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::U256;
    use axiom_types::{Mainnet, Minimal};

    use super::*;

    #[test]
    fn a_quiet_epoch_changes_nothing() {
        // Fixture state: mainnet with every fork at genesis, and node zero.
        // It custodies columns 3 and 131.
        let config = ChainConfig::mainnet().with_forks_at_genesis(ForkName::Fulu);
        let custody = BTreeSet::from([ColumnIndex(3), ColumnIndex(131)]);
        let mut subscriptions =
            Subscriptions::new(NodeId(U256::ZERO), config, Root::ZERO, &custody);

        // First update: 9 global topics, 1 column subnet, 2 attestation subnets.
        let first = subscriptions.update::<Mainnet>(Epoch(10));
        assert_eq!(first.join.len(), 12);
        assert_eq!(first.leave, Vec::<GossipTopic>::new());
        // Node zero joins subnets 49 and 50 at epoch 10, per the executable spec.
        assert_eq!(first.attnets, (1 << 49) | (1 << 50));

        // The same epoch again: nothing to do.
        assert_eq!(
            subscriptions.update::<Mainnet>(Epoch(10)),
            TopicChange {
                attnets: first.attnets,
                ..TopicChange::default()
            }
        );
    }

    #[test]
    fn a_fork_is_joined_early_and_left_late() {
        // Fixture state: minimal phase0, Altair at epoch 4, no custody columns.
        let config = ChainConfig::minimal().with_fork_epoch(ForkName::Altair, Epoch(4));
        let root = Root::ZERO;
        let phase0 = config.fork_digest(root, Epoch(3));
        let altair = config.fork_digest(root, Epoch(4));
        let mut subscriptions =
            Subscriptions::new(NodeId(U256::ZERO), config, root, &BTreeSet::new());
        let digests = |topics: &[GossipTopic]| -> BTreeSet<_> {
            topics.iter().map(|topic| topic.fork_digest).collect()
        };

        // Epoch 2: two epochs before the fork, only phase0 topics.
        let start = subscriptions.update::<Minimal>(Epoch(2));
        assert_eq!(digests(&start.join), BTreeSet::from([phase0]));

        // Epoch 3: one epoch before, Altair's topics join, with the three Altair adds.
        let early = subscriptions.update::<Minimal>(Epoch(3));
        assert_eq!(digests(&early.join), BTreeSet::from([altair]));
        assert!(
            early
                .join
                .iter()
                .any(|topic| topic.kind == GossipKind::LightClientFinalityUpdate)
        );
        assert_eq!(early.leave, Vec::new());

        // Epochs 4 and 5: both forks kept.
        assert_eq!(subscriptions.update::<Minimal>(Epoch(5)).leave, Vec::new());

        // Epoch 6: two epochs after the fork, phase0's topics go.
        let late = subscriptions.update::<Minimal>(Epoch(6));
        assert_eq!(digests(&late.leave), BTreeSet::from([phase0]));
    }

    #[test]
    fn each_fork_adds_its_own_global_topics() {
        // Phase0 has five global topics; Altair adds three, Capella one, Gloas four.
        let counts: Vec<usize> = ForkName::ALL
            .into_iter()
            .map(|fork| Subscriptions::global_kinds(fork).len())
            .collect();
        assert_eq!(counts, [5, 8, 8, 9, 9, 9, 9, 13]);
    }
}
