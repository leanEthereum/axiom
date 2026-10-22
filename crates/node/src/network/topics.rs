//! Which gossip topics the node belongs in, and how that set changes over time.

use std::collections::BTreeSet;

use axiom_das::NodeId;
use axiom_p2p::eth::{GossipKind, GossipTopic};
use axiom_types::{ChainConfig, ColumnIndex, Epoch, ForkDigest, Preset};

use super::subnets::AttestationSubnets;

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
/// Three things decide the set, and two of them move:
///
/// ```text
///     fork digest       changes at forks and blob schedule steps   -> every topic renamed
///     attestation subnets rotate every 256 epochs, staggered       -> two topics swapped
///     custody columns   fixed by the node identifier               -> never change
/// ```
///
/// The set is recomputed each slot and diffed against what the node joined.
/// A fork switches topics at its first epoch.
/// The spec suggests joining a fork's topics an epoch early.
/// This node does not, so it may miss a fork's first messages.
#[derive(Debug)]
pub(crate) struct Subscriptions {
    /// The node's attestation subnet assignment.
    subnets: AttestationSubnets,
    /// The chain configuration.
    config: ChainConfig,
    /// Subnets of the custody columns.
    column_subnets: BTreeSet<u64>,
    /// Topics currently joined.
    joined: BTreeSet<GossipTopic>,
}

impl Subscriptions {
    /// Nothing joined yet, for a node with an identifier and custody.
    pub(crate) fn new(
        node_id: NodeId,
        config: ChainConfig,
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
            column_subnets,
            joined: BTreeSet::new(),
        }
    }

    /// Moves to the set for an epoch and digest, returning what to join and leave.
    pub(crate) fn update<P: Preset>(
        &mut self,
        epoch: Epoch,
        fork_digest: ForkDigest,
    ) -> TopicChange {
        let subnets = self.subnets.at::<P>(epoch, &self.config);
        let attnets = self.subnets.bits::<P>(epoch, &self.config);

        // Global topics, custody column subnets, then long-lived attestation subnets.
        let mut kinds = vec![
            GossipKind::BeaconBlock,
            GossipKind::BeaconAggregateAndProof,
            GossipKind::VoluntaryExit,
            GossipKind::ProposerSlashing,
            GossipKind::AttesterSlashing,
            GossipKind::SyncCommitteeContributionAndProof,
            GossipKind::BlsToExecutionChange,
        ];
        kinds.extend(
            self.column_subnets
                .iter()
                .copied()
                .map(GossipKind::DataColumnSidecar),
        );
        kinds.extend(
            subnets
                .iter()
                .map(|subnet| GossipKind::BeaconAttestation(subnet.0)),
        );
        let wanted: BTreeSet<GossipTopic> = kinds
            .into_iter()
            .map(|kind| GossipTopic { fork_digest, kind })
            .collect();

        let change = TopicChange {
            join: wanted.difference(&self.joined).copied().collect(),
            leave: self.joined.difference(&wanted).copied().collect(),
            attnets,
        };
        self.joined = wanted;
        change
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::U256;
    use axiom_types::Mainnet;

    use super::*;

    #[test]
    fn a_fork_renames_every_topic_and_a_quiet_epoch_changes_nothing() {
        // Fixture state: node identifier zero, custody of columns 3 and 131 (both subnet 3).
        let config = ChainConfig::mainnet();
        let custody = BTreeSet::from([ColumnIndex(3), ColumnIndex(131)]);
        let mut subscriptions = Subscriptions::new(NodeId(U256::ZERO), config, &custody);
        let old = ForkDigest([1; 4]);
        let new = ForkDigest([2; 4]);

        // First update: 7 global topics, 1 column subnet, 2 attestation subnets.
        let first = subscriptions.update::<Mainnet>(Epoch(0), old);
        assert_eq!(first.join.len(), 10);
        assert_eq!(first.leave, Vec::<GossipTopic>::new());
        // Node zero joins subnets 49 and 50 at epoch 0, per the executable spec.
        assert_eq!(first.attnets, (1 << 49) | (1 << 50));

        // The same epoch again: nothing to do.
        assert_eq!(
            subscriptions.update::<Mainnet>(Epoch(0), old).join,
            Vec::new()
        );

        // A new digest replaces all ten topics.
        let fork = subscriptions.update::<Mainnet>(Epoch(1), new);
        assert_eq!(fork.join.len(), 10);
        assert_eq!(fork.leave.len(), 10);
        assert!(fork.join.iter().all(|topic| topic.fork_digest == new));
        assert!(fork.leave.iter().all(|topic| topic.fork_digest == old));
    }
}
