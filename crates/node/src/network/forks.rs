//! Every fork digest a chain's schedule produces, and the fork each one names.

use axiom_p2p::eth::MessageIds;
use axiom_types::{ChainConfig, Epoch, ForkDigest, ForkName, Root};

/// The fork digests of a chain, from genesis through every scheduled fork and blob step.
///
/// Gossip topics and response chunks name a fork only by its digest.
/// This table maps a digest back to the fork whose containers decode the message.
///
/// See `compute_fork_digest` in the phase0 and Fulu specs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForkDigests {
    /// Each digest with its fork and first epoch, in epoch order.
    entries: Vec<(ForkDigest, ForkName, Epoch)>,
}

impl ForkDigests {
    /// The digests of a chain's schedule under its genesis validators root.
    pub(crate) fn new(config: &ChainConfig, genesis_validators_root: Root) -> Self {
        let mut entries = Vec::new();
        let mut epoch = Epoch::GENESIS;
        // Each step lands on the next epoch whose digest differs.
        // The walk ends at the far future.
        while epoch != Epoch::FAR_FUTURE {
            entries.push((
                config.fork_digest(genesis_validators_root, epoch),
                config.fork_at(epoch),
                epoch,
            ));
            epoch = config.next_fork_epoch(epoch);
        }
        Self { entries }
    }

    /// The digest in force at an epoch.
    pub(crate) fn digest_at(&self, epoch: Epoch) -> ForkDigest {
        // Invariant: the first entry starts at genesis, so some entry is in force at any epoch.
        self.entries
            .iter()
            .rev()
            .find(|(.., start)| *start <= epoch)
            .map_or(ForkDigest([0; 4]), |(digest, ..)| *digest)
    }

    /// The gossip message identifier rules of the chain, one per digest.
    pub(crate) fn message_ids(&self) -> MessageIds {
        MessageIds::new(
            self.entries
                .iter()
                .map(|(digest, fork, _)| (*digest, *fork)),
        )
    }

    /// The fork a digest names, if the schedule produces it.
    pub(crate) fn fork_of(&self, digest: ForkDigest) -> Option<ForkName> {
        self.entries
            .iter()
            .find(|(known, ..)| *known == digest)
            .map(|(_, fork, _)| *fork)
    }
}

#[cfg(test)]
mod tests {
    use axiom_p2p::eth::{GossipKind, GossipTopic};

    use super::*;

    #[test]
    fn every_scheduled_fork_has_its_digest() {
        // Fixture state: Altair at 1, Bellatrix at 2, nothing later.
        let config = ChainConfig::minimal()
            .with_fork_epoch(ForkName::Altair, Epoch(1))
            .with_fork_epoch(ForkName::Bellatrix, Epoch(2));
        let root = Root([3; 32]);

        let digests = ForkDigests::new(&config, root);

        // Three forks, each at its activation epoch.
        assert_eq!(digests.entries.len(), 3);
        for (fork, epoch) in [
            (ForkName::Phase0, Epoch(0)),
            (ForkName::Altair, Epoch(1)),
            (ForkName::Bellatrix, Epoch(2)),
        ] {
            assert_eq!(digests.fork_of(config.fork_digest(root, epoch)), Some(fork));
        }
        // Epoch 5 is still Bellatrix's.
        assert_eq!(
            digests.digest_at(Epoch(5)),
            config.fork_digest(root, Epoch(2))
        );
        // A digest of another chain names nothing.
        assert_eq!(digests.fork_of(ForkDigest([0; 4])), None);
    }

    #[test]
    fn message_ids_follow_the_schedule() {
        // Fixture state: phase0 at genesis, Altair at 1.
        let config = ChainConfig::minimal().with_fork_epoch(ForkName::Altair, Epoch(1));
        let root = Root([3; 32]);
        let ids = ForkDigests::new(&config, root).message_ids();
        let topic = |epoch| {
            GossipTopic {
                fork_digest: config.fork_digest(root, Epoch(epoch)),
                kind: GossipKind::BeaconBlock,
            }
            .topic()
        };
        // Five bytes that are not snappy, so both formulas hash them raw.
        let data = [0xff; 5];

        // The phase0 topic hashes the payload alone: SHA256(00000000 || data)[:20].
        let digest = Root::sha256(&[[0, 0, 0, 0].as_slice(), &data].concat());
        assert_eq!(ids.id(&topic(0), &data).0, digest.0[..20]);

        // The Altair topic hashes the topic too, as a schedule-free rule does for every topic.
        assert_eq!(
            ids.id(&topic(1), &data),
            MessageIds::default().id(&topic(1), &data)
        );
        assert_ne!(
            ids.id(&topic(0), &data),
            MessageIds::default().id(&topic(0), &data)
        );
    }
}
