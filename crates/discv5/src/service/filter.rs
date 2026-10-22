//! Predicates over node records, for searches that want peers of a certain kind.

use axiom_das::{CustodyGroup, NodeId as CustodyNodeId};
use axiom_ssz::U256;
use axiom_types::{ChainConfig, ForkDigest};

use crate::enr::Enr;

/// A condition a record must meet to count as a search result.
///
/// A closed set of conditions, combined with a conjunction.
///
/// # Examples
///
/// ```
/// use axiom_discv5::service::EnrFilter;
/// use axiom_types::ForkDigest;
///
/// // Peers on the right fork that serve attestation subnet 17.
/// let filter = EnrFilter::All(vec![
///     EnrFilter::ForkDigest(ForkDigest([0xab, 0xcd, 0xef, 0x01])),
///     EnrFilter::AttestationSubnet(17),
/// ]);
/// assert!(matches!(filter, EnrFilter::All(_)));
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum EnrFilter {
    /// Every record.
    #[default]
    Any,

    /// Records whose fork identifier carries this digest.
    ForkDigest(ForkDigest),

    /// Records subscribed to an attestation subnet.
    AttestationSubnet(usize),

    /// Records subscribed to a sync committee subnet.
    SyncCommitteeSubnet(usize),

    /// Records whose node custodies a group, Fulu.
    ///
    /// A record without a custody count is taken to custody the minimum the spec requires.
    CustodyGroup(CustodyGroup),

    /// Records advertising at least this many custody groups.
    MinCustodyGroupCount(u64),

    /// Records meeting every condition.
    All(Vec<Self>),
}

impl EnrFilter {
    /// Whether a record meets the condition.
    #[must_use]
    pub fn matches(&self, enr: &Enr, chain: &ChainConfig) -> bool {
        let eth2 = enr.eth2();
        match self {
            Self::Any => true,
            Self::ForkDigest(digest) => eth2
                .fork_id
                .is_some_and(|fork_id| fork_id.fork_digest == *digest),
            Self::AttestationSubnet(subnet) => eth2.on_attestation_subnet(*subnet),
            Self::SyncCommitteeSubnet(subnet) => eth2.on_sync_subnet(*subnet),
            Self::CustodyGroup(group) => {
                // The custody draw takes the id as a 256-bit number: big-endian bytes, reversed.
                let count = eth2
                    .custody_group_count
                    .unwrap_or(chain.custody_requirement);
                let mut bytes = enr.node_id().0;
                bytes.reverse();
                CustodyNodeId(U256(bytes))
                    .custody_groups(count, chain)
                    .is_ok_and(|groups| groups.contains(group))
            }
            Self::MinCustodyGroupCount(minimum) => eth2
                .custody_group_count
                .is_some_and(|count| count >= *minimum),
            Self::All(filters) => filters.iter().all(|filter| filter.matches(enr, chain)),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::secp256k1::SecretKey;
    use axiom_types::{Epoch, Version};

    use super::*;
    use crate::enr::{Attnets, EnrForkId};

    #[test]
    fn conditions() {
        // A record on fork 0x01020304, subnet 3, with 128 custody groups: every group.
        let chain = ChainConfig::mainnet();
        let key = SecretKey::from_bytes(&[1; 32]).unwrap();
        let mut attnets = Attnets::new();
        attnets.set(3, true);
        let enr = Enr::builder()
            .fork_id(&EnrForkId {
                fork_digest: ForkDigest([1, 2, 3, 4]),
                next_fork_version: Version([0; 4]),
                next_fork_epoch: Epoch(u64::MAX),
            })
            .attnets(&attnets)
            .custody_group_count(128)
            .build(&key)
            .unwrap();
        assert!(EnrFilter::Any.matches(&enr, &chain));
        assert!(EnrFilter::ForkDigest(ForkDigest([1, 2, 3, 4])).matches(&enr, &chain));
        assert!(!EnrFilter::ForkDigest(ForkDigest([0; 4])).matches(&enr, &chain));
        assert!(EnrFilter::AttestationSubnet(3).matches(&enr, &chain));
        assert!(!EnrFilter::AttestationSubnet(4).matches(&enr, &chain));
        assert!(!EnrFilter::SyncCommitteeSubnet(0).matches(&enr, &chain));
        assert!(EnrFilter::CustodyGroup(CustodyGroup(127)).matches(&enr, &chain));
        assert!(EnrFilter::MinCustodyGroupCount(64).matches(&enr, &chain));
        assert!(
            !EnrFilter::All(vec![EnrFilter::Any, EnrFilter::AttestationSubnet(9)])
                .matches(&enr, &chain)
        );
    }

    #[test]
    fn default_custody_is_the_requirement() {
        // Without cgc, a node custodies 4 of 128 groups: exactly 4 groups match.
        let chain = ChainConfig::mainnet();
        let key = SecretKey::from_bytes(&[2; 32]).unwrap();
        let enr = Enr::builder().build(&key).unwrap();
        let matching = (0..128)
            .filter(|&group| EnrFilter::CustodyGroup(CustodyGroup(group)).matches(&enr, &chain))
            .count();
        assert_eq!(matching, 4);
        assert!(!EnrFilter::MinCustodyGroupCount(1).matches(&enr, &chain));
    }
}
