//! Custody assignment: which columns a node keeps, derived from its node identifier.

use std::{error::Error, fmt};

use axiom_ssz::U256;
use axiom_types::{ChainConfig, ColumnIndex, Preset, Root};

/// A node's identifier on the discovery network, a 256-bit number.
///
/// Custody is a function of it, so any peer can check what a node must hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NodeId(pub U256);

/// One of the groups the columns are partitioned into.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CustodyGroup(pub u64);

/// A custody request the configuration cannot satisfy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyError {
    /// More groups were asked for than exist.
    TooManyGroups {
        /// Groups asked for.
        requested: u64,
        /// Groups that exist.
        available: u64,
    },
    /// A group index is out of range.
    UnknownGroup(CustodyGroup),
}

impl fmt::Display for CustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyGroups {
                requested,
                available,
            } => {
                write!(f, "{requested} custody groups requested, {available} exist")
            }
            Self::UnknownGroup(group) => write!(f, "custody group {} does not exist", group.0),
        }
    }
}

impl Error for CustodyError {}

impl NodeId {
    /// The groups a node custodies, sorted.
    ///
    /// # Algorithm
    ///
    /// Hash the identifier, then the identifier plus one, and so on.
    /// Each hash names a group, modulo the group count.
    /// Keep drawing until enough distinct groups are named.
    ///
    /// The draw is deterministic, so peers agree on every node's custody.
    /// See `get_custody_groups` in the Fulu DAS core spec.
    ///
    /// # Errors
    ///
    /// Fails when more groups are requested than exist.
    pub fn custody_groups(
        self,
        count: u64,
        config: &ChainConfig,
    ) -> Result<Vec<CustodyGroup>, CustodyError> {
        let total = config.number_of_custody_groups;
        if count > total {
            return Err(CustodyError::TooManyGroups {
                requested: count,
                available: total,
            });
        }
        if count == total {
            return Ok((0..total).map(CustodyGroup).collect());
        }

        let mut groups = Vec::with_capacity(count as usize);
        let mut current = self.0;
        while (groups.len() as u64) < count {
            let digest = Root::sha256(&current.to_le_bytes());
            let mut word = [0; 8];
            word.copy_from_slice(&digest.0[..8]);
            let group = CustodyGroup(u64::from_le_bytes(word) % total);
            if !groups.contains(&group) {
                groups.push(group);
            }
            // The identifier wraps around at 2^256 rather than overflowing.
            current = current.wrapping_increment();
        }
        groups.sort_unstable();
        Ok(groups)
    }
}

impl CustodyGroup {
    /// The columns of a group: every column congruent to the group modulo the group count.
    ///
    /// ```text
    /// 128 columns, 128 groups: group 5 holds column 5
    /// 128 columns,  64 groups: group 5 holds columns 5 and 69
    /// ```
    ///
    /// See `compute_columns_for_custody_group` in the Fulu DAS core spec.
    ///
    /// # Errors
    ///
    /// Fails when the group does not exist.
    pub fn columns<P: Preset>(
        self,
        config: &ChainConfig,
    ) -> Result<Vec<ColumnIndex>, CustodyError> {
        let groups = config.number_of_custody_groups;
        if self.0 >= groups {
            return Err(CustodyError::UnknownGroup(self));
        }
        let per_group = P::NUMBER_OF_COLUMNS / groups;
        Ok((0..per_group)
            .map(|index| ColumnIndex(groups * index + self.0))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Mainnet;

    use super::*;

    #[test]
    fn full_custody_holds_every_group() {
        let config = ChainConfig::mainnet();
        let groups = NodeId(U256::ZERO).custody_groups(128, &config).unwrap();

        assert_eq!(groups, (0..128).map(CustodyGroup).collect::<Vec<_>>());
    }

    #[test]
    fn too_many_groups_is_rejected() {
        assert_eq!(
            NodeId(U256::ZERO).custody_groups(129, &ChainConfig::mainnet()),
            Err(CustodyError::TooManyGroups {
                requested: 129,
                available: 128
            })
        );
    }

    #[test]
    fn custody_is_sorted_and_distinct() {
        let groups = NodeId(U256::from_u64(42))
            .custody_groups(8, &ChainConfig::mainnet())
            .unwrap();

        assert_eq!(groups.len(), 8);
        assert!(groups.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn group_columns_stride_by_the_group_count() {
        // Mainnet has 128 columns and 128 groups, so each group holds exactly its own column.
        assert_eq!(
            CustodyGroup(5).columns::<Mainnet>(&ChainConfig::mainnet()),
            Ok(vec![ColumnIndex(5)])
        );
    }
}
