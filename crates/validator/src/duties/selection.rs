//! Who aggregates: the slot signatures whose hash picks a committee's aggregators.

use axiom_types::{
    BlsSignature, Preset,
    constants::{
        SYNC_COMMITTEE_SUBNET_COUNT, TARGET_AGGREGATORS_PER_COMMITTEE,
        TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
    },
};

/// How a committee picks its aggregators from their selection proofs.
///
/// A member aggregates when the hash of its proof is divisible by a modulo.
/// The modulo is the committee size over the target count, at least one.
/// About the target count of members then aggregate, unpredictably to anyone without their keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AggregatorSelection {
    /// One member in this many aggregates.
    modulo: u64,
}

impl AggregatorSelection {
    /// The selection of an attestation committee of a size.
    ///
    /// See `is_aggregator` in the phase0 validator spec.
    #[must_use]
    pub const fn committee(committee_length: u64) -> Self {
        Self::with_modulo(committee_length / TARGET_AGGREGATORS_PER_COMMITTEE)
    }

    /// The selection of a sync subcommittee.
    ///
    /// See `is_sync_committee_aggregator` in the Altair validator spec.
    #[must_use]
    pub const fn sync_subcommittee<P: Preset>() -> Self {
        Self::with_modulo(
            P::SYNC_COMMITTEE_SIZE
                / SYNC_COMMITTEE_SUBNET_COUNT
                / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
        )
    }

    /// A selection with a modulo, raised to one when smaller.
    const fn with_modulo(modulo: u64) -> Self {
        Self {
            modulo: if modulo == 0 { 1 } else { modulo },
        }
    }

    /// Whether a member with this selection proof aggregates.
    #[must_use]
    pub fn selects(self, proof: &BlsSignature) -> bool {
        proof.selects(self.modulo)
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Mainnet, Minimal};

    use super::*;

    #[test]
    fn small_committees_all_aggregate() {
        // Fewer than 16 members: the modulo is 1, so every member aggregates.
        let selection = AggregatorSelection::committee(15);
        assert_eq!(selection, AggregatorSelection { modulo: 1 });
        assert!(selection.selects(&BlsSignature([3; 96])));

        // 128 members: one in 8.
        assert_eq!(
            AggregatorSelection::committee(128),
            AggregatorSelection { modulo: 8 }
        );
    }

    #[test]
    fn sync_subcommittees_aim_for_sixteen_aggregators() {
        // Mainnet: 512 seats in 4 subnets of 128, so one in 8.
        assert_eq!(
            AggregatorSelection::sync_subcommittee::<Mainnet>(),
            AggregatorSelection { modulo: 8 }
        );
        // Minimal: 32 seats in 4 subnets of 8, so every seat aggregates.
        assert_eq!(
            AggregatorSelection::sync_subcommittee::<Minimal>(),
            AggregatorSelection { modulo: 1 }
        );
    }
}
