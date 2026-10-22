//! The gas limit a payload must carry, given its parent's and the proposer's target.

/// The parent's gas limit and the limit the proposer registered as its target.
///
/// # Overview
///
/// A builder must set the payload's gas limit to the registered target.
/// When the execution rules forbid a jump that large, it must come as close as they allow.
/// See the payload header construction in the Bellatrix builder spec.
///
/// The execution rule, from the block header validity section of the Ethereum yellow paper:
///
/// ```text
///     |gas_limit - parent_gas_limit| < parent_gas_limit / 1024
///     gas_limit >= 5000
/// ```
///
/// So each block moves the limit by at most `parent_gas_limit / 1024 - 1` toward the target.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct GasLimitTarget {
    /// Gas limit of the parent payload.
    pub parent: u64,

    /// Gas limit the proposer asked builders to reach.
    pub target: u64,
}

impl GasLimitTarget {
    /// Divisor of the largest step between consecutive gas limits, from the yellow paper.
    const BOUND_DIVISOR: u64 = 1024;

    /// Lowest gas limit a block may carry, from the yellow paper.
    const MINIMUM: u64 = 5000;

    /// The gas limit an honest builder sets: the reachable value closest to the target.
    #[must_use]
    pub const fn expected(self) -> u64 {
        // The strict inequality leaves one gas less than the divisor's quotient.
        let step = (self.parent / Self::BOUND_DIVISOR).saturating_sub(1);
        let reached = if self.target > self.parent {
            let ceiling = self.parent.saturating_add(step);
            if self.target < ceiling {
                self.target
            } else {
                ceiling
            }
        } else {
            let floor = self.parent - step;
            if self.target > floor {
                self.target
            } else {
                floor
            }
        };
        // The floor applies on its own; a parent below it may only climb.
        if reached < Self::MINIMUM && self.parent >= Self::MINIMUM {
            Self::MINIMUM
        } else {
            reached
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn a_reachable_target_is_met_exactly() {
        // Parent 30_000_000 allows a step of 30_000_000 / 1024 - 1 = 29_295.
        // A target 10_000 above the parent sits within one step.
        let limits = GasLimitTarget {
            parent: 30_000_000,
            target: 30_010_000,
        };
        assert_eq!(limits.expected(), 30_010_000);
    }

    #[test]
    fn a_distant_target_is_approached_by_one_step() {
        // Raising 30_000_000 toward 36_000_000 gains 29_295 per block.
        let up = GasLimitTarget {
            parent: 30_000_000,
            target: 36_000_000,
        };
        assert_eq!(up.expected(), 30_029_295);

        // Lowering toward 15_000_000 loses the same 29_295.
        let down = GasLimitTarget {
            parent: 30_000_000,
            target: 15_000_000,
        };
        assert_eq!(down.expected(), 29_970_705);
    }

    #[test]
    fn the_target_equal_to_the_parent_keeps_it() {
        // No move asked, none made.
        let limits = GasLimitTarget {
            parent: 36_000_000,
            target: 36_000_000,
        };
        assert_eq!(limits.expected(), 36_000_000);
    }

    #[test]
    fn the_floor_of_5000_holds() {
        // Parent 5_100 allows a step of 5_100 / 1024 - 1 = 3 toward a target of 0.
        // One step lands on 5_097, still above the floor.
        let near = GasLimitTarget {
            parent: 5_100,
            target: 0,
        };
        assert_eq!(near.expected(), 5_097);

        // Parent 5_000 has a step of 3; lowering would cross the floor, so it stays.
        let at_floor = GasLimitTarget {
            parent: 5_000,
            target: 0,
        };
        assert_eq!(at_floor.expected(), 5_000);
    }

    proptest! {
        #[test]
        fn the_expected_limit_obeys_the_execution_rule(parent in 5_000_u64..1 << 40, target in 0_u64..1 << 40) {
            let limits = GasLimitTarget { parent, target };
            let expected = limits.expected();

            // The step is strictly below parent / 1024, and the floor holds.
            prop_assert!(expected.abs_diff(parent) < parent / 1024 || expected == parent);
            prop_assert!(expected >= 5_000);

            // The limit never overshoots: it lies between the parent and the target, floor aside.
            let (low, high) = (parent.min(target).max(5_000), parent.max(target));
            prop_assert!((low..=high).contains(&expected));
        }
    }
}
