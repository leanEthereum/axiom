//! What a full node has forwarded on the light client gossip topics.

use axiom_types::{ChainConfig, Preset, Slot, SlotClock};

use super::latest::Summary;
use crate::GossipIgnore;

/// The highest light client updates forwarded on gossip so far.
///
/// # Overview
///
/// Gossip carries each finality and optimistic update forward only once it advances.
/// A finality update advances with a later finalized header.
/// It also advances when it first reaches a supermajority for the same finalized header.
///
/// See the light client gossip topics of the Altair light client networking spec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Forwarding {
    /// Finalized slot of the last forwarded finality update, and whether it had a supermajority.
    finality: Option<(Slot, bool)>,
    /// Attested slot of the last forwarded optimistic update.
    optimistic: Option<Slot>,
}

impl Forwarding {
    /// Records a finality update as forwarded, if it advances.
    pub(super) fn finality(&mut self, summary: Summary) -> Result<(), GossipIgnore> {
        let Summary {
            finalized,
            supermajority,
            ..
        } = summary;
        if let Some((forwarded, had_supermajority)) = self.finality {
            let upgrades = finalized == forwarded && supermajority && !had_supermajority;
            if finalized <= forwarded && !upgrades {
                return Err(GossipIgnore::StaleFinality {
                    finalized,
                    forwarded,
                });
            }
        }
        self.finality = Some((finalized, supermajority));
        Ok(())
    }

    /// Records an optimistic update as forwarded, if it advances.
    pub(super) fn optimistic(&mut self, summary: Summary) -> Result<(), GossipIgnore> {
        let attested = summary.attested;
        if let Some(forwarded) = self.optimistic
            && attested <= forwarded
        {
            return Err(GossipIgnore::StaleOptimistic {
                attested,
                forwarded,
            });
        }
        self.optimistic = Some(attested);
        Ok(())
    }

    /// Checks that the signature block had time to propagate before the update arrived.
    ///
    /// The update may arrive once the sync message due time of its signature slot has passed.
    /// The gossip clock disparity widens that window.
    pub(super) fn is_due<P: Preset>(
        config: &ChainConfig,
        clock: SlotClock,
        signature_slot: Slot,
        now_ms: u64,
    ) -> Result<(), GossipIgnore> {
        let fork = config.fork_at(signature_slot.epoch::<P>());
        let due_ms = clock.slot_start_ms(signature_slot)
            + clock.component_ms(config.sync_message_due_bps(fork));
        let earliest_ms = due_ms.saturating_sub(config.maximum_gossip_clock_disparity_ms);
        if now_ms < earliest_ms {
            return Err(GossipIgnore::Early {
                now_ms,
                earliest_ms,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{ForkName, Minimal};

    use super::*;

    fn summary(attested: u64, finalized: u64, supermajority: bool) -> Summary {
        Summary {
            attested: Slot(attested),
            signature: Slot(attested + 1),
            finalized: Slot(finalized),
            supermajority,
        }
    }

    #[test]
    fn a_finality_update_advances_by_slot_or_by_first_reaching_a_supermajority() {
        // Fixture state: nothing forwarded yet.
        // The first update finalizes slot 16 with 20 of 32 signers.
        let mut forwarding = Forwarding::default();
        assert_eq!(forwarding.finality(summary(26, 16, false)), Ok(()));

        // The same finalized slot without a supermajority does not advance.
        assert_eq!(
            forwarding.finality(summary(27, 16, false)),
            Err(GossipIgnore::StaleFinality {
                finalized: Slot(16),
                forwarded: Slot(16),
            })
        );

        // The same finalized slot, now with 30 of 32 signers, is forwarded once.
        assert_eq!(forwarding.finality(summary(28, 16, true)), Ok(()));
        assert_eq!(
            forwarding.finality(summary(29, 16, true)),
            Err(GossipIgnore::StaleFinality {
                finalized: Slot(16),
                forwarded: Slot(16),
            })
        );

        // An earlier finalized slot never advances; a later one does, whatever its signers.
        assert_eq!(
            forwarding.finality(summary(30, 8, true)),
            Err(GossipIgnore::StaleFinality {
                finalized: Slot(8),
                forwarded: Slot(16),
            })
        );
        assert_eq!(forwarding.finality(summary(34, 24, false)), Ok(()));
    }

    #[test]
    fn an_optimistic_update_advances_by_attested_slot_only() {
        // Fixture state: an update attested at slot 20 is forwarded first.
        let mut forwarding = Forwarding::default();
        assert_eq!(forwarding.optimistic(summary(20, 8, false)), Ok(()));

        // Another one for slot 20, even with a supermajority, does not advance.
        assert_eq!(
            forwarding.optimistic(summary(20, 8, true)),
            Err(GossipIgnore::StaleOptimistic {
                attested: Slot(20),
                forwarded: Slot(20),
            })
        );
        assert_eq!(forwarding.optimistic(summary(21, 8, false)), Ok(()));
    }

    #[test]
    fn an_update_is_due_once_the_sync_messages_of_its_slot_are() {
        // Timing: minimal slots last 6000 ms, so signature slot 21 starts at 126000 ms.
        // Sync messages are due at 3333 bps, 1999 ms in; the disparity allowance is 500 ms.
        //
        //     earliest = 126000 + 1999 - 500 = 127499
        let config = ChainConfig::minimal().with_forks_at_genesis(ForkName::Fulu);
        let clock = SlotClock::new(0, config.slot_duration_ms);
        assert_eq!(
            Forwarding::is_due::<Minimal>(&config, clock, Slot(21), 127_498),
            Err(GossipIgnore::Early {
                now_ms: 127_498,
                earliest_ms: 127_499,
            })
        );
        assert_eq!(
            Forwarding::is_due::<Minimal>(&config, clock, Slot(21), 127_499),
            Ok(())
        );

        // Gloas moves the deadline to 2500 bps, 1500 ms in: the earliest is 127000 ms.
        let config = ChainConfig::minimal().with_forks_at_genesis(ForkName::Gloas);
        assert_eq!(
            Forwarding::is_due::<Minimal>(&config, clock, Slot(21), 126_999),
            Err(GossipIgnore::Early {
                now_ms: 126_999,
                earliest_ms: 127_000,
            })
        );
    }
}
