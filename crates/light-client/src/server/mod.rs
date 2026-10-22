//! The light client data a full node serves: best updates, latest updates, and bootstraps.

mod forwarding;
mod latest;

use std::collections::{BTreeMap, HashMap, btree_map::Entry};

use axiom_ssz::Root;
use axiom_types::{ChainConfig, Preset, Slot, SlotClock};

use self::{
    forwarding::Forwarding,
    latest::{Latest, Summary},
};
use crate::{
    GossipIgnore, LightClientError, PostState, UpdateQuality,
    combined::{
        LightClientBootstrap, LightClientFinalityUpdate, LightClientOptimisticUpdate,
        LightClientUpdate,
    },
};

/// Most updates one request for a range of periods returns.
///
/// See `MAX_REQUEST_LIGHT_CLIENT_UPDATES` in the Altair light client networking spec.
pub const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u64 = 128;

/// The light client data a full node has derived from its chain, ready to serve.
///
/// # Overview
///
/// The node derives updates from canonical blocks, and offers each one here.
/// The server keeps the best update of each sync committee period, by the spec's ranking.
/// It also keeps the latest finality and optimistic updates, and bootstraps by block root.
///
/// Every item keeps the format of the fork it describes.
/// Its context slot then picks the fork digest that tags it on the wire.
///
/// See the Altair light client full node and networking specs.
///
/// # Invariants
///
/// Only updates from blocks on the canonical chain are offered.
/// The server cannot tell orphaned blocks apart, so the caller filters them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightClientServer<P: Preset> {
    /// Best update of each period, by the period of its attested header.
    best: BTreeMap<u64, Ranked<P>>,
    /// The latest update that proves a finalized header.
    finality: Option<Latest<LightClientFinalityUpdate<P>>>,
    /// The latest update of any kind, as an optimistic update.
    optimistic: Option<Latest<LightClientOptimisticUpdate<P>>>,
    /// Bootstraps of the blocks the node offers, by block root.
    bootstraps: HashMap<Root, LightClientBootstrap<P>>,
    /// The updates forwarded on gossip so far.
    forwarding: Forwarding,
}

/// An update kept as its period's best, with its rank.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Ranked<P: Preset> {
    /// Rank among the period's updates.
    quality: UpdateQuality,
    /// The update.
    update: LightClientUpdate<P>,
}

impl<P: Preset> Default for LightClientServer<P> {
    fn default() -> Self {
        Self {
            best: BTreeMap::new(),
            finality: None,
            optimistic: None,
            bootstraps: HashMap::new(),
            forwarding: Forwarding::default(),
        }
    }
}

impl<P: Preset> LightClientServer<P> {
    /// An empty server.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes in an update derived from a new canonical block.
    ///
    /// # Algorithm
    ///
    /// 1. Keep it as the period's best, if both its slots share the period and it ranks higher.
    /// 2. Keep it as the latest finality update, if it proves finality and is more recent.
    /// 3. Keep it as the latest optimistic update, if it is more recent.
    ///
    /// Recency compares the attested slot, then the signature slot.
    /// See `create_light_client_update` and the latest update rules of the full node spec.
    ///
    /// # Errors
    ///
    /// Fails when the update's headers have different formats.
    pub fn offer_update(&mut self, update: LightClientUpdate<P>) -> Result<(), LightClientError> {
        let data = update.clone().into_data();
        let summary = Summary::of(&data);

        if data.is_finality_update()
            && self
                .finality
                .as_ref()
                .is_none_or(|latest| latest.is_older_than(summary))
        {
            self.finality = Some(Latest {
                update: update.finality_update()?,
                summary,
            });
        }
        if self
            .optimistic
            .as_ref()
            .is_none_or(|latest| latest.is_older_than(summary))
        {
            self.optimistic = Some(Latest {
                update: update.optimistic_update()?,
                summary,
            });
        }

        // A signature from the next period cannot vouch for the attested period's next committee.
        let period = summary.attested.sync_committee_period::<P>();
        if period != summary.signature.sync_committee_period::<P>() {
            return Ok(());
        }
        let quality = UpdateQuality::of(&data);
        match self.best.entry(period) {
            Entry::Vacant(entry) => {
                entry.insert(Ranked { quality, update });
            }
            Entry::Occupied(mut entry) if quality > entry.get().quality => {
                entry.insert(Ranked { quality, update });
            }
            Entry::Occupied(_) => {}
        }
        Ok(())
    }

    /// Creates and keeps the bootstrap of a block the node offers, such as a finalized checkpoint.
    ///
    /// See `create_light_client_bootstrap` in the Altair light client full node spec.
    ///
    /// # Errors
    ///
    /// Fails for a phase0 block, which has no sync committee to prove.
    pub fn offer_bootstrap(&mut self, post: &PostState<'_, P>) -> Result<(), LightClientError> {
        let bootstrap = LightClientBootstrap::create(post)?;
        self.bootstraps.insert(post.root(), bootstrap);
        Ok(())
    }

    /// The bootstrap of a block, if the node offers one.
    ///
    /// See `GetLightClientBootstrap` in the Altair light client networking spec.
    #[must_use]
    pub fn bootstrap(&self, block_root: &Root) -> Option<&LightClientBootstrap<P>> {
        self.bootstraps.get(block_root)
    }

    /// The best updates of consecutive periods, from the earliest known in a requested range.
    ///
    /// The range starts at a period and spans a count of periods.
    /// At most the request limit of updates come back, in period order.
    /// A period without an update ends the run, since a client cannot skip a period.
    ///
    /// See `LightClientUpdatesByRange` in the Altair light client networking spec.
    pub fn updates_by_range(
        &self,
        start_period: u64,
        count: u64,
    ) -> impl Iterator<Item = &LightClientUpdate<P>> {
        // The request is attacker-controlled: a huge start plus count must not overflow.
        let end = start_period.saturating_add(count.min(MAX_REQUEST_LIGHT_CLIENT_UPDATES));
        let mut expected = None;
        self.best
            .range(start_period..end)
            .take_while(move |(period, _)| {
                let consecutive = expected.is_none_or(|next| **period == next);
                expected = Some(period.saturating_add(1));
                consecutive
            })
            .map(|(_, ranked)| &ranked.update)
    }

    /// The latest finality update, if any update proved finality.
    ///
    /// See `GetLightClientFinalityUpdate` in the Altair light client networking spec.
    #[must_use]
    pub fn latest_finality_update(&self) -> Option<&LightClientFinalityUpdate<P>> {
        self.finality.as_ref().map(|latest| &latest.update)
    }

    /// The latest optimistic update, if any update was offered.
    ///
    /// See `GetLightClientOptimisticUpdate` in the Altair light client networking spec.
    #[must_use]
    pub fn latest_optimistic_update(&self) -> Option<&LightClientOptimisticUpdate<P>> {
        self.optimistic.as_ref().map(|latest| &latest.update)
    }

    /// Drops best updates of periods before a slot's, and bootstraps of blocks before it.
    ///
    /// A node serves data back to the oldest epoch it keeps blocks for.
    /// See the serving ranges of the Altair light client full node spec.
    pub fn prune(&mut self, earliest: Slot) {
        let period = earliest.sync_committee_period::<P>();
        self.best = self.best.split_off(&period);
        self.bootstraps
            .retain(|_, bootstrap| bootstrap.context_slot() >= earliest);
    }

    /// Checks a finality update from gossip, or of the node's own, and records it as forwarded.
    ///
    /// # Algorithm
    ///
    /// 1. It must equal the latest finality update computed here.
    /// 2. Its signature block must have had time to propagate.
    /// 3. Its finalized header must advance, or first reach a supermajority.
    ///
    /// See `light_client_finality_update` in the Altair light client networking spec.
    ///
    /// # Errors
    ///
    /// Fails with the reason to ignore the update; nothing is then recorded.
    pub fn forward_finality_update(
        &mut self,
        update: &LightClientFinalityUpdate<P>,
        config: &ChainConfig,
        clock: SlotClock,
        now_ms: u64,
    ) -> Result<(), GossipIgnore> {
        let summary = self
            .finality
            .as_ref()
            .filter(|latest| latest.update == *update)
            .map(|latest| latest.summary)
            .ok_or_else(|| GossipIgnore::NotLocal {
                attested: update.context_slot(),
            })?;
        Forwarding::is_due::<P>(config, clock, summary.signature, now_ms)?;
        self.forwarding.finality(summary)
    }

    /// Checks an optimistic update from gossip, or of the node's own, and records it as forwarded.
    ///
    /// # Algorithm
    ///
    /// 1. It must equal the latest optimistic update computed here.
    /// 2. Its signature block must have had time to propagate.
    /// 3. Its attested header must advance.
    ///
    /// See `light_client_optimistic_update` in the Altair light client networking spec.
    ///
    /// # Errors
    ///
    /// Fails with the reason to ignore the update; nothing is then recorded.
    pub fn forward_optimistic_update(
        &mut self,
        update: &LightClientOptimisticUpdate<P>,
        config: &ChainConfig,
        clock: SlotClock,
        now_ms: u64,
    ) -> Result<(), GossipIgnore> {
        let summary = self
            .optimistic
            .as_ref()
            .filter(|latest| latest.update == *update)
            .map(|latest| latest.summary)
            .ok_or_else(|| GossipIgnore::NotLocal {
                attested: update.context_slot(),
            })?;
        Forwarding::is_due::<P>(config, clock, summary.signature, now_ms)?;
        self.forwarding.optimistic(summary)
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        Bytes32, ForkName, Minimal, altair, altair::SyncAggregate, phase0::Checkpoint,
    };

    use super::*;
    use crate::{UpdateData, combined::LightClientHeader, fixture::Chain};

    /// An Altair update, signed by the first seats, proving finality of a slot when given one.
    fn update(
        attested: u64,
        signature: u64,
        signers: usize,
        finalized: Option<u64>,
    ) -> LightClientUpdate<Minimal> {
        let header = |slot| {
            let mut header = altair::LightClientHeader::default();
            header.beacon.slot = Slot(slot);
            LightClientHeader::Altair(header)
        };
        let mut sync_aggregate = SyncAggregate::default();
        for seat in 0..signers {
            sync_aggregate.sync_committee_bits.set(seat, true);
        }
        LightClientUpdate::from_data(UpdateData {
            attested_header: header(attested),
            next_sync_committee_branch: vec![Bytes32([1; 32])],
            finalized_header: finalized.map_or_else(|| header(0), header),
            finality_branch: finalized.map_or_else(Vec::new, |_| vec![Bytes32([2; 32])]),
            sync_aggregate,
            signature_slot: Slot(signature),
            ..UpdateData::default()
        })
        .unwrap()
    }

    /// The attested slots of the updates a range request returns.
    fn range(server: &LightClientServer<Minimal>, start: u64, count: u64) -> Vec<Slot> {
        server
            .updates_by_range(start, count)
            .map(LightClientUpdate::context_slot)
            .collect()
    }

    #[test]
    fn each_period_keeps_its_best_update() {
        // Fixture state: 16 of 32 signers without finality, attested at 20 in period 0.
        let mut server = LightClientServer::new();
        let weak = update(20, 21, 16, None);
        server.offer_update(weak.clone()).unwrap();
        assert_eq!(server.updates_by_range(0, 1).collect::<Vec<_>>(), [&weak]);

        // 30 signers reach the supermajority of 22, so this one ranks higher.
        let strong = update(22, 23, 30, Some(16));
        server.offer_update(strong.clone()).unwrap();
        assert_eq!(server.updates_by_range(0, 1).collect::<Vec<_>>(), [&strong]);

        // 10 signers fall below it again, so the best stays.
        server.offer_update(update(24, 25, 10, Some(16))).unwrap();
        assert_eq!(server.updates_by_range(0, 1).collect::<Vec<_>>(), [&strong]);
    }

    #[test]
    fn a_signature_from_the_next_period_is_never_a_best_update() {
        // Fixture state: attested at 63 in period 0, signed at 64 in period 1.
        let mut server = LightClientServer::new();
        let crossing = update(63, 64, 32, Some(16));
        server.offer_update(crossing.clone()).unwrap();

        // Neither period serves it, yet it is the latest update of both kinds.
        assert_eq!(range(&server, 0, 2), []);
        assert_eq!(
            server.latest_optimistic_update(),
            Some(&crossing.optimistic_update().unwrap())
        );
        assert_eq!(
            server.latest_finality_update(),
            Some(&crossing.finality_update().unwrap())
        );
    }

    #[test]
    fn the_latest_updates_follow_the_attested_then_the_signature_slot() {
        // Fixture state: an update attested at 20 that finalizes slot 8.
        let mut server = LightClientServer::new();
        let first = update(20, 21, 32, Some(8));
        server.offer_update(first.clone()).unwrap();
        assert_eq!(
            server.latest_finality_update(),
            Some(&first.finality_update().unwrap())
        );

        // Attested at 22 without finality: only the optimistic update moves.
        let unfinal = update(22, 23, 32, None);
        server.offer_update(unfinal.clone()).unwrap();
        assert_eq!(
            server.latest_finality_update(),
            Some(&first.finality_update().unwrap())
        );
        assert_eq!(
            server.latest_optimistic_update(),
            Some(&unfinal.optimistic_update().unwrap())
        );

        // Attested at 22 again, signed later at 24 with finality: both move.
        let later = update(22, 24, 32, Some(16));
        server.offer_update(later.clone()).unwrap();
        assert_eq!(
            server.latest_finality_update(),
            Some(&later.finality_update().unwrap())
        );
        assert_eq!(
            server.latest_optimistic_update(),
            Some(&later.optimistic_update().unwrap())
        );

        // Attested at 19, however late its signature: neither moves.
        server.offer_update(update(19, 30, 32, Some(16))).unwrap();
        assert_eq!(
            server.latest_finality_update(),
            Some(&later.finality_update().unwrap())
        );
        assert_eq!(
            server.latest_optimistic_update(),
            Some(&later.optimistic_update().unwrap())
        );
    }

    #[test]
    fn a_range_runs_over_consecutive_periods_up_to_the_request_limit() {
        // Fixture state: updates for periods 0, 1, and 3, attested 20 slots into each.
        // Then 131 more, for periods 10 through 140.
        let mut server = LightClientServer::new();
        for period in [0, 1, 3].into_iter().chain(10..=140) {
            let attested = period * 64 + 20;
            server
                .offer_update(update(attested, attested + 1, 32, None))
                .unwrap();
        }

        // Periods 0 and 1 come back; the missing period 2 ends the run.
        assert_eq!(range(&server, 0, 10), [Slot(20), Slot(84)]);
        // The run starts at the earliest known period in the range, here 3.
        assert_eq!(range(&server, 2, 3), [Slot(212)]);
        // A count of 1000 returns at most 128 updates: periods 10 through 137.
        let capped = range(&server, 10, 1000);
        assert_eq!(capped.len(), 128);
        assert_eq!(capped.last(), Some(&Slot(137 * 64 + 20)));
        // A count of zero, or a range past every period, returns nothing and never overflows.
        assert_eq!(range(&server, 0, 0), []);
        assert_eq!(range(&server, u64::MAX, u64::MAX), []);
    }

    #[test]
    fn bootstraps_are_served_by_block_root_until_pruned() {
        // Fixture state: Altair blocks at 8 in period 0 and at 72 in period 1.
        let chain = Chain::new(ForkName::Altair);
        let (early_state, early) = chain.block(
            Slot(8),
            Root::ZERO,
            Checkpoint::default(),
            SyncAggregate::default(),
        );
        let (late_state, late) = chain.block(
            Slot(72),
            Root::ZERO,
            Checkpoint::default(),
            SyncAggregate::default(),
        );
        let early_post = PostState::new(&early_state, &early).unwrap();
        let late_post = PostState::new(&late_state, &late).unwrap();
        let mut server = LightClientServer::new();
        server.offer_bootstrap(&early_post).unwrap();
        server.offer_bootstrap(&late_post).unwrap();
        server.offer_update(update(20, 21, 32, None)).unwrap();
        server.offer_update(update(84, 85, 32, None)).unwrap();

        // Each block's bootstrap is found by its root, and no other root finds one.
        let expected = LightClientBootstrap::create(&early_post).unwrap();
        assert_eq!(server.bootstrap(&early.block_root()), Some(&expected));
        assert_eq!(server.bootstrap(&Root([9; 32])), None);

        // Keeping data from slot 64 on drops period 0 and the block at 8.
        server.prune(Slot(64));
        assert_eq!(server.bootstrap(&early.block_root()), None);
        assert_eq!(
            server.bootstrap(&late.block_root()),
            Some(&LightClientBootstrap::create(&late_post).unwrap())
        );
        assert_eq!(range(&server, 0, 2), [Slot(84)]);
    }

    #[test]
    fn only_the_local_update_is_forwarded_once_due() {
        // Fixture state: the local update attested at 20, signed at 21, finalizing slot 8.
        // Minimal slots last 6000 ms; the earliest forwarding time is 127499 ms.
        let config = ChainConfig::minimal().with_forks_at_genesis(ForkName::Altair);
        let clock = SlotClock::new(0, config.slot_duration_ms);
        let mut server = LightClientServer::new();
        let local = update(20, 21, 32, Some(8));
        server.offer_update(local.clone()).unwrap();
        let finality = local.finality_update().unwrap();
        let optimistic = local.optimistic_update().unwrap();

        // Mutation: an update the node did not compute, attested at 19.
        let foreign = update(19, 21, 32, Some(8)).finality_update().unwrap();
        assert_eq!(
            server.forward_finality_update(&foreign, &config, clock, 130_000),
            Err(GossipIgnore::NotLocal { attested: Slot(19) })
        );

        // The local one, one millisecond early, then on time, then a second time.
        assert_eq!(
            server.forward_finality_update(&finality, &config, clock, 127_498),
            Err(GossipIgnore::Early {
                now_ms: 127_498,
                earliest_ms: 127_499,
            })
        );
        assert_eq!(
            server.forward_finality_update(&finality, &config, clock, 127_499),
            Ok(())
        );
        assert_eq!(
            server.forward_finality_update(&finality, &config, clock, 127_500),
            Err(GossipIgnore::StaleFinality {
                finalized: Slot(8),
                forwarded: Slot(8),
            })
        );

        // The optimistic update is tracked apart, and also goes out once.
        assert_eq!(
            server.forward_optimistic_update(&optimistic, &config, clock, 127_499),
            Ok(())
        );
        assert_eq!(
            server.forward_optimistic_update(&optimistic, &config, clock, 127_500),
            Err(GossipIgnore::StaleOptimistic {
                attested: Slot(20),
                forwarded: Slot(20),
            })
        );
    }
}
