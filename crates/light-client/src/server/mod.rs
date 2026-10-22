//! The light client data a full node serves: best updates, latest updates, and bootstraps.

mod candidate;
mod forwarding;
mod latest;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    mem,
};

use axiom_ssz::Root;
use axiom_types::{ChainConfig, Preset, Slot, SlotClock};

use self::{candidate::Candidate, forwarding::Forwarding, latest::Latest};
use crate::{
    GossipIgnore, LightClientError, PostState,
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
/// The node derives an update from each block it imports, and offers it here.
/// Only updates signed on the canonical chain are served, so the server keeps two sets.
///
/// - Settled updates were signed by finalized blocks, and no reorg can drop them.
/// - Pending updates were signed after finality, on any branch the node holds.
///
/// Each head change names the canonical blocks, and the served data follows them.
/// A reorg therefore swaps the served updates for those of the new branch.
///
/// The server serves the best update of each sync committee period, by the spec's ranking.
/// It also serves the latest finality and optimistic updates, and bootstraps by block root.
///
/// Every item keeps the format of the fork it describes.
/// Its context slot then picks the fork digest that tags it on the wire.
///
/// See the Altair light client full node and networking specs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightClientServer<P: Preset> {
    /// Best settled update of each period, by the period of its attested header.
    settled: BTreeMap<u64, Candidate<P>>,
    /// The most recent settled update.
    settled_latest: Option<Candidate<P>>,
    /// The most recent settled update that proves finality.
    settled_finality: Option<Candidate<P>>,
    /// Updates signed after finality, by the root of the signing block.
    pending: HashMap<Root, Candidate<P>>,
    /// Blocks of the canonical chain since finality, as the last head change named them.
    canonical: HashSet<Root>,
    /// The signing block of the best canonical pending update of each period.
    canonical_best: BTreeMap<u64, Root>,
    /// The latest canonical update that proves a finalized header.
    finality: Option<Latest<LightClientFinalityUpdate<P>>>,
    /// The latest canonical update of any kind, as an optimistic update.
    optimistic: Option<Latest<LightClientOptimisticUpdate<P>>>,
    /// Bootstraps of the blocks the node offers, by block root.
    bootstraps: HashMap<Root, LightClientBootstrap<P>>,
    /// The updates forwarded on gossip so far.
    forwarding: Forwarding,
}

impl<P: Preset> Default for LightClientServer<P> {
    fn default() -> Self {
        Self {
            settled: BTreeMap::new(),
            settled_latest: None,
            settled_finality: None,
            pending: HashMap::new(),
            canonical: HashSet::new(),
            canonical_best: BTreeMap::new(),
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

    /// Takes in the update a block's sync aggregate signs, while the block is not yet final.
    ///
    /// The update is served once a head change names its block canonical.
    /// See `create_light_client_update` in the Altair light client full node spec.
    ///
    /// # Arguments
    ///
    /// - `signer`: the root of the block whose sync aggregate the update carries.
    ///
    /// # Errors
    ///
    /// Fails when the update's headers have different formats.
    pub fn offer_update(
        &mut self,
        signer: Root,
        update: LightClientUpdate<P>,
    ) -> Result<(), LightClientError> {
        let candidate = Candidate::new(update)?;
        self.pending.insert(signer, candidate);
        if self.canonical.contains(&signer) {
            self.select();
        }
        Ok(())
    }

    /// Serves the updates signed by the blocks of the new canonical chain.
    ///
    /// The blocks are those since finality, from the head back.
    /// Updates of other branches stay pending, in case the head returns to them.
    /// See the canonical chain rule of the Altair light client full node spec.
    pub fn follow(&mut self, canonical: impl IntoIterator<Item = Root>) {
        self.canonical = canonical.into_iter().collect();
        self.select();
    }

    /// Settles the canonical updates signed at or before a newly finalized slot.
    ///
    /// Pending updates of the canonical chain at or before the slot become settled.
    /// Those of other branches can never be canonical again, so they are dropped.
    pub fn settle(&mut self, finalized: Slot) {
        for (signer, candidate) in mem::take(&mut self.pending) {
            if candidate.summary.signature > finalized {
                self.pending.insert(signer, candidate);
            } else if self.canonical.contains(&signer) {
                self.keep_settled(candidate);
            }
        }
        self.select();
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
        let settled = self.settled.range(start_period..end);
        let pending = self.canonical_best.range(start_period..end);
        let first = settled
            .map(|(period, _)| *period)
            .chain(pending.map(|(period, _)| *period))
            .min();
        first
            .into_iter()
            .flat_map(move |first| (first..end).map_while(|period| self.best_of(period)))
            .map(|candidate| &candidate.update)
    }

    /// The latest finality update of the canonical chain, if any update proved finality.
    ///
    /// See `GetLightClientFinalityUpdate` in the Altair light client networking spec.
    #[must_use]
    pub fn latest_finality_update(&self) -> Option<&LightClientFinalityUpdate<P>> {
        self.finality.as_ref().map(|latest| &latest.update)
    }

    /// The latest optimistic update of the canonical chain, if any.
    ///
    /// See `GetLightClientOptimisticUpdate` in the Altair light client networking spec.
    #[must_use]
    pub fn latest_optimistic_update(&self) -> Option<&LightClientOptimisticUpdate<P>> {
        self.optimistic.as_ref().map(|latest| &latest.update)
    }

    /// Drops settled updates of periods before a slot's, and bootstraps of blocks before it.
    ///
    /// A node serves data for the periods back to the oldest epoch it serves blocks for.
    /// See the serving ranges of the Altair light client full node spec.
    pub fn prune(&mut self, earliest: Slot) {
        let period = earliest.sync_committee_period::<P>();
        self.settled = self.settled.split_off(&period);
        self.bootstraps
            .retain(|_, bootstrap| bootstrap.context_slot() >= earliest);
    }

    /// The settled best update of each period, by period.
    ///
    /// Finality fixed them, so a node can persist them and restore them after a restart.
    pub fn settled_updates(&self) -> impl Iterator<Item = (u64, &LightClientUpdate<P>)> {
        self.settled
            .iter()
            .map(|(period, candidate)| (*period, &candidate.update))
    }

    /// The most recent settled update, and the most recent settled one that proves finality.
    ///
    /// They seed the latest updates served until a new block derives fresher ones.
    pub fn latest_settled(&self) -> impl Iterator<Item = &LightClientUpdate<P>> {
        self.settled_latest
            .iter()
            .chain(self.settled_finality.iter())
            .map(|candidate| &candidate.update)
    }

    /// Takes back an update that was settled before a restart.
    ///
    /// It ranks against the settled updates exactly as when it first settled.
    ///
    /// # Errors
    ///
    /// Fails when the update's headers have different formats.
    pub fn restore_settled(&mut self, update: LightClientUpdate<P>) -> Result<(), LightClientError> {
        self.keep_settled(Candidate::new(update)?);
        self.select();
        Ok(())
    }

    /// Every bootstrap the node offers, by block root.
    pub fn bootstraps(&self) -> impl Iterator<Item = (&Root, &LightClientBootstrap<P>)> {
        self.bootstraps.iter()
    }

    /// Takes back a bootstrap that was offered before a restart.
    pub fn restore_bootstrap(&mut self, block_root: Root, bootstrap: LightClientBootstrap<P>) {
        self.bootstraps.insert(block_root, bootstrap);
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

    /// The best update of a period, settled or canonical pending.
    fn best_of(&self, period: u64) -> Option<&Candidate<P>> {
        let settled = self.settled.get(&period);
        let pending = self
            .canonical_best
            .get(&period)
            .and_then(|signer| self.pending.get(signer));
        match (settled, pending) {
            (Some(settled), Some(pending)) => Some(Candidate::better(settled, pending)),
            (settled, pending) => settled.or(pending),
        }
    }

    /// Keeps a final update as its period's best and as the latest, where it ranks higher.
    fn keep_settled(&mut self, candidate: Candidate<P>) {
        let recency = candidate.summary.recency();
        let is_newer = |kept: &Option<Candidate<P>>| {
            kept.as_ref()
                .is_none_or(|kept| kept.summary.recency() < recency)
        };
        if candidate.finality.is_some() && is_newer(&self.settled_finality) {
            self.settled_finality = Some(candidate.clone());
        }
        if is_newer(&self.settled_latest) {
            self.settled_latest = Some(candidate.clone());
        }
        if let Some(period) = candidate.period()
            && self
                .settled
                .get(&period)
                .is_none_or(|kept| candidate.quality > kept.quality)
        {
            self.settled.insert(period, candidate);
        }
    }

    /// Recomputes what is served from the settled updates and the canonical pending ones.
    ///
    /// The latest updates order by attested slot, then signature slot.
    /// See `create_light_client_finality_update` in the Altair light client full node spec.
    fn select(&mut self) {
        let canonical: Vec<(&Root, &Candidate<P>)> = self
            .pending
            .iter()
            .filter(|(signer, _)| self.canonical.contains(*signer))
            .collect();

        let mut best: BTreeMap<u64, (&Root, &Candidate<P>)> = BTreeMap::new();
        for &(signer, candidate) in &canonical {
            let Some(period) = candidate.period() else {
                continue;
            };
            let replaces = best
                .get(&period)
                .is_none_or(|(_, kept)| candidate.quality > kept.quality);
            if replaces {
                best.insert(period, (signer, candidate));
            }
        }

        // Settled updates are older than any pending one, so they serve only when nothing else does.
        let candidates = || {
            canonical
                .iter()
                .map(|(_, candidate)| *candidate)
                .chain(self.settled_latest.iter())
                .chain(self.settled_finality.iter())
        };
        let optimistic = candidates()
            .max_by_key(|candidate| candidate.summary.recency())
            .map(|candidate| Latest {
                update: candidate.optimistic.clone(),
                summary: candidate.summary,
            });
        let finality = candidates()
            .filter_map(|candidate| Some((candidate.finality.as_ref()?, candidate.summary)))
            .max_by_key(|(_, summary)| summary.recency())
            .map(|(update, summary)| Latest {
                update: update.clone(),
                summary,
            });

        self.canonical_best = best
            .into_iter()
            .map(|(period, (signer, _))| (period, *signer))
            .collect();
        self.optimistic = optimistic;
        self.finality = finality;
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

    /// The root of a block named by a tag.
    const fn block(tag: u16) -> Root {
        let mut bytes = [0; 32];
        let [high, low] = tag.to_be_bytes();
        bytes[0] = high;
        bytes[1] = low;
        Root(bytes)
    }

    /// Offers an update signed by a tagged block, and adds that block to the canonical chain.
    fn offer(
        server: &mut LightClientServer<Minimal>,
        tag: u16,
        update: LightClientUpdate<Minimal>,
    ) {
        server.offer_update(block(tag), update).unwrap();
        let mut canonical = server.canonical.clone();
        canonical.insert(block(tag));
        server.follow(canonical);
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
        offer(&mut server, 21, weak.clone());
        assert_eq!(server.updates_by_range(0, 1).collect::<Vec<_>>(), [&weak]);

        // 30 signers reach the supermajority of 22, so this one ranks higher.
        let strong = update(22, 23, 30, Some(16));
        offer(&mut server, 23, strong.clone());
        assert_eq!(server.updates_by_range(0, 1).collect::<Vec<_>>(), [&strong]);

        // 10 signers fall below it again, so the best stays.
        offer(&mut server, 25, update(24, 25, 10, Some(16)));
        assert_eq!(server.updates_by_range(0, 1).collect::<Vec<_>>(), [&strong]);
    }

    #[test]
    fn a_signature_from_the_next_period_is_never_a_best_update() {
        // Fixture state: attested at 63 in period 0, signed at 64 in period 1.
        let mut server = LightClientServer::new();
        let crossing = update(63, 64, 32, Some(16));
        offer(&mut server, 64, crossing.clone());

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
        offer(&mut server, 21, first.clone());
        assert_eq!(
            server.latest_finality_update(),
            Some(&first.finality_update().unwrap())
        );

        // Attested at 22 without finality: only the optimistic update moves.
        let unfinal = update(22, 23, 32, None);
        offer(&mut server, 23, unfinal.clone());
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
        offer(&mut server, 24, later.clone());
        assert_eq!(
            server.latest_finality_update(),
            Some(&later.finality_update().unwrap())
        );
        assert_eq!(
            server.latest_optimistic_update(),
            Some(&later.optimistic_update().unwrap())
        );

        // Attested at 19, however late its signature: neither moves.
        offer(&mut server, 30, update(19, 30, 32, Some(16)));
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
        // Periods 0 to 10 settle; the later ones stay pending on the canonical chain.
        let mut server = LightClientServer::new();
        for period in [0, 1, 3].into_iter().chain(10..=140) {
            let attested = period * 64 + 20;
            offer(
                &mut server,
                period as u16,
                update(attested, attested + 1, 32, None),
            );
        }
        server.settle(Slot(10 * 64 + 21));

        // Periods 0 and 1 come back; the missing period 2 ends the run.
        assert_eq!(range(&server, 0, 10), [Slot(20), Slot(84)]);
        // The run starts at the earliest known period in the range, here 3.
        assert_eq!(range(&server, 2, 3), [Slot(212)]);
        // A count of 1000 returns at most 128 updates: periods 10 through 137.
        // Period 10 is settled and period 11 pending, and the run spans both.
        let capped = range(&server, 10, 1000);
        assert_eq!(capped.len(), 128);
        assert_eq!(capped.last(), Some(&Slot(137 * 64 + 20)));
        // A count of zero, or a range past every period, returns nothing and never overflows.
        assert_eq!(range(&server, 0, 0), []);
        assert_eq!(range(&server, u64::MAX, u64::MAX), []);
    }

    #[test]
    fn a_reorg_serves_the_updates_of_the_new_branch() {
        // Fixture state: two branches from a block at 20.
        //
        //     branch a: block a at 21, signed by 30 of 32
        //     branch b: block b at 22, signed by 20 of 32, proving finality of slot 8
        let mut server = LightClientServer::new();
        let on_a = update(20, 21, 30, None);
        let on_b = update(20, 22, 20, Some(8));
        server.offer_update(block(0xa), on_a.clone()).unwrap();
        server.offer_update(block(0xb), on_b.clone()).unwrap();

        // Before any head names a branch, nothing is served.
        assert_eq!(range(&server, 0, 1), []);
        assert_eq!(server.latest_optimistic_update(), None);

        // The head on branch a serves its update, and no finality.
        server.follow([block(0xa)]);
        assert_eq!(server.updates_by_range(0, 1).collect::<Vec<_>>(), [&on_a]);
        assert_eq!(
            server.latest_optimistic_update(),
            Some(&on_a.optimistic_update().unwrap())
        );
        assert_eq!(server.latest_finality_update(), None);

        // The head moves to branch b: its weaker update is the only canonical one now.
        server.follow([block(0xb)]);
        assert_eq!(server.updates_by_range(0, 1).collect::<Vec<_>>(), [&on_b]);
        assert_eq!(
            server.latest_optimistic_update(),
            Some(&on_b.optimistic_update().unwrap())
        );
        assert_eq!(
            server.latest_finality_update(),
            Some(&on_b.finality_update().unwrap())
        );

        // And back to branch a, whose update was kept aside.
        server.follow([block(0xa)]);
        assert_eq!(server.updates_by_range(0, 1).collect::<Vec<_>>(), [&on_a]);
        assert_eq!(server.latest_finality_update(), None);
    }

    #[test]
    fn finality_settles_the_canonical_updates_and_drops_the_orphans() {
        // Fixture state: blocks at 21 and 40 on the canonical chain, an orphan at 22.
        // Finality reaches slot 32, past 21 and 22 but not 40.
        let mut server = LightClientServer::new();
        let early = update(20, 21, 30, Some(8));
        let orphan = update(20, 22, 32, None);
        let late = update(39, 40, 20, None);
        server.offer_update(block(21), early.clone()).unwrap();
        server.offer_update(block(22), orphan).unwrap();
        server.offer_update(block(40), late.clone()).unwrap();
        server.follow([block(21), block(40)]);
        server.settle(Slot(32));

        // The head chain since finality is the block at 40 alone, and the settled one stays served.
        server.follow([block(40)]);
        assert_eq!(server.updates_by_range(0, 1).collect::<Vec<_>>(), [&early]);
        assert_eq!(
            server.latest_optimistic_update(),
            Some(&late.optimistic_update().unwrap())
        );
        assert_eq!(
            server.latest_finality_update(),
            Some(&early.finality_update().unwrap())
        );

        // The orphan was dropped: naming it canonical serves nothing of it.
        // With no pending block canonical, the latest updates fall back to the settled one.
        server.follow([block(22)]);
        assert_eq!(server.updates_by_range(0, 1).collect::<Vec<_>>(), [&early]);
        assert_eq!(
            server.latest_optimistic_update(),
            Some(&early.optimistic_update().unwrap())
        );
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
        // Both updates are final once slot 85 is.
        offer(&mut server, 21, update(20, 21, 32, None));
        offer(&mut server, 85, update(84, 85, 32, None));
        server.settle(Slot(85));

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
        offer(&mut server, 21, local.clone());
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
