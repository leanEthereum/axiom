//! What a full node collects to serve light clients: bootstraps, best updates, latest updates.

use std::collections::HashMap;

use axiom_light_client::{
    BootstrapData, Header, Layout, UpdateData, UpdateQuality,
    combined::{LightClientBootstrap, LightClientHeader},
};
use axiom_ssz::{GeneralizedIndex, Root};
use axiom_state_transition::State;
use axiom_types::{
    Bytes32, ChainConfig, Epoch, ForkName, Preset, Slot,
    altair::{SyncAggregate, SyncCommittee},
};

use super::history::{BlockId, History};
use crate::Failure;

/// What a block's post-state lets a full node prove later, and the best data up to it.
///
/// See `CachedLightClientData` in the spec's light client data collection helpers.
#[derive(Clone, Debug)]
struct Cached<P: Preset> {
    /// Proof of the current sync committee.
    current_sync_committee_branch: Vec<Bytes32>,
    /// Proof of the next sync committee.
    next_sync_committee_branch: Vec<Bytes32>,
    /// First slot of the finalized epoch, or the finalized block's slot once known.
    finalized_slot: Slot,
    /// Proof of the finalized root.
    finality_branch: Vec<Bytes32>,
    /// Best update of the block's period on its branch.
    best: Option<UpdateData<LightClientHeader<P>, P>>,
    /// Latest slot on the branch with enough sync committee signers.
    latest_signature_slot: Slot,
}

/// The light client data a full node collects as blocks arrive and heads change.
///
/// See `LightClientDataStore` in the spec's light client data collection helpers.
#[derive(Debug)]
pub(super) struct Collector<P: Preset> {
    /// The chain configuration.
    config: ChainConfig,
    /// Cached data by block, for the finalized block and every newer one.
    cache: HashMap<BlockId, Cached<P>>,
    /// The latest finality update on the canonical chain.
    pub(super) latest: Option<UpdateData<LightClientHeader<P>, P>>,
    /// The earliest slot data is collected for.
    pub(super) tail_slot: Slot,
    /// Headers of finalized epoch boundary blocks, for bootstraps.
    headers: HashMap<Root, LightClientHeader<P>>,
    /// Current sync committee branches of those blocks, by slot.
    current_branches: HashMap<Slot, Vec<Bytes32>>,
    /// Current sync committee by period, when the finalized history holds it.
    sync_committees: HashMap<u64, Option<SyncCommittee<P>>>,
    /// Best update by period, on the canonical chain.
    pub(super) best_updates: HashMap<u64, UpdateData<LightClientHeader<P>, P>>,
}

impl<P: Preset> Collector<P> {
    /// An empty collector, collecting from a tail slot on.
    pub(super) fn new(config: ChainConfig, tail_slot: Slot) -> Self {
        Self {
            config,
            cache: HashMap::new(),
            latest: None,
            tail_slot,
            headers: HashMap::new(),
            current_branches: HashMap::new(),
            sync_committees: HashMap::new(),
            best_updates: HashMap::new(),
        }
    }

    /// Caches what a block's post-state proves, with the best data so far on its branch.
    ///
    /// See `_cache_lc_data` in the spec's light client data collection helpers.
    fn cache(
        &mut self,
        state: &State<P>,
        id: BlockId,
        best: Option<UpdateData<LightClientHeader<P>, P>>,
        latest_signature_slot: Slot,
    ) -> Result<(), Failure> {
        let beacon = state.beacon();
        let core = beacon.as_core();
        let layout = Layout::at::<P>(&self.config, core.slot());
        let prove = |gindex: GeneralizedIndex| {
            beacon
                .prove(gindex)
                .map(|(_, proof)| proof.branch.iter().map(|node| Bytes32(node.0)).collect())
                .ok_or_else(|| Failure(format!("state has no node at {}", gindex.get())))
        };
        let cached = Cached {
            current_sync_committee_branch: prove(layout.current_sync_committee)?,
            next_sync_committee_branch: prove(layout.next_sync_committee)?,
            finalized_slot: core.finalized_checkpoint().epoch.start_slot::<P>(),
            finality_branch: prove(layout.finalized_root)?,
            best,
            latest_signature_slot,
        };
        if self.cache.insert(id, cached).is_some() {
            return Err(Failure(format!(
                "light client data of {} cached twice",
                id.root
            )));
        }
        Ok(())
    }

    /// Caches the data of the block a case starts from, and offers it as a bootstrap.
    pub(super) fn start(
        &mut self,
        history: &mut History<P>,
        state: &State<P>,
        id: BlockId,
    ) -> Result<(), Failure> {
        self.cache(state, id, None, Slot::GENESIS)?;
        self.create_bootstrap(history, id)
    }

    /// Cached data of a block.
    fn cached(&self, id: BlockId) -> Result<&Cached<P>, Failure> {
        self.cache
            .get(&id)
            .ok_or_else(|| Failure(format!("no light client data cached for {}", id.root)))
    }

    /// Updates the data with a new block and its post-state.
    ///
    /// See `_process_new_block_for_light_client` and `_create_lc_update` in the helpers.
    pub(super) fn on_block(
        &mut self,
        history: &History<P>,
        state: &State<P>,
        id: BlockId,
        parent: BlockId,
    ) -> Result<(), Failure> {
        if id.slot < self.tail_slot {
            return Ok(());
        }
        if parent.slot < self.tail_slot {
            return self.cache(state, id, None, Slot::GENESIS);
        }

        // A new period starts with no best update.
        let attested_period = parent.slot.sync_committee_period::<P>();
        let signature_period = id.slot.sync_committee_period::<P>();
        let attested = self.cached(parent)?;
        let mut best = if attested_period == signature_period {
            attested.best.clone()
        } else {
            None
        };

        // Too few signers leave the latest signature where it was.
        let record = history.block(&id.root)?;
        let sync_aggregate = record
            .sync_aggregate
            .clone()
            .ok_or_else(|| Failure(format!("block {} carries no sync aggregate", id.root)))?;
        let participants = sync_aggregate.sync_committee_bits.count_ones() as u64;
        let enough = participants >= P::MIN_SYNC_COMMITTEE_PARTICIPANTS;
        let latest_signature_slot = if enough {
            id.slot
        } else {
            attested.latest_signature_slot
        };
        if !enough || attested_period != signature_period {
            return self.cache(state, id, best, latest_signature_slot);
        }

        let next_sync_committee = state
            .beacon()
            .sync_committees()
            .map(|committees| committees.next_sync_committee().clone())
            .ok_or_else(|| Failure::new("post-state has no sync committees"))?;
        let mut update = self.finality_data(history, parent, id.slot, sync_aggregate)?;
        update.next_sync_committee = next_sync_committee;
        update
            .next_sync_committee_branch
            .clone_from(&self.cached(parent)?.next_sync_committee_branch);
        if best
            .as_ref()
            .is_none_or(|best| UpdateQuality::of(&update) > UpdateQuality::of(best))
        {
            best = Some(update);
        }
        self.cache(state, id, best, latest_signature_slot)
    }

    /// A finality update's fields for an attested block, in the attested block's format.
    ///
    /// See `_create_lc_finality_update_from_lc_data` in the helpers.
    fn finality_data(
        &mut self,
        history: &History<P>,
        attested: BlockId,
        signature_slot: Slot,
        sync_aggregate: SyncAggregate<P>,
    ) -> Result<UpdateData<LightClientHeader<P>, P>, Failure> {
        let attested_header = history.block(&attested.root)?.header.clone();
        let format = attested_header.format();
        let cached_slot = self.cached(attested)?.finalized_slot;
        let mut finalized_header = LightClientHeader::default();
        let mut finality_branch = Vec::new();
        if let Some(finalized) = history.finalized_at(cached_slot) {
            // Empty slots ended the finalized epoch, so the finalized block sits earlier.
            if finalized.slot != cached_slot
                && let Some(cached) = self.cache.get_mut(&attested)
            {
                cached.finalized_slot = finalized.slot;
            }
            finalized_header = if finalized.slot == Slot::GENESIS {
                LightClientHeader::empty(format)
            } else {
                history
                    .block(&finalized.root)?
                    .header
                    .clone()
                    .upgrade_to(format, &self.config)
                    .map_err(|error| Failure(error.to_string()))?
            };
            finality_branch.clone_from(&self.cached(attested)?.finality_branch);
        }
        // Without a finalized block the update proves nothing, so both stay empty.
        if finality_branch.is_empty() {
            finalized_header = LightClientHeader::empty(format);
        }
        Ok(UpdateData {
            attested_header,
            finalized_header,
            finality_branch,
            sync_aggregate,
            signature_slot,
            ..UpdateData::default()
        })
    }

    /// Offers a finalized block as a bootstrap.
    ///
    /// See `_create_lc_bootstrap` in the helpers.
    fn create_bootstrap(&mut self, history: &mut History<P>, id: BlockId) -> Result<(), Failure> {
        let period = id.slot.sync_committee_period::<P>();
        if !self.sync_committees.contains_key(&period) {
            let committee = self.finalized_committee(history, period)?;
            self.sync_committees.insert(period, committee);
        }
        let header = history.block(&id.root)?.header.clone();
        self.headers.insert(id.root, header);
        let branch = self.cached(id)?.current_sync_committee_branch.clone();
        self.current_branches.insert(id.slot, branch);
        Ok(())
    }

    /// The current sync committee of a period, from the finalized history.
    ///
    /// The generator advances the finalized state in place, in every map that shares it.
    /// See `_get_current_sync_committee_for_finalized_period` in the helpers.
    fn finalized_committee(
        &self,
        history: &mut History<P>,
        period: u64,
    ) -> Result<Option<SyncCommittee<P>>, Failure> {
        let altair_slot = self.config.fork_epoch(ForkName::Altair).start_slot::<P>();
        let low_slot = history.tail_slot.max(altair_slot);
        if period < low_slot.sync_committee_period::<P>() {
            return Ok(None);
        }
        let slot = period_start::<P>(period).max(low_slot);
        let Some(id) = history.finalized_at(slot) else {
            return Ok(None);
        };
        let state_root = history.block(&id.root)?.state_root;
        let cell = history.checkpoint_cell(&state_root)?;
        let state = &mut history.cells[cell];
        if slot > state.beacon().as_core().slot() {
            state
                .process_slots(&self.config, slot)
                .map_err(|error| Failure(error.to_string()))?;
        }
        Ok(state
            .beacon()
            .sync_committees()
            .map(|committees| committees.current_sync_committee().clone()))
    }

    /// Commits the best data of a new head's branch, and its latest finality update.
    ///
    /// See `_process_head_change_for_light_client` in the helpers.
    pub(super) fn on_head(
        &mut self,
        history: &History<P>,
        head: BlockId,
        old_finalized: BlockId,
    ) -> Result<(), Failure> {
        if head.slot < self.tail_slot {
            return Ok(());
        }

        // Commit the best update of each period the head's branch reaches, newest first.
        let head_period = head.slot.sync_committee_period::<P>();
        let low_slot = self.tail_slot.max(old_finalized.slot);
        let low_period = low_slot.sync_committee_period::<P>();
        let mut id = head;
        for period in (low_period..=head_period).rev() {
            let period_end = period_start::<P>(period + 1) - 1;
            match history.ancestor(id, period_end) {
                Some(ancestor) if ancestor.slot >= low_slot => id = ancestor,
                _ => break,
            }
            let best = self.cached(id)?.best.clone();
            match best {
                Some(best) if best.participants() as u64 >= P::MIN_SYNC_COMMITTEE_PARTICIPANTS => {
                    self.best_updates.insert(period, best);
                }
                _ => {
                    self.best_updates.remove(&period);
                }
            }
        }

        // The latest update is signed by the latest well-signed block on the branch.
        self.latest = None;
        let signature_slot = self.cached(head)?.latest_signature_slot;
        if signature_slot <= low_slot {
            return Ok(());
        }
        let Some(signature) = history
            .ancestor(head, signature_slot)
            .filter(|signature| signature.slot > low_slot)
        else {
            return Ok(());
        };
        let Some(attested) = history
            .ancestor(signature, signature.slot - 1)
            .filter(|attested| attested.slot >= low_slot)
        else {
            return Ok(());
        };
        let sync_aggregate = history
            .block(&signature.root)?
            .sync_aggregate
            .clone()
            .ok_or_else(|| {
                Failure(format!(
                    "block {} carries no sync aggregate",
                    signature.root
                ))
            })?;
        self.latest =
            Some(self.finality_data(history, attested, signature_slot, sync_aggregate)?);
        Ok(())
    }

    /// Offers newly finalized epoch boundary blocks as bootstraps, and prunes the cache.
    ///
    /// See `_process_finalization_for_light_client` in the helpers.
    pub(super) fn on_finalization(
        &mut self,
        history: &mut History<P>,
        finalized: BlockId,
        old_finalized: BlockId,
    ) -> Result<(), Failure> {
        if finalized.slot < self.tail_slot {
            return Ok(());
        }
        let low_slot = (old_finalized.slot + 1).max(self.tail_slot);
        let mut boundary = finalized.slot;
        while boundary >= low_slot {
            let Some(id) = history.finalized_at(boundary) else {
                break;
            };
            if id.slot >= low_slot {
                self.create_bootstrap(history, id)?;
            }
            // The first slot whose checkpoint can name this block.
            boundary = (id.slot + (P::SLOTS_PER_EPOCH - 1))
                .epoch::<P>()
                .start_slot::<P>();
            if boundary.0 < P::SLOTS_PER_EPOCH {
                break;
            }
            boundary = boundary - P::SLOTS_PER_EPOCH;
        }
        self.cache.retain(|id, _| id.slot >= finalized.slot);
        Ok(())
    }

    /// The bootstrap a full node serves for a block, if it is a finalized epoch boundary.
    ///
    /// See `get_light_client_bootstrap` in the helpers.
    pub(super) fn bootstrap(
        &self,
        root: &Root,
    ) -> Result<Option<LightClientBootstrap<P>>, Failure> {
        let Some(header) = self.headers.get(root) else {
            return Ok(None);
        };
        let slot = Header::<P>::beacon(header).slot;
        let committee = self
            .sync_committees
            .get(&slot.sync_committee_period::<P>())
            .cloned()
            .flatten()
            .ok_or_else(|| {
                Failure(format!(
                    "no sync committee for the bootstrap at slot {slot}"
                ))
            })?;
        let branch = self
            .current_branches
            .get(&slot)
            .cloned()
            .ok_or_else(|| Failure(format!("no committee branch for slot {slot}")))?;
        LightClientBootstrap::from_data(BootstrapData {
            header: header.clone(),
            current_sync_committee: committee,
            current_sync_committee_branch: branch,
        })
        .map(Some)
        .map_err(|error| Failure(error.to_string()))
    }
}

/// First slot of a sync committee period.
const fn period_start<P: Preset>(period: u64) -> Slot {
    Epoch(period * P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD).start_slot::<P>()
}
