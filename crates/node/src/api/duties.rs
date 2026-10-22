//! Validator duties of an epoch, read from the head's state, and the routes that serve them.
//!
//! See the duties routes of beacon-APIs, and the phase0, Altair, and Gloas validator specs.

use std::collections::BTreeSet;

use axiom_beacon_json::{
    ApiJson,
    api::{AttesterDuty, Duties, ProposerDuty, PtcDuty, SyncDuty},
};
use axiom_http::{Request, Response, StatusCode};
use axiom_state_transition::{State, gloas::ptc::PtcWindow};
use axiom_types::{
    BlsPubkey, ChainConfig, CommitteeIndex, Epoch, Preset, Root, Slot, ValidatorIndex,
    accessors::{CoreState, ForkState},
    gloas,
};

use super::{
    ApiContext,
    query::Body,
    reply::{ApiError, ApiResult, Reply, Routes},
};

/// Routes under `/eth/v1/validator/duties` and `/eth/v2/validator/duties`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DutyRoutes;

impl DutyRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get(
                "/eth/v1/validator/duties/proposer/{epoch}",
                Self::proposers::<P>,
            )
            .get(
                "/eth/v2/validator/duties/proposer/{epoch}",
                Self::proposers_v2::<P>,
            )
            .post(
                "/eth/v1/validator/duties/attester/{epoch}",
                Self::attesters::<P>,
            )
            .post("/eth/v1/validator/duties/sync/{epoch}", Self::sync::<P>)
            .post("/eth/v1/validator/duties/ptc/{epoch}", Self::ptc::<P>)
    }

    /// The proposers of an epoch, with the root before the epoch as their dependent root.
    ///
    /// See `getProposerDuties` in the beacon API.
    async fn proposers<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let epoch = Self::epoch(&request)?;
        context
            .query(move |chain| {
                let head = chain.head();
                let roster = Roster::new(chain.head_state()?, chain.config(), head.root);
                let dependent_root = roster.root_before(epoch.start_slot::<P>());
                let data = roster.proposers(epoch)?;
                Ok(Self::reply(Some(dependent_root), head.optimistic, data))
            })
            .await
    }

    /// The proposers of an epoch, with the root before the previous epoch as their dependent root.
    ///
    /// The proposer lookahead fixes an epoch's proposers one epoch ahead.
    /// So they depend on the last block before the epoch preceding theirs.
    /// See `getProposerDutiesV2` in the beacon API.
    async fn proposers_v2<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let epoch = Self::epoch(&request)?;
        context
            .query(move |chain| {
                let head = chain.head();
                let roster = Roster::new(chain.head_state()?, chain.config(), head.root);
                let dependent_root = roster.root_before_previous(epoch);
                let data = roster.proposers(epoch)?;
                Ok(Self::reply(Some(dependent_root), head.optimistic, data))
            })
            .await
    }

    /// The committee seats of some validators in an epoch.
    ///
    /// See `getAttesterDuties` in the beacon API.
    async fn attesters<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let epoch = Self::epoch(&request)?;
        let validators = Self::indices(&request)?;
        context
            .query(move |chain| {
                let head = chain.head();
                let roster = Roster::new(chain.head_state()?, chain.config(), head.root);
                let dependent_root = roster.root_before_previous(epoch);
                let data = roster.attesters(epoch, &validators)?;
                Ok(Self::reply(Some(dependent_root), head.optimistic, data))
            })
            .await
    }

    /// The sync committee seats of some validators in an epoch's period.
    ///
    /// Sync committees follow the period, so these duties carry no dependent root.
    /// See `getSyncCommitteeDuties` in the beacon API.
    async fn sync<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let epoch = Self::epoch(&request)?;
        let validators = Self::indices(&request)?;
        context
            .query(move |chain| {
                let head = chain.head();
                let data = Roster::new(chain.head_state()?, chain.config(), head.root)
                    .sync(epoch, &validators)?;
                Ok(Self::reply(None, head.optimistic, data))
            })
            .await
    }

    /// The payload timeliness committee seats of some validators in an epoch.
    ///
    /// See `getPtcDuties` in the beacon API.
    async fn ptc<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let epoch = Self::epoch(&request)?;
        let validators = Self::indices(&request)?;
        context
            .query(move |chain| {
                let head = chain.head();
                let roster = Roster::new(chain.head_state()?, chain.config(), head.root);
                let dependent_root = roster.root_before_previous(epoch);
                let data = roster.ptc(epoch, &validators)?;
                Ok(Self::reply(Some(dependent_root), head.optimistic, data))
            })
            .await
    }

    /// The epoch of a duties path.
    fn epoch(request: &Request) -> Result<Epoch, ApiError> {
        let text = request
            .param("epoch")
            .ok_or_else(|| ApiError::bad_request("missing epoch"))?;
        text.parse()
            .map(Epoch)
            .map_err(|_| ApiError::bad_request(format!("invalid epoch: {text}")))
    }

    /// The validator indices of a duties request body: a JSON array of decimal strings.
    fn indices(request: &Request) -> Result<BTreeSet<ValidatorIndex>, ApiError> {
        Ok(Body(request).json_items()?.into_iter().collect())
    }

    /// A duties reply.
    fn reply<T: ApiJson>(
        dependent_root: Option<Root>,
        execution_optimistic: bool,
        data: Vec<T>,
    ) -> Response {
        let duties = Duties {
            dependent_root,
            execution_optimistic,
            data,
        };
        Reply::json(StatusCode::OK, &duties.to_json())
    }
}

/// The duties of an epoch, computed on a copy of the head's state.
///
/// # Overview
///
/// Committees of an epoch are fixed one epoch ahead, by the shuffling's lookahead.
/// So the head's state answers for its own epoch, the one before, and the one after.
/// Each duty set comes with the root its shuffling depends on.
/// A validator client refetches its duties when that root changes, as after a reorg.
#[derive(Debug)]
pub(crate) struct Roster<'a, P: Preset> {
    /// The head's state, advanced as needed.
    state: State<P>,
    /// The chain configuration.
    config: &'a ChainConfig,
    /// Root of the head block, for dependent roots past the head.
    head_root: Root,
}

impl<'a, P: Preset> Roster<'a, P> {
    /// Duties read from a copy of the head's state.
    pub(crate) fn new(head: &State<P>, config: &'a ChainConfig, head_root: Root) -> Self {
        Self {
            state: head.clone(),
            config,
            head_root,
        }
    }

    /// The proposers of every slot of an epoch, the current or the next.
    ///
    /// # Errors
    ///
    /// Fails for any other epoch, which the state cannot answer for.
    pub(crate) fn proposers(mut self, epoch: Epoch) -> Result<Vec<ProposerDuty>, ApiError> {
        let current = self.state.beacon().current_epoch();
        if epoch != current && epoch != current + 1 {
            return Err(ApiError::bad_request(format!(
                "proposer duties of epoch {epoch} are not known at epoch {current}"
            )));
        }
        let mut duties = Vec::with_capacity(P::SLOTS_PER_EPOCH as usize);
        for slot in (0..P::SLOTS_PER_EPOCH).map(|offset| epoch.start_slot::<P>() + offset) {
            let proposer = self
                .at_slot(slot)?
                .beacon_proposer_index()
                .map_err(|error| ApiError::internal(error.to_string()))?;
            duties.push(ProposerDuty {
                pubkey: self.pubkey(proposer),
                validator_index: proposer,
                slot,
            });
        }
        Ok(duties)
    }

    /// The committee seats of some validators in an epoch, up to the next.
    ///
    /// # Errors
    ///
    /// Fails for an epoch past the next.
    pub(crate) fn attesters(
        mut self,
        epoch: Epoch,
        validators: &BTreeSet<ValidatorIndex>,
    ) -> Result<Vec<AttesterDuty>, ApiError> {
        let current = self.state.beacon().current_epoch();
        if epoch > current + 1 {
            return Err(ApiError::bad_request(format!(
                "attester duties of epoch {epoch} are not known at epoch {current}"
            )));
        }
        let committees = self.state.compute_committees(epoch);
        let per_slot = committees.committees_per_slot();
        let mut duties = Vec::new();
        for slot in (0..P::SLOTS_PER_EPOCH).map(|offset| epoch.start_slot::<P>() + offset) {
            for index in (0..per_slot).map(CommitteeIndex) {
                let Some(members) = committees.committee(slot, index) else {
                    continue;
                };
                for (position, member) in members.iter().enumerate() {
                    if validators.contains(member) {
                        duties.push(AttesterDuty {
                            pubkey: self.pubkey(*member),
                            validator_index: *member,
                            committee_index: index,
                            committee_length: members.len() as u64,
                            committees_at_slot: per_slot,
                            validator_committee_index: position as u64,
                            slot,
                        });
                    }
                }
            }
        }
        Ok(duties)
    }

    /// The sync committee seats of some validators in an epoch's period, the current or the next.
    ///
    /// # Errors
    ///
    /// Fails before Altair, or for a period the state does not hold.
    pub(crate) fn sync(
        self,
        epoch: Epoch,
        validators: &BTreeSet<ValidatorIndex>,
    ) -> Result<Vec<SyncDuty>, ApiError> {
        let beacon = self.state.beacon();
        let period = |epoch: Epoch| epoch.0 / P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let current = period(beacon.current_epoch());
        let committees = beacon
            .sync_committees()
            .ok_or_else(|| ApiError::bad_request("the head's fork has no sync committee"))?;
        let committee = match period(epoch) {
            asked if asked == current => committees.current_sync_committee(),
            asked if asked == current + 1 => committees.next_sync_committee(),
            asked => {
                return Err(ApiError::bad_request(format!(
                    "sync period {asked} is not known in period {current}"
                )));
            }
        };
        let mut duties = Vec::new();
        for validator in validators {
            let Some(record) = beacon.validators().get(validator.as_usize()) else {
                continue;
            };
            let seats: Vec<u64> = committee
                .pubkeys
                .iter()
                .enumerate()
                .filter(|(_, key)| **key == record.pubkey)
                .map(|(seat, _)| seat as u64)
                .collect();
            if !seats.is_empty() {
                duties.push(SyncDuty {
                    pubkey: record.pubkey,
                    validator_index: *validator,
                    validator_sync_committee_indices: seats,
                });
            }
        }
        Ok(duties)
    }

    /// The payload timeliness committee seats of some validators in an epoch, Gloas only.
    ///
    /// See `get_ptc_assignment` in the Gloas validator spec.
    ///
    /// # Errors
    ///
    /// Fails before Gloas, or for an epoch outside the state's committee window.
    pub(crate) fn ptc(
        self,
        epoch: Epoch,
        validators: &BTreeSet<ValidatorIndex>,
    ) -> Result<Vec<PtcDuty>, ApiError> {
        let beacon = self.state.beacon();
        let gloas = gloas::BeaconState::<P>::from_any(beacon)
            .ok_or_else(|| ApiError::bad_request("the head's fork has no payload committee"))?;
        let mut duties = Vec::new();
        for slot in (0..P::SLOTS_PER_EPOCH).map(|offset| epoch.start_slot::<P>() + offset) {
            let committee = PtcWindow::of_slot(gloas, slot, self.config.gloas_fork_epoch)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            let members: BTreeSet<ValidatorIndex> = committee.iter().copied().collect();
            for member in members.intersection(validators) {
                duties.push(PtcDuty {
                    pubkey: self.pubkey(*member),
                    validator_index: *member,
                    slot,
                });
            }
        }
        Ok(duties)
    }

    /// The state as of a slot of its epoch, or advanced to a later slot.
    ///
    /// A slot already passed in the same epoch only changes which slot the election draws for.
    /// The seed and the active set are the epoch's, so a copy with the slot set elects the same.
    fn at_slot(&mut self, slot: Slot) -> Result<State<P>, ApiError> {
        if slot > self.state.beacon().slot() {
            self.state
                .process_slots(self.config, slot)
                .map_err(|error| ApiError::internal(error.to_string()))?;
            return Ok(self.state.clone());
        }
        let mut copy = self.state.clone();
        *copy.beacon_mut().as_core_mut().slot_mut() = slot;
        Ok(copy)
    }

    /// Root of the latest block before the epoch preceding an epoch.
    ///
    /// Shufflings fixed one epoch ahead depend on it.
    /// The genesis root stands in when the epoch before does not exist.
    fn root_before_previous(&self, epoch: Epoch) -> Root {
        self.root_before(Epoch(epoch.0.saturating_sub(1)).start_slot::<P>())
    }

    /// Root of the latest block before a slot, the head's own root past the head.
    ///
    /// Before slot zero there is no block, so the genesis block stands in, as the API says.
    fn root_before(&self, slot: Slot) -> Root {
        let beacon = self.state.beacon();
        let previous = Slot(slot.0.saturating_sub(1));
        if previous < beacon.slot() {
            beacon
                .block_root_at_slot(previous)
                .unwrap_or(self.head_root)
        } else {
            self.head_root
        }
    }

    /// The key of a validator, zero when it does not exist.
    fn pubkey(&self, validator: ValidatorIndex) -> BlsPubkey {
        self.state
            .beacon()
            .validators()
            .get(validator.as_usize())
            .map(|record| record.pubkey)
            .unwrap_or_default()
    }
}
