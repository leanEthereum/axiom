//! Validator duties of an epoch, read from the head's state.

use std::collections::BTreeSet;

use axiom_state_transition::{State, gloas::ptc::PtcWindow};
use axiom_types::{
    BlsPubkey, ChainConfig, CommitteeIndex, Epoch, Preset, Root, Slot, ValidatorIndex,
    accessors::{CoreState, ForkState},
    gloas,
};

use super::reply::ApiError;

/// A proposer of one slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProposerDuty {
    /// The proposer's key.
    pub(crate) pubkey: BlsPubkey,
    /// The proposer.
    pub(crate) validator_index: ValidatorIndex,
    /// The slot it proposes in.
    pub(crate) slot: Slot,
}

/// An attester's seat in a committee of one slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AttesterDuty {
    /// The attester's key.
    pub(crate) pubkey: BlsPubkey,
    /// The attester.
    pub(crate) validator_index: ValidatorIndex,
    /// The committee it sits in.
    pub(crate) committee_index: CommitteeIndex,
    /// Members of the committee.
    pub(crate) committee_length: u64,
    /// Committees in the slot.
    pub(crate) committees_at_slot: u64,
    /// The attester's place in its committee.
    pub(crate) validator_committee_index: u64,
    /// The slot it attests in.
    pub(crate) slot: Slot,
}

/// A sync committee member's seats for one period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SyncDuty {
    /// The member's key.
    pub(crate) pubkey: BlsPubkey,
    /// The member.
    pub(crate) validator_index: ValidatorIndex,
    /// Its seats in the committee.
    pub(crate) seats: Vec<usize>,
}

/// The duties of an epoch, computed on a copy of the head's state.
///
/// # Overview
///
/// Committees of an epoch are fixed one epoch ahead, by the shuffling's lookahead.
/// So the head's state answers for its own epoch, the one before, and the one after.
/// Each duty set comes with the root its shuffling depends on.
/// A validator client refetches its duties when that root changes, as after a reorg.
/// See the duties routes of beacon-APIs, and the phase0 validator spec.
#[derive(Debug)]
pub(crate) struct Duties<'a, P: Preset> {
    /// The head's state, advanced as needed.
    state: State<P>,
    /// The chain configuration.
    config: &'a ChainConfig,
    /// Root of the head block, for dependent roots past the head.
    head_root: Root,
}

impl<'a, P: Preset> Duties<'a, P> {
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
    pub(crate) fn proposers(mut self, epoch: Epoch) -> Result<(Root, Vec<ProposerDuty>), ApiError> {
        let current = self.state.beacon().current_epoch();
        if epoch != current && epoch != current + 1 {
            return Err(ApiError::bad_request(format!(
                "proposer duties of epoch {epoch} are not known at epoch {current}"
            )));
        }
        let dependent_root = self.root_before(epoch.start_slot::<P>());
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
        Ok((dependent_root, duties))
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
    ) -> Result<(Root, Vec<AttesterDuty>), ApiError> {
        let current = self.state.beacon().current_epoch();
        if epoch > current + 1 {
            return Err(ApiError::bad_request(format!(
                "attester duties of epoch {epoch} are not known at epoch {current}"
            )));
        }
        // The shuffling of an epoch is fixed at the end of the epoch two before it.
        let dependent_root = self.root_before(Epoch(epoch.0.saturating_sub(1)).start_slot::<P>());
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
        Ok((dependent_root, duties))
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
            let seats: Vec<usize> = committee
                .pubkeys
                .iter()
                .enumerate()
                .filter(|(_, key)| **key == record.pubkey)
                .map(|(seat, _)| seat)
                .collect();
            if !seats.is_empty() {
                duties.push(SyncDuty {
                    pubkey: record.pubkey,
                    validator_index: *validator,
                    seats,
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
    ) -> Result<(Root, Vec<ProposerDuty>), ApiError> {
        let dependent_root = self.root_before(Epoch(epoch.0.saturating_sub(1)).start_slot::<P>());
        let beacon = self.state.beacon();
        let gloas = gloas::BeaconState::<P>::from_any(beacon)
            .ok_or_else(|| ApiError::bad_request("the head's fork has no payload committee"))?;
        let mut duties = Vec::new();
        for slot in (0..P::SLOTS_PER_EPOCH).map(|offset| epoch.start_slot::<P>() + offset) {
            let committee = PtcWindow::of_slot(gloas, slot, self.config.gloas_fork_epoch)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            let members: BTreeSet<ValidatorIndex> = committee.iter().copied().collect();
            for member in members.intersection(validators) {
                duties.push(ProposerDuty {
                    pubkey: self.pubkey(*member),
                    validator_index: *member,
                    slot,
                });
            }
        }
        Ok((dependent_root, duties))
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

    /// Root of the latest block before a slot, the head's own root past the head.
    fn root_before(&self, slot: Slot) -> Root {
        let beacon = self.state.beacon();
        match slot.0.checked_sub(1) {
            Some(previous) if Slot(previous) < beacon.slot() => beacon
                .block_root_at_slot(Slot(previous))
                .unwrap_or(self.head_root),
            // Genesis has no block before it; its own root stands in.
            _ => self.head_root,
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
