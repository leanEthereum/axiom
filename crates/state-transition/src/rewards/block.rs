//! What a block pays its proposer, by the operations that earned it.

use std::collections::BTreeSet;

use axiom_ssz::{BitList, Length};
use axiom_types::{
    ChainConfig, ForkName, Gwei, Preset, ValidatorIndex,
    accessors::CoreState,
    combined,
    phase0::{self, AttestationData},
};

use super::RewardsError;
use crate::{
    ActiveBalance, CachedState, KnownVerdict, State, StateError, TransitionError, Verification,
    phase0::epoch::BaseReward,
};

/// A block's rewards to its proposer, by source.
///
/// # Overview
///
/// From Altair on the block pays the proposer as it processes each operation.
/// The amounts here are those payments, recorded as the block is applied.
///
/// Phase0 pays for included votes only when their epoch is scored.
/// For a phase0 block, the attestation reward is the proposer's share of every vote it included first.
/// It uses the block's balances, which the scoring keeps for votes of the previous epoch.
/// A vote of the current epoch is scored an epoch later, after effective balances may change.
///
/// See `process_attestation`, `process_sync_aggregate`, and `slash_validator` in each fork's spec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockRewards {
    /// The proposer paid.
    pub proposer_index: ValidatorIndex,
    /// Paid for the votes the block includes.
    pub attestations: Gwei,
    /// Paid for the sync committee's signature.
    pub sync_aggregate: Gwei,
    /// Paid for proposer slashings.
    pub proposer_slashings: Gwei,
    /// Paid for attester slashings.
    pub attester_slashings: Gwei,
}

impl BlockRewards {
    /// The rewards of a block, applied to its parent's post-state.
    ///
    /// Signatures are not checked and the payload is taken as valid: the block is already known.
    ///
    /// # Errors
    ///
    /// Fails when the block does not apply to the state.
    pub fn of_block<P: Preset>(
        mut state: State<P>,
        block: &combined::SignedBeaconBlock<P>,
        config: &ChainConfig,
    ) -> Result<Self, RewardsError> {
        let slot = block.slot();
        if slot > state.beacon().slot() {
            state.process_slots(config, slot)?;
        }
        let deferred = match block {
            combined::SignedBeaconBlock::Phase0(signed) => {
                Some(Self::first_inclusions(&mut state, &signed.message)?)
            }
            _ => None,
        };
        state.state_transition(config, block, Verification::Skip, &KnownVerdict(true))?;
        let ledger = state.caches.proposer_ledger;
        Ok(Self {
            proposer_index: block.message().proposer_index(),
            attestations: deferred.unwrap_or(ledger.attestations),
            sync_aggregate: ledger.sync_aggregate,
            proposer_slashings: ledger.proposer_slashings,
            attester_slashings: ledger.attester_slashings,
        })
    }

    /// The sum of every reward.
    #[must_use]
    pub fn total(&self) -> Gwei {
        self.attestations + self.sync_aggregate + self.proposer_slashings + self.attester_slashings
    }

    /// The proposer's share of the phase0 votes a block includes before any other block.
    ///
    /// The earliest inclusion pays its proposer an eighth of the voter's base reward.
    /// Only unslashed voters count.
    /// See `get_inclusion_delay_deltas` in the phase0 beacon chain spec.
    fn first_inclusions<P: Preset>(
        state: &mut State<P>,
        block: &phase0::BeaconBlock<P>,
    ) -> Result<Gwei, RewardsError> {
        let fork = state.fork_name();
        let mut cached =
            state
                .of_fork::<phase0::BeaconState<P>>()
                .ok_or(TransitionError::ForkMismatch {
                    slot: block.slot,
                    block: ForkName::Phase0,
                    state: fork,
                })?;
        let base = BaseReward::new(ActiveBalance::of(cached.beacon()));

        // Phase 1: the voters the state already records, per target epoch.
        let recorded: Vec<_> = cached
            .beacon()
            .previous_epoch_attestations
            .iter()
            .chain(cached.beacon().current_epoch_attestations.iter())
            .map(|pending| (pending.data.clone(), pending.aggregation_bits.clone()))
            .collect();
        let mut included = BTreeSet::new();
        for (data, bits) in &recorded {
            for voter in Self::voters(&mut cached, data, bits)? {
                included.insert((data.target.epoch, voter));
            }
        }

        // Phase 2: each voter this block records first earns the proposer its share.
        let mut reward = Gwei::ZERO;
        for attestation in &block.body.attestations {
            let data = &attestation.data;
            for voter in Self::voters(&mut cached, data, &attestation.aggregation_bits)? {
                let validator = &cached.beacon().validators[voter.as_usize()];
                if included.insert((data.target.epoch, voter)) && !validator.slashed {
                    reward += base.proposer_share::<P>(validator.effective_balance);
                }
            }
        }
        Ok(reward)
    }

    /// The committee members whose bit a phase0 vote sets.
    ///
    /// A vote naming no committee has no voters; block processing refuses it later.
    fn voters<P: Preset, N: Length>(
        state: &mut CachedState<'_, phase0::BeaconState<P>>,
        data: &AttestationData,
        bits: &BitList<N>,
    ) -> Result<Vec<ValidatorIndex>, StateError> {
        let committees = state.committees(data.target.epoch)?;
        Ok(committees
            .committee(data.slot, data.index)
            .map(|committee| {
                committee
                    .iter()
                    .zip(bits.iter())
                    .filter_map(|(member, bit)| bit.then_some(*member))
                    .collect()
            })
            .unwrap_or_default())
    }
}
