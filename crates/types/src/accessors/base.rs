//! The phase0 core every beacon state carries.

use axiom_ssz::CapacityError;

use crate::{
    Bytes32, Domain, DomainType, Epoch, ForkName, Gwei, Preset, Root, Slot, ValidatorIndex,
    combined,
    phase0::{
        BeaconBlockHeader, BlockRoots, Checkpoint, Eth1Data, Eth1DataVotes, Fork, HistoricalRoots,
        JustificationBits, RandaoMixes, Slashings, StateRoots, Validator,
    },
};

/// The fields every fork's state keeps from phase0, and the helpers that only read them.
///
/// # Overview
///
/// Every state of every fork implements it, and so does the state of any fork.
/// Code that only needs the core takes any state, without knowing its fork.
///
/// The trait stays object safe, so the state of any fork can hand out one view of itself.
/// Helpers that take generic arguments are therefore limited to sized implementors.
pub trait CoreState {
    /// The preset that sizes the state's vectors and lists.
    type Preset: Preset;

    /// The fork the state belongs to.
    fn fork_name(&self) -> ForkName;

    /// Merkle commitment to the whole state, which blocks name as their state root.
    fn state_root(&self) -> Root;

    /// Unix time of genesis, in seconds.
    fn genesis_time(&self) -> u64;

    /// Root of the genesis validator set, which identifies the chain.
    fn genesis_validators_root(&self) -> Root;

    /// Slot the state is at.
    fn slot(&self) -> Slot;

    /// Slot the state is at, for slot processing.
    fn slot_mut(&mut self) -> &mut Slot;

    /// Current and previous fork versions.
    fn fork(&self) -> &Fork;

    /// Header of the latest block, with its state root filled in one slot late.
    fn latest_block_header(&self) -> &BeaconBlockHeader;

    /// Header of the latest block, for block and slot processing.
    fn latest_block_header_mut(&mut self) -> &mut BeaconBlockHeader;

    /// Recent block roots, a ring buffer indexed by slot.
    fn block_roots(&self) -> &BlockRoots<Self::Preset>;

    /// Recent block roots, for slot processing.
    fn block_roots_mut(&mut self) -> &mut BlockRoots<Self::Preset>;

    /// Recent state roots, a ring buffer indexed by slot.
    fn state_roots(&self) -> &StateRoots<Self::Preset>;

    /// Recent state roots, for slot processing.
    fn state_roots_mut(&mut self) -> &mut StateRoots<Self::Preset>;

    /// The pre-Capella history accumulator.
    fn historical_roots(&self) -> &HistoricalRoots<Self::Preset>;

    /// The pre-Capella history accumulator, for its epoch update.
    fn historical_roots_mut(&mut self) -> &mut HistoricalRoots<Self::Preset>;

    /// Latest agreed deposit contract snapshot.
    fn eth1_data(&self) -> &Eth1Data;

    /// Latest agreed deposit contract snapshot, for the eth1 vote.
    fn eth1_data_mut(&mut self) -> &mut Eth1Data;

    /// Eth1 data votes of the current voting period.
    fn eth1_data_votes(&self) -> &Eth1DataVotes<Self::Preset>;

    /// Eth1 data votes, for the vote and its periodic reset.
    fn eth1_data_votes_mut(&mut self) -> &mut Eth1DataVotes<Self::Preset>;

    /// Deposits from the deposit contract processed so far.
    fn eth1_deposit_index(&self) -> u64;

    /// Deposits processed so far, for deposit processing.
    fn eth1_deposit_index_mut(&mut self) -> &mut u64;

    /// The validator registry.
    fn validators(&self) -> &[Validator];

    /// The validator registry, for edits in place.
    fn validators_mut(&mut self) -> &mut [Validator];

    /// Actual balance of each validator.
    fn balances(&self) -> &[Gwei];

    /// Actual balance of each validator, for edits in place.
    fn balances_mut(&mut self) -> &mut [Gwei];

    /// Appends a validator and its balance to the registry.
    ///
    /// Forks with more per-validator lists grow them through their own trait as well.
    ///
    /// # Errors
    ///
    /// Fails when the registry is at its limit, and leaves both lists unchanged.
    fn push_validator(&mut self, validator: Validator, balance: Gwei) -> Result<(), CapacityError>;

    /// Randomness accumulated from randao reveals, a ring buffer indexed by epoch.
    fn randao_mixes(&self) -> &RandaoMixes<Self::Preset>;

    /// Randao mixes, for the reveal and the epoch reset.
    fn randao_mixes_mut(&mut self) -> &mut RandaoMixes<Self::Preset>;

    /// Effective balance slashed per epoch, for the correlation penalty.
    fn slashings(&self) -> &Slashings<Self::Preset>;

    /// Slashed balances, for slashing and the epoch reset.
    fn slashings_mut(&mut self) -> &mut Slashings<Self::Preset>;

    /// Which of the last four epochs were justified, newest first.
    fn justification_bits(&self) -> &JustificationBits;

    /// Justification history, for the epoch's finality update.
    fn justification_bits_mut(&mut self) -> &mut JustificationBits;

    /// Justified checkpoint as of the previous epoch.
    fn previous_justified_checkpoint(&self) -> Checkpoint;

    /// Justified checkpoint as of the previous epoch, for the finality update.
    fn previous_justified_checkpoint_mut(&mut self) -> &mut Checkpoint;

    /// Latest justified checkpoint.
    fn current_justified_checkpoint(&self) -> Checkpoint;

    /// Latest justified checkpoint, for the finality update.
    fn current_justified_checkpoint_mut(&mut self) -> &mut Checkpoint;

    /// Latest finalized checkpoint.
    fn finalized_checkpoint(&self) -> Checkpoint;

    /// Latest finalized checkpoint, for the finality update.
    fn finalized_checkpoint_mut(&mut self) -> &mut Checkpoint;

    /// Epoch of the state's slot.
    fn current_epoch(&self) -> Epoch {
        self.slot().epoch::<Self::Preset>()
    }

    /// Epoch before the current one, or genesis at genesis.
    fn previous_epoch(&self) -> Epoch {
        self.current_epoch().saturating_sub(1)
    }

    /// Root of the block at a recent slot.
    ///
    /// Returns nothing unless the slot is in the past and still in the ring buffer.
    /// See `get_block_root_at_slot` in the phase0 beacon chain spec.
    fn block_root_at_slot(&self, slot: Slot) -> Option<Root> {
        let state_slot = self.slot();
        let window = <Self::Preset as Preset>::SLOTS_PER_HISTORICAL_ROOT;
        let in_range = slot < state_slot && state_slot.0 <= slot.0.saturating_add(window);
        in_range.then(|| self.block_roots()[(slot % window) as usize])
    }

    /// Root of the block at the start of a recent epoch.
    ///
    /// See `get_block_root` in the phase0 beacon chain spec.
    fn block_root(&self, epoch: Epoch) -> Option<Root> {
        self.block_root_at_slot(epoch.start_slot::<Self::Preset>())
    }

    /// Randao mix of a recent epoch.
    ///
    /// See `get_randao_mix` in the phase0 beacon chain spec.
    fn randao_mix(&self, epoch: Epoch) -> Bytes32 {
        self.randao_mixes()
            [(epoch % <Self::Preset as Preset>::EPOCHS_PER_HISTORICAL_VECTOR) as usize]
    }

    /// Indices of the validators active at an epoch, in registry order.
    ///
    /// See `get_active_validator_indices` in the phase0 beacon chain spec.
    fn active_validator_indices(&self, epoch: Epoch) -> Vec<ValidatorIndex> {
        self.validators()
            .iter()
            .enumerate()
            .filter(|(_, validator)| validator.is_active_at(epoch))
            .map(|(index, _)| ValidatorIndex::from(index))
            .collect()
    }

    /// Seed for a domain at an epoch.
    ///
    /// The mix comes from MIN_SEED_LOOKAHEAD + 1 epochs earlier.
    /// That mix was fixed before anyone could know which seed it would feed.
    /// See `get_seed` in the phase0 beacon chain spec.
    fn seed(&self, epoch: Epoch, domain_type: DomainType) -> Bytes32 {
        // Adding the vector length first keeps the subtraction from underflowing near genesis.
        let mix_epoch = Epoch(
            epoch.0 + <Self::Preset as Preset>::EPOCHS_PER_HISTORICAL_VECTOR
                - <Self::Preset as Preset>::MIN_SEED_LOOKAHEAD
                - 1,
        );
        let mix = self.randao_mix(mix_epoch);

        let mut preimage = [0; 4 + 8 + 32];
        preimage[..4].copy_from_slice(&domain_type.0);
        preimage[4..12].copy_from_slice(&epoch.0.to_le_bytes());
        preimage[12..].copy_from_slice(&mix.0);
        Bytes32(Root::sha256(&preimage).0)
    }

    /// Sum of the effective balances of some validators, at least one increment.
    ///
    /// The floor keeps every division by a total balance well defined.
    /// See `get_total_balance` in the phase0 beacon chain spec.
    fn total_balance(&self, indices: &[ValidatorIndex]) -> Gwei {
        let validators = self.validators();
        let sum: Gwei = indices
            .iter()
            .map(|index| validators[index.as_usize()].effective_balance)
            .sum();
        sum.max(<Self::Preset as Preset>::EFFECTIVE_BALANCE_INCREMENT)
    }

    /// Sum of the effective balances of the validators active in the current epoch.
    ///
    /// See `get_total_active_balance` in the phase0 beacon chain spec.
    fn total_active_balance(&self) -> Gwei {
        let epoch = self.current_epoch();
        let sum: Gwei = self
            .validators()
            .iter()
            .filter(|validator| validator.is_active_at(epoch))
            .map(|validator| validator.effective_balance)
            .sum();
        sum.max(<Self::Preset as Preset>::EFFECTIVE_BALANCE_INCREMENT)
    }

    /// Signature domain of a message type at an epoch.
    ///
    /// Messages from before the latest fork sign with the previous fork version.
    /// See `get_domain` in the phase0 beacon chain spec.
    fn domain(&self, domain_type: DomainType, epoch: Epoch) -> Domain {
        Domain::compute(
            domain_type,
            self.fork().version_at(epoch),
            self.genesis_validators_root(),
        )
    }

    /// Epochs since the last finalized checkpoint, counted from the previous epoch.
    ///
    /// See `get_finality_delay` in the phase0 beacon chain spec.
    fn finality_delay(&self) -> u64 {
        self.previous_epoch() - self.finalized_checkpoint().epoch
    }

    /// Whether finality has stalled long enough for the inactivity leak.
    ///
    /// The leak drains non-participants until the participants hold two thirds again.
    /// See `is_in_inactivity_leak` in the phase0 beacon chain spec.
    fn is_in_inactivity_leak(&self) -> bool {
        self.finality_delay() > <Self::Preset as Preset>::MIN_EPOCHS_TO_INACTIVITY_PENALTY
    }

    /// Validators that earn rewards or penalties for the previous epoch.
    ///
    /// Slashed validators stay eligible until withdrawable, so they keep paying penalties.
    /// See `get_eligible_validator_indices` in the phase0 beacon chain spec.
    fn eligible_validator_indices(&self) -> Vec<ValidatorIndex> {
        let previous_epoch = self.previous_epoch();
        self.validators()
            .iter()
            .enumerate()
            .filter(|(_, validator)| {
                validator.is_active_at(previous_epoch)
                    || (validator.slashed && previous_epoch + 1 < validator.withdrawable_epoch)
            })
            .map(|(index, _)| ValidatorIndex::from(index))
            .collect()
    }
}

/// The state of one known fork, as opposed to the state of any fork.
///
/// The fork is a constant of the type.
/// Constant tables keyed by the fork therefore fold at compile time.
pub trait ForkState: CoreState + Sized {
    /// The fork this state type belongs to.
    const FORK: ForkName;

    /// The state inside a state of any fork, when that state is of this fork.
    fn from_any(state: &combined::BeaconState<Self::Preset>) -> Option<&Self>;

    /// The state inside a state of any fork, for edits, when that state is of this fork.
    fn from_any_mut(state: &mut combined::BeaconState<Self::Preset>) -> Option<&mut Self>;

    /// The state as a state of any fork.
    fn into_any(self) -> combined::BeaconState<Self::Preset>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Minimal, phase0};

    /// A validator active from genesis until an exit epoch, with an effective balance in ETH.
    fn validator(exit_epoch: Epoch, eth: u64, slashed: bool) -> Validator {
        Validator {
            effective_balance: Gwei(eth * 1_000_000_000),
            slashed,
            exit_epoch,
            withdrawable_epoch: Epoch::FAR_FUTURE,
            ..Default::default()
        }
    }

    #[test]
    fn block_roots_are_read_only_inside_the_window() {
        // Fixture state: slot 70 of the minimal preset, whose ring buffer holds 64 roots.
        let mut state = phase0::BeaconState::<Minimal> {
            slot: Slot(70),
            ..Default::default()
        };
        state.block_roots[69 % 64] = Root([7; 32]);

        // Slot 69 is the last past slot, still in the window.
        assert_eq!(state.block_root_at_slot(Slot(69)), Some(Root([7; 32])));
        // Slot 6 is exactly 64 slots back, the oldest the window keeps.
        assert!(state.block_root_at_slot(Slot(6)).is_some());
        // Slot 5 fell out, and slot 70 has no block root yet.
        assert_eq!(state.block_root_at_slot(Slot(5)), None);
        assert_eq!(state.block_root_at_slot(Slot(70)), None);
        // Epoch 8 starts at slot 64, inside the window.
        assert_eq!(state.block_root(Epoch(8)), Some(state.block_roots[0]));
    }

    #[test]
    fn balances_and_eligibility_follow_activity() {
        // Fixture state: epoch 3; 32 ETH active, 16 ETH exiting at 3, and 8 ETH slashed, exited at 1.
        let mut state = phase0::BeaconState::<Minimal> {
            slot: Epoch(3).start_slot::<Minimal>(),
            ..Default::default()
        };
        for validator in [
            validator(Epoch::FAR_FUTURE, 32, false),
            validator(Epoch(3), 16, false),
            validator(Epoch(1), 8, true),
        ] {
            state.validators.push(validator).unwrap();
        }

        // Only the first is active at epoch 3, so the active total is 32 ETH.
        assert_eq!(
            state.active_validator_indices(Epoch(3)),
            [ValidatorIndex(0)]
        );
        assert_eq!(state.total_active_balance(), Gwei(32_000_000_000));
        // Validator 1 was still active in the previous epoch, 2; the slashed one awaits withdrawal.
        assert_eq!(
            state.eligible_validator_indices(),
            [ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)]
        );
        // A total over no validator floors at one increment, 1 ETH.
        assert_eq!(state.total_balance(&[]), Gwei(1_000_000_000));
        assert_eq!(
            state.total_balance(&[ValidatorIndex(1), ValidatorIndex(2)]),
            Gwei(24_000_000_000)
        );
    }

    #[test]
    fn the_leak_starts_after_four_epochs_without_finality() {
        // Fixture state: epoch 6, finalized at genesis, so the previous epoch is 5 past finality.
        let state = phase0::BeaconState::<Minimal> {
            slot: Epoch(6).start_slot::<Minimal>(),
            ..Default::default()
        };

        // Threshold: a delay above MIN_EPOCHS_TO_INACTIVITY_PENALTY, which is 4.
        assert_eq!(state.finality_delay(), 5);
        assert!(state.is_in_inactivity_leak());
        assert_eq!(state.fork_name(), ForkName::Phase0);
        assert_eq!(state.previous_epoch(), Epoch(5));
    }
}
