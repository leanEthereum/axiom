//! Spec mutators: the only ways processing changes balances and validator lifecycles.

use axiom_bls::{PublicKey, Signature};
use axiom_types::{
    BlsPubkey, BlsSignature, Bytes32, ChainConfig, DepositMessage, Domain, Epoch, Gwei,
    ParticipationFlags, PendingDeposit, Preset, Root, SigningData, Slot, Validator, ValidatorIndex,
    constants::{
        COMPOUNDING_WITHDRAWAL_PREFIX, DOMAIN_DEPOSIT, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR,
    },
};

use super::State;
use crate::{StateError, Verification};

/// The point at infinity of G2, compressed: a placeholder signature.
///
/// Queued excess balance carries it, since it moves stake already proven.
const G2_POINT_AT_INFINITY: BlsSignature = {
    let mut bytes = [0; 96];
    bytes[0] = 0xc0;
    BlsSignature(bytes)
};

impl<P: Preset> State<P> {
    /// Adds to a validator's balance.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist or the balance overflows.
    pub fn increase_balance(
        &mut self,
        index: ValidatorIndex,
        delta: Gwei,
    ) -> Result<(), StateError> {
        let balance = self
            .beacon
            .balances
            .get_mut(index.as_usize())
            .ok_or(StateError::UnknownValidator(index))?;
        *balance = balance.checked_add(delta).ok_or(StateError::Overflow)?;
        Ok(())
    }

    /// Takes from a validator's balance, stopping at zero.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist.
    pub fn decrease_balance(
        &mut self,
        index: ValidatorIndex,
        delta: Gwei,
    ) -> Result<(), StateError> {
        let balance = self
            .beacon
            .balances
            .get_mut(index.as_usize())
            .ok_or(StateError::UnknownValidator(index))?;
        *balance = balance.saturating_sub(delta);
        Ok(())
    }

    /// Schedules an exit for the earliest epoch the exit churn allows.
    ///
    /// A validator already exiting keeps its schedule.
    /// See `initiate_validator_exit` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist.
    pub fn initiate_validator_exit(
        &mut self,
        config: &ChainConfig,
        index: ValidatorIndex,
        total_active_balance: Gwei,
    ) -> Result<(), StateError> {
        let validator = self
            .beacon
            .validators
            .get(index.as_usize())
            .ok_or(StateError::UnknownValidator(index))?;
        if validator.exit_epoch != Epoch::FAR_FUTURE {
            return Ok(());
        }

        let exit_epoch = self.compute_exit_epoch_and_update_churn(
            config,
            validator.effective_balance,
            total_active_balance,
        );
        let validator = &mut self.beacon.validators[index.as_usize()];
        validator.exit_epoch = exit_epoch;
        validator.withdrawable_epoch = exit_epoch
            .checked_add(config.min_validator_withdrawability_delay)
            .ok_or(StateError::Overflow)?;
        Ok(())
    }

    /// Slashes a validator, and pays the proposer and the whistleblower.
    ///
    /// # Algorithm
    ///
    /// - The validator exits, and stays unwithdrawable for half the slashings vector.
    /// - Its effective balance joins the epoch's slashed total for the correlation penalty.
    /// - It loses an initial penalty of 1/4096 of its effective balance.
    /// - The whistleblower earns 1/4096 of it, of which the proposer takes 8/64.
    ///
    /// See `slash_validator` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when a validator does not exist or a balance overflows.
    pub fn slash_validator(
        &mut self,
        config: &ChainConfig,
        slashed: ValidatorIndex,
        whistleblower: Option<ValidatorIndex>,
        total_active_balance: Gwei,
    ) -> Result<(), StateError> {
        let epoch = self.beacon.current_epoch();
        self.initiate_validator_exit(config, slashed, total_active_balance)?;

        let validator = &mut self.beacon.validators[slashed.as_usize()];
        validator.slashed = true;
        validator.withdrawable_epoch = validator
            .withdrawable_epoch
            .max(epoch.saturating_add(P::EPOCHS_PER_SLASHINGS_VECTOR));
        let effective_balance = validator.effective_balance;

        let slot = (epoch % P::EPOCHS_PER_SLASHINGS_VECTOR) as usize;
        self.beacon.slashings[slot] = self.beacon.slashings[slot]
            .checked_add(effective_balance)
            .ok_or(StateError::Overflow)?;
        self.decrease_balance(
            slashed,
            effective_balance / P::MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
        )?;

        let proposer = self.beacon.beacon_proposer_index();
        let whistleblower = whistleblower.unwrap_or(proposer);
        let whistleblower_reward = effective_balance / P::WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA;
        let proposer_reward = whistleblower_reward * PROPOSER_WEIGHT / WEIGHT_DENOMINATOR;
        self.increase_balance(proposer, proposer_reward)?;
        self.increase_balance(whistleblower, whistleblower_reward - proposer_reward)
    }

    /// Earliest epoch an exit of some balance fits in, consuming that churn.
    ///
    /// # Algorithm
    ///
    /// Exits queue behind each other, each epoch admitting one epoch's churn of balance.
    ///
    /// ```text
    /// churn = 128 ETH per epoch, 40 ETH left in epoch 10, exit of 200 ETH
    ///
    /// 200 - 40 = 160 more ETH, needing ceil(160 / 128) = 2 more epochs
    /// the exit lands in epoch 12, leaving 40 + 256 - 200 = 96 ETH there
    /// ```
    ///
    /// See `compute_exit_epoch_and_update_churn` in the Electra beacon chain spec.
    pub fn compute_exit_epoch_and_update_churn(
        &mut self,
        config: &ChainConfig,
        exit_balance: Gwei,
        total_active_balance: Gwei,
    ) -> Epoch {
        let state = &mut self.beacon;
        let mut earliest = state
            .earliest_exit_epoch
            .max(Self::activation_exit_epoch(state.current_epoch()));
        let per_epoch_churn = Self::activation_exit_churn_limit(config, total_active_balance);

        // A later epoch than the queue's tail starts with a full churn budget.
        let mut to_consume = if state.earliest_exit_epoch < earliest {
            per_epoch_churn
        } else {
            state.exit_balance_to_consume
        };

        if exit_balance > to_consume {
            let remaining = exit_balance - to_consume;
            let additional_epochs = (remaining.0 - 1) / per_epoch_churn.0 + 1;
            earliest += additional_epochs;
            to_consume += per_epoch_churn * additional_epochs;
        }

        state.exit_balance_to_consume = to_consume - exit_balance;
        state.earliest_exit_epoch = earliest;
        earliest
    }

    /// Earliest epoch a consolidation of some balance fits in, consuming that churn.
    ///
    /// The same queue as exits, with the consolidation share of the churn.
    /// See `compute_consolidation_epoch_and_update_churn` in the Electra beacon chain spec.
    pub fn compute_consolidation_epoch_and_update_churn(
        &mut self,
        config: &ChainConfig,
        consolidation_balance: Gwei,
        total_active_balance: Gwei,
    ) -> Epoch {
        let state = &mut self.beacon;
        let mut earliest = state
            .earliest_consolidation_epoch
            .max(Self::activation_exit_epoch(state.current_epoch()));
        let per_epoch_churn = Self::consolidation_churn_limit(config, total_active_balance);

        let mut to_consume = if state.earliest_consolidation_epoch < earliest {
            per_epoch_churn
        } else {
            state.consolidation_balance_to_consume
        };

        if consolidation_balance > to_consume {
            let remaining = consolidation_balance - to_consume;
            let additional_epochs = (remaining.0 - 1) / per_epoch_churn.0 + 1;
            earliest += additional_epochs;
            to_consume += per_epoch_churn * additional_epochs;
        }

        state.consolidation_balance_to_consume = to_consume - consolidation_balance;
        state.earliest_consolidation_epoch = earliest;
        earliest
    }

    /// Epoch an activation or exit decided in an epoch takes effect.
    ///
    /// The delay keeps the change outside every committee already derivable from randao.
    #[must_use]
    pub const fn activation_exit_epoch(epoch: Epoch) -> Epoch {
        Epoch(epoch.0 + 1 + P::MAX_SEED_LOOKAHEAD)
    }

    /// Switches a validator to compounding credentials, and queues its excess balance.
    ///
    /// See `switch_to_compounding_validator` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the pending deposit queue is full.
    pub fn switch_to_compounding_validator(
        &mut self,
        index: ValidatorIndex,
    ) -> Result<(), StateError> {
        let validator = &mut self.beacon.validators[index.as_usize()];
        validator.withdrawal_credentials.0[0] = COMPOUNDING_WITHDRAWAL_PREFIX;
        self.queue_excess_active_balance(index)
    }

    /// Moves the balance above the activation balance back through the deposit queue.
    ///
    /// The excess then re-enters under the churn, like any new stake.
    ///
    /// # Errors
    ///
    /// Fails when the pending deposit queue is full.
    pub fn queue_excess_active_balance(&mut self, index: ValidatorIndex) -> Result<(), StateError> {
        let balance = self.beacon.balances[index.as_usize()];
        if balance > P::MIN_ACTIVATION_BALANCE {
            let excess = balance - P::MIN_ACTIVATION_BALANCE;
            self.beacon.balances[index.as_usize()] = P::MIN_ACTIVATION_BALANCE;
            let validator = &self.beacon.validators[index.as_usize()];
            let deposit = PendingDeposit {
                pubkey: validator.pubkey,
                withdrawal_credentials: validator.withdrawal_credentials,
                amount: excess,
                signature: G2_POINT_AT_INFINITY,
                // The genesis slot marks a deposit that needs no finality wait.
                slot: Slot::GENESIS,
            };
            self.beacon
                .pending_deposits
                .push(deposit)
                .map_err(|_| StateError::ListFull)?;
        }
        Ok(())
    }

    /// Applies a deposit that cleared the queue: tops up a validator, or creates one.
    ///
    /// A deposit for a new key must carry a proof of possession.
    /// Otherwise one key holder could register a key derived from another's, a rogue key attack.
    ///
    /// See `apply_pending_deposit` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when a list is full or a balance overflows.
    pub fn apply_pending_deposit(
        &mut self,
        config: &ChainConfig,
        deposit: &PendingDeposit,
    ) -> Result<(), StateError> {
        match self.validator_index(&deposit.pubkey) {
            Some(index) => self.increase_balance(index, deposit.amount),
            None => {
                let skip = self.verification == Verification::Skip;
                if skip
                    || Self::is_valid_deposit_signature(
                        config,
                        &deposit.pubkey,
                        deposit.withdrawal_credentials,
                        deposit.amount,
                        &deposit.signature,
                    )
                {
                    self.add_validator_to_registry(
                        deposit.pubkey,
                        deposit.withdrawal_credentials,
                        deposit.amount,
                    )?;
                }
                Ok(())
            }
        }
    }

    /// Whether a deposit's signature proves possession of its key.
    ///
    /// The domain ignores forks, so a deposit stays valid across every fork.
    #[must_use]
    pub fn is_valid_deposit_signature(
        config: &ChainConfig,
        pubkey: &BlsPubkey,
        withdrawal_credentials: Bytes32,
        amount: Gwei,
        signature: &BlsSignature,
    ) -> bool {
        let message = DepositMessage {
            pubkey: *pubkey,
            withdrawal_credentials,
            amount,
        };
        // Fork-agnostic: the genesis fork version and the zero chain root.
        let domain = Domain::compute(DOMAIN_DEPOSIT, config.genesis_fork_version, Root::ZERO);
        let signing_root = SigningData::signing_root(&message, domain);
        let (Ok(key), Ok(signature)) = (
            PublicKey::from_bytes(&pubkey.0),
            Signature::from_bytes(&signature.0),
        ) else {
            return false;
        };
        signature.verify(&key, &signing_root.0)
    }

    /// Appends a new validator and its per-validator entries.
    ///
    /// See `add_validator_to_registry` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the registry is full.
    pub fn add_validator_to_registry(
        &mut self,
        pubkey: BlsPubkey,
        withdrawal_credentials: Bytes32,
        amount: Gwei,
    ) -> Result<(), StateError> {
        let state = &mut self.beacon;
        let validator = Validator::from_deposit::<P>(pubkey, withdrawal_credentials, amount);
        state
            .validators
            .push(validator)
            .map_err(|_| StateError::ListFull)?;
        state
            .balances
            .push(amount)
            .map_err(|_| StateError::ListFull)?;
        state
            .previous_epoch_participation
            .push(ParticipationFlags::default())
            .map_err(|_| StateError::ListFull)?;
        state
            .current_epoch_participation
            .push(ParticipationFlags::default())
            .map_err(|_| StateError::ListFull)?;
        state
            .inactivity_scores
            .push(0)
            .map_err(|_| StateError::ListFull)?;
        self.pubkeys.sync(&self.beacon.validators);
        Ok(())
    }
}
