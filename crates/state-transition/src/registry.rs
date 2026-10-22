//! The validator registry's lifecycle rules: exits, slashings, compounding, and deposits.

use axiom_bls::{PublicKey, Signature};
use axiom_types::{
    BlsSignature, ChainConfig, DepositMessage, Domain, Epoch, Gwei, ParticipationFlags,
    PendingDeposit, Preset, Root, SigningData, Slot, Validator, ValidatorIndex,
    constants::{
        COMPOUNDING_WITHDRAWAL_PREFIX, DOMAIN_DEPOSIT, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR,
    },
};

use crate::{ActiveBalance, State, StateError, Verification, churn::ChurnQueue};

/// The point at infinity of G2, compressed: a placeholder signature.
///
/// Queued excess balance carries it, since it moves stake already proven.
const G2_POINT_AT_INFINITY: BlsSignature = {
    let mut bytes = [0; 96];
    bytes[0] = 0xc0;
    BlsSignature(bytes)
};

/// A state's validator registry, with the configuration and the balance its rules read.
///
/// # Overview
///
/// Exits, slashings, and consolidations all draw on the epoch's churn.
/// The churn depends on the total active balance, fixed for a block or an epoch transition.
/// This view carries that total, so no caller threads it through.
#[derive(Debug)]
pub(crate) struct Registry<'a, P: Preset> {
    /// The state whose registry changes.
    state: &'a mut State<P>,
    /// The chain configuration.
    config: &'a ChainConfig,
    /// Total active balance of the current epoch.
    total_active_balance: ActiveBalance,
}

impl<'a, P: Preset> Registry<'a, P> {
    /// The registry of a state, under a fixed total active balance.
    pub(crate) const fn new(
        state: &'a mut State<P>,
        config: &'a ChainConfig,
        total_active_balance: ActiveBalance,
    ) -> Self {
        Self {
            state,
            config,
            total_active_balance,
        }
    }

    /// The state whose registry this is.
    pub(crate) const fn state(&mut self) -> &mut State<P> {
        &mut *self.state
    }

    /// Schedules an exit for the earliest epoch the exit churn allows.
    ///
    /// A validator already exiting keeps its schedule.
    /// See `initiate_validator_exit` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist.
    pub(crate) fn initiate_exit(&mut self, index: ValidatorIndex) -> Result<(), StateError> {
        let validator = self
            .state
            .beacon
            .validators
            .get(index.as_usize())
            .ok_or(StateError::UnknownValidator(index))?;
        if validator.exit_epoch != Epoch::FAR_FUTURE {
            return Ok(());
        }

        let effective_balance = validator.effective_balance;
        let exit_epoch = self.exit_epoch(effective_balance);
        let withdrawable_epoch = self.withdrawable_epoch(exit_epoch)?;
        let validator = &mut self.state.beacon.validators[index.as_usize()];
        validator.exit_epoch = exit_epoch;
        validator.withdrawable_epoch = withdrawable_epoch;
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
    pub(crate) fn slash(
        &mut self,
        slashed: ValidatorIndex,
        whistleblower: Option<ValidatorIndex>,
    ) -> Result<(), StateError> {
        let epoch = self.state.beacon.current_epoch();
        self.initiate_exit(slashed)?;

        let beacon = &mut self.state.beacon;
        let validator = &mut beacon.validators[slashed.as_usize()];
        validator.slashed = true;
        validator.withdrawable_epoch = validator
            .withdrawable_epoch
            .max(epoch.saturating_add(P::EPOCHS_PER_SLASHINGS_VECTOR));
        let effective_balance = validator.effective_balance;

        let slot = (epoch % P::EPOCHS_PER_SLASHINGS_VECTOR) as usize;
        beacon.slashings[slot] = beacon.slashings[slot]
            .checked_add(effective_balance)
            .ok_or(StateError::Overflow)?;
        self.state.decrease_balance(
            slashed,
            effective_balance / P::MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
        )?;

        let proposer = self.state.beacon.beacon_proposer_index();
        let whistleblower = whistleblower.unwrap_or(proposer);
        let whistleblower_reward = effective_balance / P::WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA;
        let proposer_reward = whistleblower_reward * PROPOSER_WEIGHT / WEIGHT_DENOMINATOR;
        self.state.increase_balance(proposer, proposer_reward)?;
        self.state
            .increase_balance(whistleblower, whistleblower_reward - proposer_reward)
    }

    /// Earliest epoch an exit of some balance fits in, consuming that churn.
    ///
    /// See `compute_exit_epoch_and_update_churn` in the Electra beacon chain spec.
    pub(crate) fn exit_epoch(&mut self, balance: Gwei) -> Epoch {
        let per_epoch_churn = self
            .total_active_balance
            .activation_exit_churn_limit::<P>(self.config);
        let beacon = &mut self.state.beacon;
        let earliest = beacon.current_epoch().activation_exit_epoch::<P>();
        ChurnQueue::new(
            &mut beacon.earliest_exit_epoch,
            &mut beacon.exit_balance_to_consume,
        )
        .schedule(balance, per_epoch_churn, earliest)
    }

    /// Earliest epoch a consolidation of some balance fits in, consuming that churn.
    ///
    /// The same queue as exits, with the consolidation share of the churn.
    /// See `compute_consolidation_epoch_and_update_churn` in the Electra beacon chain spec.
    pub(crate) fn consolidation_epoch(&mut self, balance: Gwei) -> Epoch {
        let per_epoch_churn = self
            .total_active_balance
            .consolidation_churn_limit::<P>(self.config);
        let beacon = &mut self.state.beacon;
        let earliest = beacon.current_epoch().activation_exit_epoch::<P>();
        ChurnQueue::new(
            &mut beacon.earliest_consolidation_epoch,
            &mut beacon.consolidation_balance_to_consume,
        )
        .schedule(balance, per_epoch_churn, earliest)
    }

    /// Epoch a validator exiting at an epoch can withdraw from.
    ///
    /// # Errors
    ///
    /// Fails when the epoch overflows.
    pub(crate) fn withdrawable_epoch(&self, exit_epoch: Epoch) -> Result<Epoch, StateError> {
        exit_epoch
            .checked_add(self.config.min_validator_withdrawability_delay)
            .ok_or(StateError::Overflow)
    }

    /// Switches a validator to compounding credentials, and queues its excess balance.
    ///
    /// See `switch_to_compounding_validator` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the pending deposit queue is full.
    pub(crate) fn switch_to_compounding(
        &mut self,
        index: ValidatorIndex,
    ) -> Result<(), StateError> {
        let validator = &mut self.state.beacon.validators[index.as_usize()];
        validator.withdrawal_credentials.0[0] = COMPOUNDING_WITHDRAWAL_PREFIX;
        self.queue_excess_active_balance(index)
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
    pub(crate) fn apply_pending_deposit(
        &mut self,
        deposit: &PendingDeposit,
    ) -> Result<(), StateError> {
        match self.state.validator_index(&deposit.pubkey) {
            Some(index) => self.state.increase_balance(index, deposit.amount),
            None => {
                let skip = self.state.verification == Verification::Skip;
                if skip || self.has_valid_signature(deposit) {
                    self.add_validator(deposit)?;
                }
                Ok(())
            }
        }
    }

    /// Moves the balance above the activation balance back through the deposit queue.
    ///
    /// The excess then re-enters under the churn, like any new stake.
    fn queue_excess_active_balance(&mut self, index: ValidatorIndex) -> Result<(), StateError> {
        let beacon = &mut self.state.beacon;
        let balance = beacon.balances[index.as_usize()];
        if balance > P::MIN_ACTIVATION_BALANCE {
            let excess = balance - P::MIN_ACTIVATION_BALANCE;
            beacon.balances[index.as_usize()] = P::MIN_ACTIVATION_BALANCE;
            let validator = &beacon.validators[index.as_usize()];
            let deposit = PendingDeposit {
                pubkey: validator.pubkey,
                withdrawal_credentials: validator.withdrawal_credentials,
                amount: excess,
                signature: G2_POINT_AT_INFINITY,
                // The genesis slot marks a deposit that needs no finality wait.
                slot: Slot::GENESIS,
            };
            beacon
                .pending_deposits
                .push(deposit)
                .map_err(|_| StateError::ListFull)?;
        }
        Ok(())
    }

    /// Whether a deposit's signature proves possession of its key.
    ///
    /// The domain ignores forks, so a deposit stays valid across every fork.
    /// See `is_valid_deposit_signature` in the Electra beacon chain spec.
    fn has_valid_signature(&self, deposit: &PendingDeposit) -> bool {
        let message = DepositMessage {
            pubkey: deposit.pubkey,
            withdrawal_credentials: deposit.withdrawal_credentials,
            amount: deposit.amount,
        };
        // Fork-agnostic: the genesis fork version and the zero chain root.
        let domain = Domain::compute(DOMAIN_DEPOSIT, self.config.genesis_fork_version, Root::ZERO);
        let signing_root = SigningData::signing_root(&message, domain);
        let (Ok(key), Ok(signature)) = (
            PublicKey::from_bytes(&deposit.pubkey.0),
            Signature::from_bytes(&deposit.signature.0),
        ) else {
            return false;
        };
        signature.verify(&key, &signing_root.0)
    }

    /// Appends a new validator and its per-validator entries.
    ///
    /// See `add_validator_to_registry` in the Electra beacon chain spec.
    fn add_validator(&mut self, deposit: &PendingDeposit) -> Result<(), StateError> {
        let beacon = &mut self.state.beacon;
        let validator = Validator::from_deposit::<P>(
            deposit.pubkey,
            deposit.withdrawal_credentials,
            deposit.amount,
        );
        beacon
            .validators
            .push(validator)
            .map_err(|_| StateError::ListFull)?;
        beacon
            .balances
            .push(deposit.amount)
            .map_err(|_| StateError::ListFull)?;
        beacon
            .previous_epoch_participation
            .push(ParticipationFlags::default())
            .map_err(|_| StateError::ListFull)?;
        beacon
            .current_epoch_participation
            .push(ParticipationFlags::default())
            .map_err(|_| StateError::ListFull)?;
        beacon
            .inactivity_scores
            .push(0)
            .map_err(|_| StateError::ListFull)?;
        self.state.pubkeys.sync(&self.state.beacon.validators);
        Ok(())
    }
}
