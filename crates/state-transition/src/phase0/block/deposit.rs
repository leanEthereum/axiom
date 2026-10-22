//! Deposits from the deposit contract, proven against the eth1 data's deposit root.

use axiom_bls::{PublicKey, Signature};
use axiom_types::{
    ChainConfig, Domain, Preset, Root,
    accessors::CoreState,
    constants::DOMAIN_DEPOSIT,
    phase0::{self, Deposit, DepositMessage, SigningData, Validator},
};

use crate::{
    BlockError, BlockProcessor, Fork, Operation, StateError, Verification,
    phase0::block::DepositInclusion,
};

/// The deposits a block must carry: every unprocessed one, up to the per-block maximum.
///
/// A proposer cannot censor deposits, since the count is fixed by the agreed eth1 data.
/// Electra replaced this rule while the contract queue drains.
/// See `process_operations` in the phase0 beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositQuota {
    /// Deposits the block must carry.
    expected: u64,
}

impl DepositQuota {
    /// The quota of the block at a state.
    #[must_use]
    pub fn of<S: CoreState + ?Sized>(state: &S) -> Self {
        let unprocessed = state
            .eth1_data()
            .deposit_count
            .saturating_sub(state.eth1_deposit_index());
        Self {
            expected: unprocessed.min(S::Preset::MAX_DEPOSITS),
        }
    }

    /// Checks that a block carries exactly the quota.
    ///
    /// # Errors
    ///
    /// Fails when the block carries more or fewer deposits.
    pub const fn check(self, carried: usize) -> Result<(), BlockError> {
        if carried as u64 == self.expected {
            Ok(())
        } else {
            Err(BlockError::DepositCountMismatch {
                expected: self.expected,
                actual: carried,
            })
        }
    }
}

/// A deposit from the deposit contract, in the order the contract received it.
///
/// Phase0 introduced the rule, and every fork through Deneb kept its proof and top-up logic.
/// Forks differ only in how they register a new validator.
/// See `process_deposit` and `apply_deposit` in the phase0 beacon chain spec.
#[derive(Clone, Copy, Debug)]
pub struct ContractDeposit<'a>(pub &'a Deposit);

impl ContractDeposit<'_> {
    /// Checks the proof, consumes the deposit, and tops up a known key.
    ///
    /// # Algorithm
    ///
    /// 1. The proof places the deposit at the next index under the agreed deposit root.
    /// 2. The next index moves on, whatever happens to the deposit.
    /// 3. A known key gets the amount added to its balance.
    /// 4. A new key with a valid proof of possession yields a validator to register.
    /// 5. A new key without one is dropped, and its amount is lost.
    ///
    /// # Returns
    ///
    /// The validator to register with the deposit's amount as its balance, or nothing.
    ///
    /// # Errors
    ///
    /// Fails when the proof is invalid or a balance overflows.
    pub fn admit<S: Fork>(
        self,
        processor: &mut BlockProcessor<'_, S>,
    ) -> Result<Option<Validator>, BlockError> {
        DepositInclusion(self.0).consume(&mut *processor.state.beacon)?;

        let data = &self.0.data;
        if let Some(known) = processor.state.validator_index(&data.pubkey) {
            processor.state.increase_balance(known, data.amount)?;
            return Ok(None);
        }
        let skip = processor.state.verification() == Verification::Skip;
        if !skip && !self.proves_possession(processor.config) {
            return Ok(None);
        }
        let mut validator = Validator::from_deposit::<S::Preset>(
            data.pubkey,
            data.withdrawal_credentials,
            data.amount,
        );
        // Before Electra every validator shares one cap, whatever its credentials say.
        validator.effective_balance = validator
            .effective_balance
            .min(S::Preset::MAX_EFFECTIVE_BALANCE);
        Ok(Some(validator))
    }

    /// Whether the deposit's signature proves possession of its key.
    ///
    /// Without it, one key holder could register a key derived from another's, a rogue key attack.
    /// The domain ignores forks and the chain, so a deposit stays valid across every fork.
    fn proves_possession(self, config: &ChainConfig) -> bool {
        let data = &self.0.data;
        let message = DepositMessage {
            pubkey: data.pubkey,
            withdrawal_credentials: data.withdrawal_credentials,
            amount: data.amount,
        };
        let domain = Domain::compute(DOMAIN_DEPOSIT, config.genesis_fork_version, Root::ZERO);
        let signing_root = SigningData::signing_root(&message, domain);
        let (Ok(key), Ok(signature)) = (
            PublicKey::from_bytes(&data.pubkey.0),
            Signature::from_bytes(&data.signature.0),
        ) else {
            return false;
        };
        signature.verify(&key, &signing_root.0)
    }
}

impl<P: Preset> Operation<phase0::BeaconState<P>> for Deposit {
    /// Applies a deposit, registering a new validator with its balance and nothing else.
    ///
    /// See `add_validator_to_registry` in the phase0 beacon chain spec.
    fn apply(
        &self,
        processor: &mut BlockProcessor<'_, phase0::BeaconState<P>>,
    ) -> Result<(), BlockError> {
        let Some(validator) = ContractDeposit(self).admit(processor)? else {
            return Ok(());
        };
        processor
            .state
            .beacon
            .push_validator(validator, self.data.amount)
            .map_err(|source| StateError::Capacity {
                list: "validators",
                source,
            })?;
        Ok(())
    }
}
