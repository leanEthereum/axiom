//! The genesis state, built from the deposit contract as of one eth1 block.

use axiom_ssz::{Merkleizer, Ssz};
use axiom_types::{
    Bytes32, ChainConfig, Epoch, Gwei, Hash32, Preset,
    accessors::CoreState,
    constants::DEPOSIT_CONTRACT_TREE_DEPTH,
    phase0::{BeaconBlockBody, BeaconState, Deposit, Fork},
};

use crate::{BlockError, BlockProcessor, CachedState, Caches, PubkeyCache, Verification};

/// The eth1 block a candidate genesis state is built at.
///
/// Every eth1 block before genesis yields a candidate state from the deposits up to it.
/// The first valid candidate becomes the genesis state.
/// See the genesis section of the phase0 beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Genesis {
    /// Hash of the eth1 block, which seeds the randomness.
    pub eth1_block_hash: Hash32,
    /// Unix time of the eth1 block, in seconds.
    pub eth1_timestamp: u64,
}

impl Genesis {
    /// The candidate state from every deposit up to the eth1 block.
    ///
    /// # Algorithm
    ///
    /// 1. Start from an empty state, its time a genesis delay after the eth1 block.
    /// 2. Seed every randao mix with the eth1 block hash.
    /// 3. Apply each deposit, proven against the deposit root of the deposits so far.
    /// 4. Activate at genesis every validator holding the maximum effective balance.
    /// 5. Commit to the validator set, which identifies the chain from then on.
    ///
    /// See `initialize_beacon_state_from_eth1` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when a deposit proof is invalid or the registry overflows.
    pub fn initialize<P: Preset>(
        self,
        deposits: &[Deposit],
        config: &ChainConfig,
    ) -> Result<BeaconState<P>, BlockError> {
        let mut state = BeaconState::<P> {
            genesis_time: self.eth1_timestamp.saturating_add(config.genesis_delay),
            fork: Fork {
                previous_version: config.genesis_fork_version,
                current_version: config.genesis_fork_version,
                epoch: Epoch::GENESIS,
            },
            ..BeaconState::default()
        };
        state.eth1_data.deposit_count = deposits.len() as u64;
        state.eth1_data.block_hash = self.eth1_block_hash;
        state.latest_block_header.body_root = BeaconBlockBody::<P>::default().hash_tree_root();
        for mix in state.randao_mixes.iter_mut() {
            *mix = Bytes32(self.eth1_block_hash.0);
        }

        // Phase 1: each deposit, proven against the root of the deposit list up to it.
        // The deposits apply by the block rule, though no block exists yet.
        let mut caches = Caches::new(&state, PubkeyCache::default());
        let cached = CachedState::new(&mut state, &mut caches);
        let mut processor = BlockProcessor::new(cached, config, Verification::Verify);
        let mut tree = Merkleizer::with_limit(1 << DEPOSIT_CONTRACT_TREE_DEPTH);
        for (count, deposit) in (1..).zip(deposits) {
            tree.push(deposit.data.hash_tree_root());
            processor.state().beacon_mut().eth1_data.deposit_root =
                tree.clone().finish().mix_in_length(count);
            processor.apply(deposit)?;
        }

        // Phase 2: activations, for validators holding the maximum effective balance.
        let increment = P::EFFECTIVE_BALANCE_INCREMENT;
        for (validator, balance) in state.validators.iter_mut().zip(state.balances.iter()) {
            let rounded = Gwei(balance.0 - balance.0 % increment.0);
            validator.effective_balance = rounded.min(P::MAX_EFFECTIVE_BALANCE);
            if validator.effective_balance == P::MAX_EFFECTIVE_BALANCE {
                validator.activation_eligibility_epoch = Epoch::GENESIS;
                validator.activation_epoch = Epoch::GENESIS;
            }
        }

        state.genesis_validators_root = state.validators.hash_tree_root();
        Ok(state)
    }

    /// Whether a candidate state may start the chain: late enough, with enough validators.
    ///
    /// See `is_valid_genesis_state` in the phase0 beacon chain spec.
    #[must_use]
    pub fn is_valid<P: Preset>(state: &BeaconState<P>, config: &ChainConfig) -> bool {
        state.genesis_time >= config.min_genesis_time
            && state.active_validator_indices(Epoch::GENESIS).len() as u64
                >= config.min_genesis_active_validator_count
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, phase0::Validator};

    use super::*;

    #[test]
    fn genesis_needs_both_the_time_and_the_validators() {
        // Fixture state: the minimal config asks for 64 validators and a time of 1578009600.
        let config = ChainConfig::minimal();
        let mut state = BeaconState::<Minimal> {
            genesis_time: config.min_genesis_time,
            ..BeaconState::default()
        };
        for _ in 0..config.min_genesis_active_validator_count {
            state
                .push_validator(
                    Validator {
                        exit_epoch: Epoch::FAR_FUTURE,
                        ..Validator::default()
                    },
                    Gwei::ZERO,
                )
                .unwrap();
        }
        assert!(Genesis::is_valid(&state, &config));

        // One second early is invalid.
        state.genesis_time -= 1;
        assert!(!Genesis::is_valid(&state, &config));

        // On time, but one validator short, is invalid too.
        state.genesis_time += 1;
        state.validators[0].exit_epoch = Epoch::GENESIS;
        assert!(!Genesis::is_valid(&state, &config));
    }
}
