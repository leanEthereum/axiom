//! Balance-weighted sampling of validators, for proposers and sync committees.

use axiom_types::{
    BeaconState, Bytes32, Epoch, Gwei, Preset, Root, ValidatorIndex,
    constants::{DOMAIN_BEACON_PROPOSER, DOMAIN_SYNC_COMMITTEE},
};

use crate::{StateError, SwapOrNot};

/// Largest value of the 16-bit random draws.
///
/// See `compute_proposer_index` in the Electra beacon chain spec.
const MAX_RANDOM_VALUE: u64 = (1 << 16) - 1;

/// Validators drawn from shuffled candidates, each accepted with odds set by its balance.
///
/// # Algorithm
///
/// Walk the shuffled candidates in order, wrapping around.
/// Accept each one with probability effective balance over the maximum balance.
///
/// The draws come 16 bits at a time from hashes of the seed, sixteen draws per hash.
/// See `compute_proposer_index` and `get_next_sync_committee_indices` in the Electra spec.
///
/// The iterator never ends while a candidate has a nonzero balance.
#[derive(Debug)]
pub(crate) struct WeightedSampler<'a, P: Preset> {
    /// The state whose balances weigh the candidates.
    state: &'a BeaconState<P>,
    /// The candidates, before shuffling.
    candidates: &'a [ValidatorIndex],
    /// The shuffle of the candidates.
    shuffle: SwapOrNot,
    /// The random draws.
    draws: RandomDraws,
    /// Position of the next candidate to consider, counted across wraps.
    position: u64,
}

impl<'a, P: Preset> WeightedSampler<'a, P> {
    /// A sampler over candidates, seeded.
    #[must_use]
    pub(crate) const fn new(
        state: &'a BeaconState<P>,
        candidates: &'a [ValidatorIndex],
        seed: Bytes32,
    ) -> Self {
        Self {
            state,
            candidates,
            shuffle: SwapOrNot::new(seed, P::SHUFFLE_ROUND_COUNT),
            draws: RandomDraws::new(seed),
            position: 0,
        }
    }

    /// Proposers of every slot of an epoch.
    ///
    /// Each slot gets its own seed, the epoch seed hashed with the slot number.
    /// See `get_beacon_proposer_indices` in the Fulu beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the epoch has no active validator.
    pub(crate) fn proposers(
        state: &BeaconState<P>,
        epoch: Epoch,
    ) -> Result<Vec<ValidatorIndex>, StateError> {
        let candidates = state.active_validator_indices(epoch);
        let seed = state.seed(epoch, DOMAIN_BEACON_PROPOSER);
        let start = epoch.start_slot::<P>();
        (0..P::SLOTS_PER_EPOCH)
            .map(|offset| {
                let mut preimage = [0; 40];
                preimage[..32].copy_from_slice(&seed.0);
                preimage[32..].copy_from_slice(&(start.0 + offset).to_le_bytes());
                let slot_seed = Bytes32(Root::sha256(&preimage).0);
                WeightedSampler::new(state, &candidates, slot_seed)
                    .next()
                    .ok_or(StateError::NoActiveValidators(epoch))
            })
            .collect()
    }

    /// Indices of the next sync committee, possibly repeating a validator.
    ///
    /// See `get_next_sync_committee_indices` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the next epoch has no active validator.
    pub(crate) fn next_sync_committee(
        state: &BeaconState<P>,
    ) -> Result<Vec<ValidatorIndex>, StateError> {
        let epoch = state.current_epoch() + 1;
        let candidates = state.active_validator_indices(epoch);
        if candidates.is_empty() {
            return Err(StateError::NoActiveValidators(epoch));
        }
        let seed = state.seed(epoch, DOMAIN_SYNC_COMMITTEE);
        Ok(WeightedSampler::new(state, &candidates, seed)
            .take(P::SYNC_COMMITTEE_SIZE as usize)
            .collect())
    }

    /// Whether a candidate passes its draw.
    ///
    /// Threshold: balance * 65535 >= max balance * draw, so a full balance always passes.
    const fn accepts(effective_balance: Gwei, draw: u64) -> bool {
        effective_balance.0 as u128 * MAX_RANDOM_VALUE as u128
            >= P::MAX_EFFECTIVE_BALANCE_ELECTRA.0 as u128 * draw as u128
    }
}

impl<P: Preset> Iterator for WeightedSampler<'_, P> {
    type Item = ValidatorIndex;

    fn next(&mut self) -> Option<ValidatorIndex> {
        let total = self.candidates.len() as u64;
        if total == 0 {
            return None;
        }
        loop {
            let i = self.position;
            self.position += 1;
            let candidate = self.candidates[self.shuffle.shuffled_index(i % total, total) as usize];
            let effective_balance = self.state.validators[candidate.as_usize()].effective_balance;
            if Self::accepts(effective_balance, self.draws.draw(i)) {
                return Some(candidate);
            }
        }
    }
}

/// Sixteen-bit random draws from hashes of a seed, sixteen draws per hash.
#[derive(Debug)]
struct RandomDraws {
    /// The seed every hash starts from.
    seed: Bytes32,
    /// The latest hash and the block number it came from.
    cached: Option<(u64, Root)>,
}

impl RandomDraws {
    /// Draws from a seed.
    const fn new(seed: Bytes32) -> Self {
        Self { seed, cached: None }
    }

    /// Draw number i: bytes 2 * (i % 16) and the next one of sha256(seed || i / 16).
    fn draw(&mut self, i: u64) -> u64 {
        let block = i / 16;
        let hash = match self.cached {
            Some((cached_block, hash)) if cached_block == block => hash,
            _ => {
                let mut preimage = [0; 40];
                preimage[..32].copy_from_slice(&self.seed.0);
                preimage[32..].copy_from_slice(&block.to_le_bytes());
                let hash = Root::sha256(&preimage);
                self.cached = Some((block, hash));
                hash
            }
        };
        let offset = (i % 16 * 2) as usize;
        u64::from(u16::from_le_bytes([hash.0[offset], hash.0[offset + 1]]))
    }
}
