//! Balance-weighted sampling of validators, for proposers, sync committees, and PTCs.

use axiom_types::{
    Bytes32, Epoch, Gwei, Preset, Root, Slot, ValidatorIndex,
    accessors::ForkState,
    constants::{DOMAIN_BEACON_PROPOSER, DOMAIN_SYNC_COMMITTEE},
};

use crate::{StateError, SwapOrNot};

/// Validators drawn from candidates, each accepted with odds set by its balance.
///
/// # Algorithm
///
/// Walk the candidates, shuffled or in order, wrapping around.
/// Accept each one with probability effective balance over the fork's sampling ceiling.
///
/// The draws come from hashes of the seed.
/// Phase0 takes one byte per draw, Electra two, so each hash yields 32 or 16 draws.
///
/// See `compute_proposer_index` in the phase0 and Electra beacon chain specs.
/// See `compute_balance_weighted_selection` in the Gloas beacon chain spec.
///
/// The iterator never ends while a candidate has a nonzero balance.
#[derive(Debug)]
pub(crate) struct WeightedSampler<'a, S> {
    /// The state whose balances weigh the candidates.
    state: &'a S,
    /// The candidates, before shuffling.
    candidates: &'a [ValidatorIndex],
    /// The shuffle of the candidates, or nothing to walk them in order.
    shuffle: Option<SwapOrNot>,
    /// The random draws.
    draws: RandomDraws,
    /// Position of the next candidate to consider, counted across wraps.
    position: u64,
}

impl<'a, S: ForkState> WeightedSampler<'a, S> {
    /// A sampler that walks the candidates in a seeded shuffle.
    #[must_use]
    pub(crate) const fn shuffled(
        state: &'a S,
        candidates: &'a [ValidatorIndex],
        seed: Bytes32,
    ) -> Self {
        Self {
            state,
            candidates,
            shuffle: Some(SwapOrNot::new(seed, S::Preset::SHUFFLE_ROUND_COUNT)),
            draws: RandomDraws::new(seed, S::FORK.random_value_bytes()),
            position: 0,
        }
    }

    /// A sampler that walks the candidates in their given order.
    ///
    /// Gloas samples payload timeliness committees this way, from committees already shuffled.
    #[must_use]
    pub(crate) const fn in_order(
        state: &'a S,
        candidates: &'a [ValidatorIndex],
        seed: Bytes32,
    ) -> Self {
        Self {
            state,
            candidates,
            shuffle: None,
            draws: RandomDraws::new(seed, S::FORK.random_value_bytes()),
            position: 0,
        }
    }

    /// Proposer of one slot, drawn from some candidates.
    ///
    /// Each slot gets its own seed, the epoch seed hashed with the slot number.
    /// See `get_beacon_proposer_index` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when there is no candidate.
    pub(crate) fn proposer(
        state: &S,
        candidates: &[ValidatorIndex],
        epoch_seed: Bytes32,
        slot: Slot,
    ) -> Result<ValidatorIndex, StateError> {
        let mut preimage = [0; 40];
        preimage[..32].copy_from_slice(&epoch_seed.0);
        preimage[32..].copy_from_slice(&slot.0.to_le_bytes());
        let slot_seed = Bytes32(Root::sha256(&preimage).0);
        WeightedSampler::shuffled(state, candidates, slot_seed)
            .next()
            .ok_or_else(|| StateError::NoActiveValidators(slot.epoch::<S::Preset>()))
    }

    /// Proposer of the state's slot, drawn afresh from the validators active in its epoch.
    ///
    /// Fulu replaced this with a lookahead fixed one epoch ahead.
    /// See `get_beacon_proposer_index` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the epoch has no active validator.
    pub(crate) fn slot_proposer(state: &S) -> Result<ValidatorIndex, StateError> {
        let epoch = state.current_epoch();
        let candidates = state.active_validator_indices(epoch);
        let seed = state.seed(epoch, DOMAIN_BEACON_PROPOSER);
        Self::proposer(state, &candidates, seed, state.slot())
    }

    /// Proposers of every slot of an epoch, among the validators active in it.
    ///
    /// See `get_beacon_proposer_indices` in the Fulu beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the epoch has no active validator.
    pub(crate) fn proposers(state: &S, epoch: Epoch) -> Result<Vec<ValidatorIndex>, StateError> {
        let candidates = state.active_validator_indices(epoch);
        let seed = state.seed(epoch, DOMAIN_BEACON_PROPOSER);
        let start = epoch.start_slot::<S::Preset>();
        (0..S::Preset::SLOTS_PER_EPOCH)
            .map(|offset| Self::proposer(state, &candidates, seed, Slot(start.0 + offset)))
            .collect()
    }

    /// Indices of the next sync committee, possibly repeating a validator.
    ///
    /// See `get_next_sync_committee_indices` in the Altair and Electra beacon chain specs.
    ///
    /// # Errors
    ///
    /// Fails when the next epoch has no active validator.
    pub(crate) fn next_sync_committee(state: &S) -> Result<Vec<ValidatorIndex>, StateError> {
        let epoch = state.current_epoch() + 1;
        let candidates = state.active_validator_indices(epoch);
        if candidates.is_empty() {
            return Err(StateError::NoActiveValidators(epoch));
        }
        let seed = state.seed(epoch, DOMAIN_SYNC_COMMITTEE);
        Ok(WeightedSampler::shuffled(state, &candidates, seed)
            .take(S::Preset::SYNC_COMMITTEE_SIZE as usize)
            .collect())
    }

    /// Whether a candidate passes its draw.
    ///
    /// Threshold: balance * max draw >= ceiling * draw, so a full balance always passes.
    fn accepts(&self, effective_balance: Gwei, draw: u64) -> bool {
        let ceiling = S::FORK.max_sampling_balance::<S::Preset>();
        u128::from(effective_balance.0) * u128::from(self.draws.max_value())
            >= u128::from(ceiling.0) * u128::from(draw)
    }
}

impl<S: ForkState> Iterator for WeightedSampler<'_, S> {
    type Item = ValidatorIndex;

    fn next(&mut self) -> Option<ValidatorIndex> {
        let total = self.candidates.len() as u64;
        if total == 0 {
            return None;
        }
        loop {
            let i = self.position;
            self.position += 1;
            let position = match self.shuffle {
                Some(shuffle) => shuffle.shuffled_index(i % total, total),
                None => i % total,
            };
            let candidate = self.candidates[position as usize];
            let effective_balance = self.state.validators()[candidate.as_usize()].effective_balance;
            let draw = self.draws.draw(i);
            if self.accepts(effective_balance, draw) {
                return Some(candidate);
            }
        }
    }
}

/// Little-endian random draws of a fixed width from hashes of a seed.
///
/// Draw i of width w reads bytes w * (i % (32 / w)) onward of sha256(seed || i / (32 / w)).
#[derive(Debug)]
struct RandomDraws {
    /// The seed every hash starts from.
    seed: Bytes32,
    /// Bytes per draw, one or two.
    width: usize,
    /// The latest hash and the block number it came from.
    cached: Option<(u64, Root)>,
}

impl RandomDraws {
    /// Draws of a width from a seed.
    const fn new(seed: Bytes32, width: usize) -> Self {
        Self {
            seed,
            width,
            cached: None,
        }
    }

    /// The largest value a draw can take, 255 or 65535.
    const fn max_value(&self) -> u64 {
        (1 << (8 * self.width)) - 1
    }

    /// Draw number i.
    fn draw(&mut self, i: u64) -> u64 {
        let per_hash = (32 / self.width) as u64;
        let block = i / per_hash;
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
        let offset = (i % per_hash) as usize * self.width;
        hash.0[offset..offset + self.width]
            .iter()
            .rev()
            .fold(0, |value, byte| (value << 8) | u64::from(*byte))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_read_little_endian_words_of_the_fork_width() {
        // Fixture state: the zero seed, whose block 0 hash is sha256 of 40 zero bytes.
        let seed = Bytes32([0; 32]);
        let hash = Root::sha256(&[0; 40]).0;

        // One-byte draws: draw 5 is byte 5 of the block 0 hash, draw 32 starts block 1.
        let mut narrow = RandomDraws::new(seed, 1);
        assert_eq!(narrow.max_value(), 255);
        assert_eq!(narrow.draw(5), u64::from(hash[5]));
        let mut preimage = [0; 40];
        preimage[32] = 1;
        assert_eq!(narrow.draw(32), u64::from(Root::sha256(&preimage).0[0]));

        // Two-byte draws: draw 3 is bytes 6 and 7 of the block 0 hash, low byte first.
        let mut wide = RandomDraws::new(seed, 2);
        assert_eq!(wide.max_value(), 65_535);
        assert_eq!(
            wide.draw(3),
            u64::from(u16::from_le_bytes([hash[6], hash[7]]))
        );
    }
}
