//! Balance-weighted sampling of validators, for proposers, sync committees, and PTCs.

use axiom_types::{
    Bytes32, Epoch, Gwei, Preset, Root, Slot, ValidatorIndex,
    accessors::ForkState,
    constants::{DOMAIN_BEACON_PROPOSER, DOMAIN_SYNC_COMMITTEE},
};

use crate::{StateError, SwapOrNot, shuffle::IndexShuffle};

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
    /// The order of the walk, and where it reads balances.
    walk: Walk,
    /// The random draws.
    draws: RandomDraws,
    /// Position of the next candidate to consider, counted across wraps.
    position: u64,
}

/// How a sampler walks its candidates, and where it reads their balances.
#[derive(Debug)]
enum Walk {
    /// A seeded shuffle, reading each visited balance from the registry.
    ///
    /// Proposer draws visit a few dozen of up to a million candidates, so nothing is gathered.
    Shuffled(IndexShuffle),
    /// The given order, with the candidates' balances gathered once, in that order.
    ///
    /// A payload committee walks one slot's committees, wrapping them whenever they are small.
    InOrder {
        /// Effective balance of each candidate.
        balances: Vec<Gwei>,
        /// The next candidate's place in the list, wrapping to zero at its end.
        next: usize,
    },
}

impl<'a, S: ForkState> WeightedSampler<'a, S> {
    /// A sampler that walks the candidates in a seeded shuffle.
    #[must_use]
    pub(crate) fn shuffled(state: &'a S, candidates: &'a [ValidatorIndex], seed: Bytes32) -> Self {
        let shuffle = SwapOrNot::new(seed, S::Preset::SHUFFLE_ROUND_COUNT);
        Self {
            state,
            candidates,
            // An empty candidate list draws nothing, so its shuffle is never asked for an image.
            walk: Walk::Shuffled(IndexShuffle::new(shuffle, candidates.len().max(1) as u64)),
            draws: RandomDraws::new(seed, S::FORK.random_value_bytes()),
            position: 0,
        }
    }

    /// A sampler that walks the candidates in their given order.
    ///
    /// Gloas samples payload timeliness committees this way, from committees already shuffled.
    #[must_use]
    pub(crate) fn in_order(state: &'a S, candidates: &'a [ValidatorIndex], seed: Bytes32) -> Self {
        let validators = state.validators();
        let balances = candidates
            .iter()
            .map(|candidate| validators[candidate.as_usize()].effective_balance)
            .collect();
        Self {
            state,
            candidates,
            walk: Walk::InOrder { balances, next: 0 },
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
        Self::proposers_among(state, epoch, &state.active_validator_indices(epoch))
    }

    /// Proposers of every slot of an epoch, among some candidates.
    ///
    /// Gloas draws only among the unslashed active validators, see EIP-8045.
    /// See `compute_proposer_indices` in the Fulu and Gloas beacon chain specs.
    ///
    /// # Errors
    ///
    /// Fails when there is no candidate.
    pub(crate) fn proposers_among(
        state: &S,
        epoch: Epoch,
        candidates: &[ValidatorIndex],
    ) -> Result<Vec<ValidatorIndex>, StateError> {
        let seed = state.seed(epoch, DOMAIN_BEACON_PROPOSER);
        let start = epoch.start_slot::<S::Preset>();
        (0..S::Preset::SLOTS_PER_EPOCH)
            .map(|offset| Self::proposer(state, candidates, seed, Slot(start.0 + offset)))
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
            let (candidate, effective_balance) = match &mut self.walk {
                Walk::Shuffled(shuffle) => {
                    let candidate = self.candidates[shuffle.image(i % total) as usize];
                    let validator = &self.state.validators()[candidate.as_usize()];
                    (candidate, validator.effective_balance)
                }
                Walk::InOrder { balances, next } => {
                    let position = *next;
                    *next = if position + 1 == balances.len() {
                        0
                    } else {
                        position + 1
                    };
                    (self.candidates[position], balances[position])
                }
            };
            // Invariant: draw i pairs with position i, as both advance once per candidate.
            let draw = self.draws.next_draw();
            if self.accepts(effective_balance, draw) {
                return Some(candidate);
            }
        }
    }
}

/// Little-endian random draws of a fixed width from hashes of a seed, in order.
///
/// Draw i of width w reads bytes w * (i % (32 / w)) onward of sha256(seed || i / (32 / w)).
/// The sampler consumes draws strictly in order, so the stream keeps its place in the hash.
#[derive(Debug)]
struct RandomDraws {
    /// The seed every hash starts from.
    seed: Bytes32,
    /// Bytes per draw, one or two, so a hash holds a whole number of draws.
    width: usize,
    /// Number of the next hash to compute.
    next_block: u64,
    /// The current hash.
    hash: Root,
    /// Offset of the next draw's first byte in the current hash, 32 once it is used up.
    offset: usize,
}

impl RandomDraws {
    /// Draws of a width from a seed.
    const fn new(seed: Bytes32, width: usize) -> Self {
        Self {
            seed,
            width,
            next_block: 0,
            hash: Root::ZERO,
            offset: 32,
        }
    }

    /// The largest value a draw can take, 255 or 65535.
    const fn max_value(&self) -> u64 {
        (1 << (8 * self.width)) - 1
    }

    /// The next draw.
    fn next_draw(&mut self) -> u64 {
        if self.offset == 32 {
            let mut preimage = [0; 40];
            preimage[..32].copy_from_slice(&self.seed.0);
            preimage[32..].copy_from_slice(&self.next_block.to_le_bytes());
            self.hash = Root::sha256(&preimage);
            self.next_block += 1;
            self.offset = 0;
        }
        let bytes = &self.hash.0[self.offset..self.offset + self.width];
        self.offset += self.width;
        bytes
            .iter()
            .rev()
            .fold(0, |value, byte| (value << 8) | u64::from(*byte))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Draw number i of a width, straight from its definition.
    fn reference_draw(seed: Bytes32, width: usize, i: u64) -> u64 {
        let per_hash = (32 / width) as u64;
        let mut preimage = [0; 40];
        preimage[..32].copy_from_slice(&seed.0);
        preimage[32..].copy_from_slice(&(i / per_hash).to_le_bytes());
        let hash = Root::sha256(&preimage);
        let offset = (i % per_hash) as usize * width;
        hash.0[offset..offset + width]
            .iter()
            .rev()
            .fold(0, |value, byte| (value << 8) | u64::from(*byte))
    }

    #[test]
    fn draws_read_little_endian_words_of_the_fork_width() {
        // Fixture state: the zero seed, whose block 0 hash is sha256 of 40 zero bytes.
        let seed = Bytes32([0; 32]);
        let hash = Root::sha256(&[0; 40]).0;

        // One-byte draws: draw 5 is byte 5 of the block 0 hash, draw 32 starts block 1.
        let narrow: Vec<u64> = {
            let mut draws = RandomDraws::new(seed, 1);
            assert_eq!(draws.max_value(), 255);
            (0..33).map(|_| draws.next_draw()).collect()
        };
        assert_eq!(narrow[5], u64::from(hash[5]));
        let mut preimage = [0; 40];
        preimage[32] = 1;
        assert_eq!(narrow[32], u64::from(Root::sha256(&preimage).0[0]));

        // Two-byte draws: draw 3 is bytes 6 and 7 of the block 0 hash, low byte first.
        let mut wide = RandomDraws::new(seed, 2);
        assert_eq!(wide.max_value(), 65_535);
        let wide: Vec<u64> = (0..4).map(|_| wide.next_draw()).collect();
        assert_eq!(wide[3], u64::from(u16::from_le_bytes([hash[6], hash[7]])));
    }

    proptest! {
        #[test]
        fn the_stream_equals_the_indexed_definition(seed: [u8; 32], wide: bool) {
            // Three hashes' worth of draws, crossing two hash boundaries.
            let width = if wide { 2 } else { 1 };
            let mut draws = RandomDraws::new(Bytes32(seed), width);
            for i in 0..3 * (32 / width) as u64 {
                prop_assert_eq!(draws.next_draw(), reference_draw(Bytes32(seed), width, i));
            }
        }
    }
}
