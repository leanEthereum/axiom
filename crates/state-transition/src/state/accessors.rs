//! Spec accessors that need the state's caches.

use std::{collections::BTreeSet, sync::Arc};

use axiom_bls::PublicKey;
use axiom_types::{
    Attestation, BlsPubkey, Bytes32, ChainConfig, CommitteeIndex, Epoch, Gwei, Preset, Root, Slot,
    SyncCommittee, ValidatorIndex,
    constants::{DOMAIN_BEACON_PROPOSER, DOMAIN_SYNC_COMMITTEE},
};

use super::State;
use crate::{BlockError, EpochCommittees, StateError, SwapOrNot};

/// Largest value of the 16-bit random draws in proposer and sync committee sampling.
///
/// See `compute_proposer_index` in the Electra beacon chain spec.
const MAX_RANDOM_VALUE: u64 = (1 << 16) - 1;

impl<P: Preset> State<P> {
    /// Committees of the previous, current, or next epoch.
    ///
    /// # Errors
    ///
    /// Fails for any other epoch, whose committees are not fixed yet or no longer kept.
    pub fn committees(&mut self, epoch: Epoch) -> Result<Arc<EpochCommittees>, StateError> {
        self.check_committee_epoch(epoch)?;
        if let Some(found) = self
            .committees
            .iter()
            .find(|cached| cached.epoch() == epoch)
        {
            return Ok(Arc::clone(found));
        }
        let computed = Arc::new(EpochCommittees::compute(&self.beacon, epoch));
        self.committees.push(Arc::clone(&computed));
        Ok(computed)
    }

    /// Validators an attestation counts, sorted and unique.
    ///
    /// The aggregation bits run across the selected committees, back to back.
    ///
    /// ```text
    /// committee bits:    0 1 0 1          committees 1 and 3 are aggregated
    /// aggregation bits:  [c1 members][c3 members]
    /// ```
    ///
    /// See `get_attesting_indices` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when a committee does not exist or the bits run short.
    pub fn attesting_indices(
        &mut self,
        attestation: &Attestation<P>,
    ) -> Result<BTreeSet<ValidatorIndex>, BlockError> {
        let committees = self.committees(attestation.data.target.epoch)?;
        let mut attesters = BTreeSet::new();
        let mut offset = 0;
        for index in attestation.committee_indices() {
            let committee = committees
                .committee(attestation.data.slot, index)
                .ok_or(BlockError::UnknownCommittee(index))?;
            for (position, validator) in committee.iter().enumerate() {
                let bit = attestation
                    .aggregation_bits
                    .get(offset + position)
                    .ok_or(BlockError::AggregationBitsLengthMismatch)?;
                if bit {
                    attesters.insert(*validator);
                }
            }
            offset += committee.len();
        }
        Ok(attesters)
    }

    /// Decompressed key of a validator.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist or its key does not decompress.
    pub fn public_key(&mut self, index: ValidatorIndex) -> Result<PublicKey, BlockError> {
        let validator = self
            .beacon
            .validators
            .get(index.as_usize())
            .ok_or(StateError::UnknownValidator(index))?;
        self.pubkeys.sync(&self.beacon.validators);
        self.pubkeys
            .public_key(index, &validator.pubkey)
            .ok_or(BlockError::MalformedSignature)
    }

    /// Index of the validator with a key.
    pub fn validator_index(&mut self, pubkey: &BlsPubkey) -> Option<ValidatorIndex> {
        self.pubkeys.sync(&self.beacon.validators);
        self.pubkeys.index_of(pubkey)
    }

    /// Samples a validator from candidates, weighted by effective balance.
    ///
    /// # Algorithm
    ///
    /// Walk the shuffled candidates in order.
    /// Accept each one with probability effective balance over the maximum balance.
    ///
    /// The draws come 16 bits at a time from hashes of the seed, sixteen draws per hash.
    /// See `compute_proposer_index` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when there is no candidate.
    pub fn compute_proposer_index(
        &self,
        candidates: &[ValidatorIndex],
        seed: Bytes32,
    ) -> Result<ValidatorIndex, StateError> {
        let total = candidates.len() as u64;
        if total == 0 {
            return Err(StateError::NoActiveValidators(self.beacon.current_epoch()));
        }
        let shuffle = SwapOrNot::new(seed, P::SHUFFLE_ROUND_COUNT);
        let mut draws = RandomDraws::new(seed);
        for i in 0.. {
            let candidate = candidates[shuffle.shuffled_index(i % total, total) as usize];
            let effective_balance = self.beacon.validators[candidate.as_usize()].effective_balance;
            if Self::accepts(effective_balance, draws.draw(i)) {
                return Ok(candidate);
            }
        }
        unreachable!("a validator with nonzero balance is eventually accepted")
    }

    /// Proposers of every slot of an epoch.
    ///
    /// Each slot gets its own seed, the epoch seed hashed with the slot number.
    /// See `get_beacon_proposer_indices` in the Fulu beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the epoch has no active validator.
    pub fn beacon_proposer_indices(&self, epoch: Epoch) -> Result<Vec<ValidatorIndex>, StateError> {
        let candidates = self.beacon.active_validator_indices(epoch);
        let seed = self.beacon.seed(epoch, DOMAIN_BEACON_PROPOSER);
        let start = epoch.start_slot::<P>();
        (0..P::SLOTS_PER_EPOCH)
            .map(|offset| {
                let mut preimage = [0; 40];
                preimage[..32].copy_from_slice(&seed.0);
                preimage[32..].copy_from_slice(&(start.0 + offset).to_le_bytes());
                self.compute_proposer_index(&candidates, Bytes32(Root::sha256(&preimage).0))
            })
            .collect()
    }

    /// Indices of the next sync committee, possibly repeating a validator.
    ///
    /// Sampling is weighted by effective balance, as for proposers.
    /// See `get_next_sync_committee_indices` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the next epoch has no active validator.
    pub fn next_sync_committee_indices(&self) -> Result<Vec<ValidatorIndex>, StateError> {
        let epoch = self.beacon.current_epoch() + 1;
        let candidates = self.beacon.active_validator_indices(epoch);
        let total = candidates.len() as u64;
        if total == 0 {
            return Err(StateError::NoActiveValidators(epoch));
        }
        let seed = self.beacon.seed(epoch, DOMAIN_SYNC_COMMITTEE);
        let shuffle = SwapOrNot::new(seed, P::SHUFFLE_ROUND_COUNT);
        let mut draws = RandomDraws::new(seed);

        let size = P::SYNC_COMMITTEE_SIZE as usize;
        let mut indices = Vec::with_capacity(size);
        let mut i = 0;
        while indices.len() < size {
            let candidate = candidates[shuffle.shuffled_index(i % total, total) as usize];
            let effective_balance = self.beacon.validators[candidate.as_usize()].effective_balance;
            if Self::accepts(effective_balance, draws.draw(i)) {
                indices.push(candidate);
            }
            i += 1;
        }
        Ok(indices)
    }

    /// The next sync committee, with its aggregate key.
    ///
    /// See `get_next_sync_committee` in the Altair beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when there is no candidate, or the keys do not aggregate.
    pub fn next_sync_committee(&mut self) -> Result<SyncCommittee<P>, StateError> {
        let indices = self.next_sync_committee_indices()?;
        let pubkeys: Vec<BlsPubkey> = indices
            .iter()
            .map(|index| self.beacon.validators[index.as_usize()].pubkey)
            .collect();

        let keys = indices
            .iter()
            .map(|index| self.public_key(*index))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StateError::InvalidSyncCommittee)?;
        let aggregate =
            PublicKey::aggregate(&keys).map_err(|_| StateError::InvalidSyncCommittee)?;

        Ok(SyncCommittee {
            pubkeys: pubkeys
                .try_into()
                .map_err(|_| StateError::InvalidSyncCommittee)?,
            aggregate_pubkey: BlsPubkey(aggregate.to_bytes()),
        })
    }

    /// Base reward per increment of effective balance.
    ///
    /// It scales with the inverse square root of the total stake.
    /// Issuance then grows with the square root of the stake.
    ///
    /// See `get_base_reward_per_increment` in the Altair beacon chain spec.
    #[must_use]
    pub const fn base_reward_per_increment(total_active_balance: Gwei) -> Gwei {
        Gwei(
            P::EFFECTIVE_BALANCE_INCREMENT.0 * P::BASE_REWARD_FACTOR
                / total_active_balance.0.isqrt(),
        )
    }

    /// Churn of the current epoch in balance, before splitting into its uses.
    ///
    /// See `get_balance_churn_limit` in the Electra beacon chain spec.
    #[must_use]
    pub fn balance_churn_limit(config: &ChainConfig, total_active_balance: Gwei) -> Gwei {
        let churn = config
            .min_per_epoch_churn_limit_electra
            .max(total_active_balance / config.churn_limit_quotient);
        churn - Gwei(churn.0 % P::EFFECTIVE_BALANCE_INCREMENT.0)
    }

    /// Churn of the current epoch reserved for activations and exits.
    #[must_use]
    pub fn activation_exit_churn_limit(config: &ChainConfig, total_active_balance: Gwei) -> Gwei {
        config
            .max_per_epoch_activation_exit_churn_limit
            .min(Self::balance_churn_limit(config, total_active_balance))
    }

    /// Churn of the current epoch left for consolidations.
    #[must_use]
    pub fn consolidation_churn_limit(config: &ChainConfig, total_active_balance: Gwei) -> Gwei {
        Self::balance_churn_limit(config, total_active_balance)
            - Self::activation_exit_churn_limit(config, total_active_balance)
    }

    /// The beacon committee at a slot and index.
    ///
    /// # Errors
    ///
    /// Fails when the slot's epoch is not cached or the committee does not exist.
    pub fn beacon_committee(
        &mut self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Result<Vec<ValidatorIndex>, BlockError> {
        let committees = self.committees(slot.epoch::<P>())?;
        committees
            .committee(slot, index)
            .map(<[ValidatorIndex]>::to_vec)
            .ok_or(BlockError::UnknownCommittee(index))
    }

    /// Whether a candidate passes its draw.
    ///
    /// Threshold: balance * 65535 >= max balance * draw, so a full balance always passes.
    const fn accepts(effective_balance: Gwei, draw: u64) -> bool {
        effective_balance.0 as u128 * MAX_RANDOM_VALUE as u128
            >= P::MAX_EFFECTIVE_BALANCE_ELECTRA.0 as u128 * draw as u128
    }
}

/// Sixteen-bit random draws from hashes of a seed, sixteen draws per hash.
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
