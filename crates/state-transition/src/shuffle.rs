//! The swap-or-not shuffle that assigns validators to committees.

use axiom_types::{Bytes32, Root};

/// A seeded permutation of `0..count`, built from swap-or-not rounds.
///
/// # Overview
///
/// Each round picks a pivot, and pairs every position `x` with its mirror `pivot - x`.
/// A seeded bit then decides whether the pair swaps.
///
/// ```text
/// count = 6, pivot = 4
///
/// pairs:   0<->4   1<->3   2<->2   5<->5
/// a set bit for the pair's larger member swaps it
/// ```
///
/// A round is an involution, so the shuffle is a bijection and can be computed per index.
/// See Hoang, Morris, and Rogaway, "An Enciphering Scheme Based on a Card Shuffle", CRYPTO 2012.
///
/// # Performance
///
/// One index costs two hashes per round.
/// The whole permutation costs one hash per 512 positions per round, so committees use it.
#[derive(Clone, Copy, Debug)]
pub struct SwapOrNot {
    /// The seed every round hashes from.
    seed: Bytes32,
    /// Number of rounds, the preset's shuffle round count.
    rounds: u8,
}

impl SwapOrNot {
    /// A shuffle with a seed and a round count.
    #[must_use]
    pub const fn new(seed: Bytes32, rounds: u64) -> Self {
        // Invariant: the spec encodes the round number in one byte.
        assert!(rounds <= 256, "swap-or-not encodes the round in one byte");
        Self {
            seed,
            rounds: rounds as u8,
        }
    }

    /// Image of one index under the shuffle.
    ///
    /// See `compute_shuffled_index` in the phase0 beacon chain spec.
    ///
    /// # Panics
    ///
    /// Panics when the index is not below the count.
    #[must_use]
    pub fn shuffled_index(&self, mut index: u64, count: u64) -> u64 {
        assert!(
            index < count,
            "index {index} outside a permutation of {count}"
        );
        for round in 0..self.rounds {
            let pivot = self.pivot(round, count);
            let flip = (pivot + count - index) % count;
            // The pair shares one bit, read at its larger member.
            let position = index.max(flip);
            if self.bit(round, position) {
                index = flip;
            }
        }
        index
    }

    /// The whole permutation: entry `i` is the image of `i`.
    ///
    /// See `compute_shuffled_permutation` in the phase0 beacon chain spec.
    #[must_use]
    pub fn permutation(&self, count: u64) -> Vec<u64> {
        let mut images: Vec<u64> = (0..count).collect();
        self.shuffle(&mut images);
        images
    }

    /// Reorders a list in place, so position `i` receives the item at the image of `i`.
    ///
    /// # Algorithm
    ///
    /// Each round is an involution that swaps some mirror pairs.
    /// Applying the rounds to the list, last round first, composes them in spec order:
    ///
    /// ```text
    /// list[i] = original[round_last(...round_0(i))] = original[image(i)]
    /// ```
    ///
    /// A round visits each pair once, through its larger member, in ascending order.
    /// Consecutive members share their bucket hash, so a round costs one hash per 512 items.
    pub fn shuffle<T: Copy>(&self, items: &mut [T]) {
        let count = items.len() as u64;
        // A list of one has a single fixed point, and every round leaves it alone.
        if count < 2 {
            return;
        }
        for round in (0..self.rounds).rev() {
            let pivot = self.pivot(round, count);
            // Pairs inside 0..=pivot mirror around pivot / 2.
            self.swap_mirrors(items, round, pivot / 2 + 1, pivot, pivot);
            // Pairs inside pivot + 1..count mirror around (pivot + count) / 2.
            self.swap_mirrors(
                items,
                round,
                pivot.midpoint(count) + 1,
                count - 1,
                pivot + count,
            );
        }
    }

    /// Swaps each larger member of a range with its mirror, where the round's bit says so.
    ///
    /// The mirror of a member is the sum minus the member.
    /// The range starts just above half the sum, so every mirror lies below the range.
    fn swap_mirrors<T: Copy>(&self, items: &mut [T], round: u8, first: u64, last: u64, sum: u64) {
        if first > last {
            return;
        }
        // Invariant: sum - first < first, so the mirrors and the members are disjoint slices.
        let (below, above) = items.split_at_mut(first as usize);
        let members = &mut above[..=(last - first) as usize];
        let mirrors = &mut below[(sum - last) as usize..=(sum - first) as usize];

        let mut done = 0;
        while done < members.len() {
            // One bucket of 256 positions shares one hash.
            let position = first + done as u64;
            let source = self.source(round, position / 256);
            let offset = (position % 256) as usize;
            let len = (256 - offset).min(members.len() - done);
            // The member j places past the range start pairs with the j-th mirror from the top.
            let end = mirrors.len() - done;
            let pairs = members[done..done + len]
                .iter_mut()
                .zip(mirrors[end - len..end].iter_mut().rev());
            for (bit, (member, mirror)) in (offset..).zip(pairs) {
                // Why: the bits are random, so a branch would mispredict on half the pairs.
                // Indexing a two-item array by the bit selects without branching.
                let swap = usize::from((source.0[bit / 8] >> (bit % 8)) & 1);
                let pair = [*member, *mirror];
                *member = pair[swap];
                *mirror = pair[1 - swap];
            }
            done += len;
        }
    }

    /// The pivot of a round: the first eight bytes of its hash, modulo the count.
    fn pivot(&self, round: u8, count: u64) -> u64 {
        let mut preimage = [0; 33];
        preimage[..32].copy_from_slice(&self.seed.0);
        preimage[32] = round;
        let digest = Root::sha256(&preimage);
        let mut word = [0; 8];
        word.copy_from_slice(&digest.0[..8]);
        u64::from_le_bytes(word) % count
    }

    /// The 256 decision bits of one bucket of positions in a round.
    fn source(&self, round: u8, bucket: u64) -> Root {
        let mut preimage = [0; 37];
        preimage[..32].copy_from_slice(&self.seed.0);
        preimage[32] = round;
        // Invariant: positions are below 2^40, so their bucket fits in four bytes.
        preimage[33..].copy_from_slice(&(bucket as u32).to_le_bytes());
        Root::sha256(&preimage)
    }

    /// The decision bit for a position in a round.
    fn bit(&self, round: u8, position: u64) -> bool {
        Self::bit_of(&self.source(round, position / 256), position)
    }

    /// Reads a position's bit from its bucket's hash.
    const fn bit_of(source: &Root, position: u64) -> bool {
        let byte = source.0[((position % 256) / 8) as usize];
        (byte >> (position % 8)) & 1 == 1
    }
}

/// Buckets per round up to which a single-index shuffle keeps its bucket hashes.
///
/// Sixteen buckets cover 4096 positions, and a table of every round's buckets stays near 50 KiB.
const KEPT_BUCKETS: u64 = 16;

/// A swap-or-not shuffle of one list size, answering many single-index queries.
///
/// Weighted sampling walks a shuffle index by index, often for dozens of draws.
///
/// # Performance
///
/// Pivots depend only on the round and the size, so each is hashed once, not per query.
/// A small list revisits its few buckets on every query, so their hashes are kept too.
/// A large list rarely revisits a bucket, so keeping its hashes would only cost.
#[derive(Clone, Debug)]
pub(crate) struct IndexShuffle {
    /// The shuffle.
    shuffle: SwapOrNot,
    /// Size of the list, nonzero.
    count: u64,
    /// The pivot of each round.
    pivots: Vec<u64>,
    /// Buckets in each round, the stride of the kept hashes.
    buckets: u64,
    /// Hash of each round's bucket once computed, or empty for a large list.
    sources: Vec<Option<Root>>,
}

impl IndexShuffle {
    /// The shuffle of a list of a nonzero size.
    pub(crate) fn new(shuffle: SwapOrNot, count: u64) -> Self {
        let pivots = (0..shuffle.rounds)
            .map(|round| shuffle.pivot(round, count))
            .collect();
        let buckets = count.div_ceil(256);
        let sources = if buckets <= KEPT_BUCKETS {
            vec![None; (u64::from(shuffle.rounds) * buckets) as usize]
        } else {
            Vec::new()
        };
        Self {
            shuffle,
            count,
            pivots,
            buckets,
            sources,
        }
    }

    /// Image of one index, equal to the single-index shuffle of the spec.
    ///
    /// # Panics
    ///
    /// Panics when the index is not below the count.
    pub(crate) fn image(&mut self, mut index: u64) -> u64 {
        assert!(
            index < self.count,
            "index {index} outside a permutation of {}",
            self.count
        );
        for round in 0..self.shuffle.rounds {
            let pivot = self.pivots[usize::from(round)];
            let flip = (pivot + self.count - index) % self.count;
            // The pair shares one bit, read at its larger member.
            let position = index.max(flip);
            let source = self.source(round, position / 256);
            // Why: the bit is random, so the pair is selected without a branch.
            let swap = usize::from(SwapOrNot::bit_of(&source, position));
            index = [index, flip][swap];
        }
        index
    }

    /// The hash of a round's bucket, kept for a small list.
    fn source(&mut self, round: u8, bucket: u64) -> Root {
        let slot = (u64::from(round) * self.buckets + bucket) as usize;
        match self.sources.get_mut(slot) {
            Some(Some(source)) => *source,
            Some(kept) => *kept.insert(self.shuffle.source(round, bucket)),
            None => self.shuffle.source(round, bucket),
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn single_element_maps_to_itself() {
        assert_eq!(SwapOrNot::new(Bytes32([7; 32]), 90).shuffled_index(0, 1), 0);
    }

    #[test]
    #[should_panic(expected = "outside a permutation")]
    fn index_at_the_count_is_rejected() {
        let _ = SwapOrNot::new(Bytes32::ZERO, 10).shuffled_index(5, 5);
    }

    proptest! {
        #[test]
        fn permutation_matches_per_index(seed: [u8; 32], count in 1_u64..1500) {
            // The bucket-cached permutation must equal the per-index definition.
            let shuffle = SwapOrNot::new(Bytes32(seed), 10);
            let permutation = shuffle.permutation(count);

            for (index, image) in permutation.iter().enumerate() {
                prop_assert_eq!(*image, shuffle.shuffled_index(index as u64, count));
            }
        }

        #[test]
        fn index_shuffle_matches_per_index(
            seed: [u8; 32],
            count in prop_oneof![1_u64..600, 4000_u64..4200, 60_000_u64..70_000],
            queries in proptest::collection::vec(any::<u64>(), 1..40),
        ) {
            // Counts up to 4096 keep their bucket hashes, larger ones hash afresh.
            // Both must equal the per-index definition, query after query.
            let shuffle = SwapOrNot::new(Bytes32(seed), 10);
            let mut cached = IndexShuffle::new(shuffle, count);

            for query in queries {
                let index = query % count;
                prop_assert_eq!(cached.image(index), shuffle.shuffled_index(index, count));
            }
        }

        #[test]
        fn permutation_is_a_bijection(seed: [u8; 32], count in 1_u64..600) {
            let mut permutation = SwapOrNot::new(Bytes32(seed), 10).permutation(count);
            permutation.sort_unstable();

            prop_assert_eq!(permutation, (0..count).collect::<Vec<_>>());
        }
    }
}
