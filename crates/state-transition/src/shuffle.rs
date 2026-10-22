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
/// The whole permutation costs one hash per 256 positions per round, so committees use it.
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
        if count == 0 {
            return images;
        }
        for round in 0..self.rounds {
            let pivot = self.pivot(round, count);
            // Every image moves through the same round, so each bucket hash is shared.
            let mut bucket_cache: Option<(u64, Root)> = None;
            for image in &mut images {
                let flip = (pivot + count - *image) % count;
                let position = (*image).max(flip);
                let bucket = position / 256;
                let source = match bucket_cache {
                    Some((cached, source)) if cached == bucket => source,
                    _ => {
                        let source = self.source(round, bucket);
                        bucket_cache = Some((bucket, source));
                        source
                    }
                };
                if Self::bit_of(&source, position) {
                    *image = flip;
                }
            }
        }
        images
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
        fn permutation_matches_per_index(seed: [u8; 32], count in 1_u64..600) {
            // The bucket-cached permutation must equal the per-index definition.
            let shuffle = SwapOrNot::new(Bytes32(seed), 10);
            let permutation = shuffle.permutation(count);

            for (index, image) in permutation.iter().enumerate() {
                prop_assert_eq!(*image, shuffle.shuffled_index(index as u64, count));
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
