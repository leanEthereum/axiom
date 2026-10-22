//! A small seeded generator for peer selection.
//!
//! Gossipsub picks peers at random so attackers cannot predict the mesh.
//! A seeded generator keeps simulations reproducible.
//! It is not suitable for keys or nonces.

/// The xoshiro256** generator of Blackman and Vigna, seeded through SplitMix64.
#[derive(Clone, Debug)]
pub(crate) struct Rng {
    /// The 256-bit state.
    state: [u64; 4],
}

impl Rng {
    /// A generator from a seed; equal seeds give equal sequences.
    #[must_use]
    pub(crate) const fn new(seed: u64) -> Self {
        // SplitMix64 spreads one seed word over four state words.
        let mut x = seed;
        let mut state = [0u64; 4];
        let mut index = 0;
        while index < 4 {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            state[index] = z ^ (z >> 31);
            index += 1;
        }
        Self { state }
    }

    /// The next 64 random bits.
    pub(crate) const fn next_u64(&mut self) -> u64 {
        let [s0, s1, s2, s3] = self.state;
        let result = s1.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s1 << 17;
        // The xoshiro state transition: xor-shift-rotate over the four words.
        let s2 = s2 ^ s0;
        let s3 = s3 ^ s1;
        let s1 = s1 ^ s2;
        let s0 = s0 ^ s3;
        self.state = [s0, s1, s2 ^ t, s3.rotate_left(45)];
        result
    }

    /// A value below a bound, which must be positive.
    pub(crate) fn below(&mut self, bound: usize) -> usize {
        // Lemire's multiply-shift maps 64 random bits onto the range with negligible bias.
        ((u128::from(self.next_u64()) * bound as u128) >> 64) as usize
    }

    /// Shuffles a slice in place, Fisher-Yates.
    pub(crate) fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }

    /// Fills a buffer with random bytes.
    pub(crate) fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_in_range() {
        // Equal seeds give equal streams.
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        assert_eq!(a.next_u64(), b.next_u64());
        // Values stay below the bound.
        for _ in 0..1000 {
            assert!(a.below(13) < 13);
        }
        // A shuffle is a permutation.
        let mut items: Vec<u32> = (0..50).collect();
        a.shuffle(&mut items);
        let mut sorted = items.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..50).collect::<Vec<_>>());
    }
}
