//! Keccak-f\[1600\], the permutation under every sponge of the family.

/// Lanes of the permutation state, a 5 x 5 grid of 64-bit words.
const LANES: usize = 25;

/// Rounds of Keccak-f\[1600\]: 12 + 2 * log_2(64), per the Keccak reference, section 1.2.
const ROUNDS: usize = 24;

/// Round constants of the iota step, one per round.
///
/// Each one is the output of a degree-8 LFSR, per the Keccak reference, section 1.2.
const ROUND_CONSTANTS: [u64; ROUNDS] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation amounts of the rho step, in the order the pi step visits the lanes.
///
/// Entry t is (t + 1)(t + 2) / 2 mod 64, per the Keccak reference, section 1.2.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Lane visit order of the pi step, starting from lane 1.
///
/// Lane (x, y) at index x + 5y moves to (y, 2x + 3y), and the chain covers all 24 non-origin lanes.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The 1600-bit Keccak state and its permutation.
///
/// Lane (x, y) sits at index x + 5y.
/// Bytes enter lanes in little-endian order, per FIPS 202, section 3.1.2.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeccakF1600 {
    /// The 25 lanes.
    lanes: [u64; LANES],
}

impl KeccakF1600 {
    /// The all-zero state.
    #[must_use]
    pub const fn new() -> Self {
        Self { lanes: [0; LANES] }
    }

    /// A state with the given lanes.
    #[must_use]
    pub const fn from_lanes(lanes: [u64; LANES]) -> Self {
        Self { lanes }
    }

    /// The lanes of the state.
    #[must_use]
    pub const fn lanes(&self) -> &[u64; LANES] {
        &self.lanes
    }

    /// Applies the 24-round permutation in place.
    ///
    /// # Algorithm
    ///
    /// Each round chains five steps, per the Keccak reference, section 1.2.
    ///
    /// ```text
    /// theta : each lane absorbs the parity of two neighbouring columns
    /// rho   : each lane rotates by its own fixed amount
    /// pi    : lanes move to new positions
    /// chi   : each row passes through the only non-linear map, a ^ (!b & c)
    /// iota  : lane (0, 0) absorbs the round constant
    /// ```
    pub fn permute(&mut self) {
        // Lanes in place, 24 rounds.
        let a = &mut self.lanes;
        for &round_constant in &ROUND_CONSTANTS {
            // Theta, phase 1: parity of each of the five columns.
            let mut parity = [0_u64; 5];
            for (x, column) in parity.iter_mut().enumerate() {
                *column = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }

            // Theta, phase 2: lane (x, y) absorbs column x - 1 and column x + 1 rotated by one.
            for x in 0..5 {
                let d = parity[(x + 4) % 5] ^ parity[(x + 1) % 5].rotate_left(1);
                for y in 0..5 {
                    a[x + 5 * y] ^= d;
                }
            }

            // Rho and pi together: walk the pi cycle, rotating each lane as it moves.
            //
            //     lane 1 -> lane 10 (rotated by 1)
            //     lane 10 -> lane 7 (rotated by 3)
            //     ...
            //     lane 6 -> lane 1  (rotated by 44)
            let mut carried = a[1];
            for (&target, &rotation) in PI.iter().zip(&RHO) {
                let displaced = a[target];
                a[target] = carried.rotate_left(rotation);
                carried = displaced;
            }

            // Chi: each row of five lanes mixes non-linearly, from a copy of the row.
            for y in 0..5 {
                let row = [
                    a[5 * y],
                    a[5 * y + 1],
                    a[5 * y + 2],
                    a[5 * y + 3],
                    a[5 * y + 4],
                ];
                for x in 0..5 {
                    a[5 * y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
                }
            }

            // Iota: break the symmetry between rounds.
            a[0] ^= round_constant;
        }
    }

    /// XORs a block into the leading lanes.
    ///
    /// Every rate of the family is a whole number of lanes, so the block is too.
    pub(crate) fn absorb(&mut self, block: &[u8]) {
        // Invariant: rates are 72, 104, 136, 144 or 168 bytes, all multiples of 8.
        debug_assert!(block.len().is_multiple_of(8) && block.len() <= 8 * LANES);
        let (words, _) = block.as_chunks::<8>();
        for (lane, word) in self.lanes.iter_mut().zip(words) {
            *lane ^= u64::from_le_bytes(*word);
        }
    }

    /// Copies the leading bytes of the state, lanes in little-endian order.
    pub(crate) fn extract(&self, out: &mut [u8]) {
        // Whole lanes first, then the leading bytes of one more lane.
        debug_assert!(out.len() <= 8 * LANES);
        let (words, tail) = out.as_chunks_mut::<8>();
        for (word, lane) in words.iter_mut().zip(&self.lanes) {
            *word = lane.to_le_bytes();
        }
        if !tail.is_empty() {
            let last = self.lanes[words.len()].to_le_bytes();
            tail.copy_from_slice(&last[..tail.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutation_of_the_zero_state() {
        // The Keccak team's known answer: Keccak-f[1600] on 1600 zero bits.
        let mut state = KeccakF1600::new();
        state.permute();
        assert_eq!(
            state.lanes()[..4],
            [
                0xf125_8f79_40e1_dde7,
                0x84d5_ccf9_33c0_478a,
                0xd598_261e_a65a_a9ee,
                0xbd15_4730_6f80_494d,
            ]
        );
    }

    #[test]
    fn extract_reads_lanes_little_endian() {
        // Fixture state: lane 0 = 0x0807060504030201, lane 1 = 0x100f0e0d0c0b0a09.
        let mut lanes = [0; LANES];
        lanes[0] = 0x0807_0605_0403_0201;
        lanes[1] = 0x100f_0e0d_0c0b_0a09;
        let state = KeccakF1600::from_lanes(lanes);

        // Eleven bytes: one whole lane, then the first three bytes of the next.
        let mut out = [0; 11];
        state.extract(&mut out);
        assert_eq!(out, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    }

    #[test]
    fn absorb_xors_into_the_leading_lanes() {
        // Absorbing the same 16 bytes twice cancels out, lane by lane.
        let block: Vec<u8> = (1..=16).collect();
        let mut state = KeccakF1600::new();
        state.absorb(&block);
        assert_eq!(
            state.lanes()[..3],
            [0x0807_0605_0403_0201, 0x100f_0e0d_0c0b_0a09, 0]
        );
        state.absorb(&block);
        assert_eq!(state, KeccakF1600::new());
    }
}
