//! The Poseidon1 permutation over KoalaBear, at widths 16 and 24.
//!
//! # Overview
//!
//! Poseidon alternates full rounds, where every word passes the S-box, with partial rounds, where one does.
//! Each round adds its constants, applies the S-box, and multiplies by an MDS matrix.
//!
//! ```text
//! rounds = 4 full, R_P partial, 4 full
//! S-box  = x^3, a permutation since gcd(3, p - 1) = 1
//! R_P    = 20 at width 16, 23 at width 24
//! ```
//!
//! The partial round counts follow the Poseidon paper's security analysis for 128-bit security.
//! The MDS matrices are circulant, given by their first row.
//! The round constants come from the paper's Grain LFSR, generated at compile time.
//!
//! Grassi, Khovratovich, Rechberger, Roy, Schofnegger, "Poseidon", USENIX Security 2021.
//!
//! # Performance
//!
//! The matrix multiply accumulates integer products of Montgomery forms and reduces once per output.
//! The form is linear: a sum of c_j * (x_j * 2^32) is the form of sum c_j * x_j.

mod grain;

use crate::{field::KoalaBear, poseidon::grain::Grain};

/// Full rounds before and after the partial rounds, R_F / 2 in the Poseidon paper.
const HALF_FULL_ROUNDS: usize = 4;

/// Partial rounds at width 16.
const PARTIAL_ROUNDS_16: usize = 20;

/// Partial rounds at width 24.
const PARTIAL_ROUNDS_24: usize = 23;

/// First row of the width-16 circulant MDS matrix: small entries, so sums stay in 64 bits.
const MDS_ROW_16: [u32; 16] = [1, 1, 51, 1, 11, 17, 2, 1, 101, 63, 15, 2, 67, 22, 13, 3];

/// First row of the width-24 circulant MDS matrix.
const MDS_ROW_24: [u32; 24] = [
    0x2d0a_aaab,
    0x6485_0517,
    0x17f5_551d,
    0x04ec_beb5,
    0x6d91_a8d5,
    0x6070_3026,
    0x18d6_f3ca,
    0x7296_01a7,
    0x77cd_a9e2,
    0x3c0f_5038,
    0x26d5_2a61,
    0x0360_405d,
    0x68fc_71c8,
    0x2495_a71d,
    0x5d57_afc2,
    0x1689_dd98,
    0x3c2c_3dbe,
    0x0c23_dc41,
    0x0524_c7f2,
    0x6be4_df69,
    0x0a6e_572c,
    0x5c77_90fa,
    0x17e1_18f6,
    0x0878_a07f,
];

/// Round constants of the width-16 instance, one row per round.
static ROUND_CONSTANTS_16: [[KoalaBear; 16]; 2 * HALF_FULL_ROUNDS + PARTIAL_ROUNDS_16] =
    round_constants(PARTIAL_ROUNDS_16);

/// Round constants of the width-24 instance, one row per round.
static ROUND_CONSTANTS_24: [[KoalaBear; 24]; 2 * HALF_FULL_ROUNDS + PARTIAL_ROUNDS_24] =
    round_constants(PARTIAL_ROUNDS_24);

/// The width-16 permutation, which compresses one chain step.
pub static POSEIDON1_16: Poseidon1<16> = Poseidon1 {
    round_constants: &ROUND_CONSTANTS_16,
    partial_rounds: PARTIAL_ROUNDS_16,
    mds_row: MDS_ROW_16,
};

/// The width-24 permutation, which merges tree nodes and drives the sponge.
pub static POSEIDON1_24: Poseidon1<24> = Poseidon1 {
    round_constants: &ROUND_CONSTANTS_24,
    partial_rounds: PARTIAL_ROUNDS_24,
    mds_row: MDS_ROW_24,
};

/// The Grain-derived round constants of one instance, rounds in order.
const fn round_constants<const WIDTH: usize, const ROUNDS: usize>(
    partial_rounds: usize,
) -> [[KoalaBear; WIDTH]; ROUNDS] {
    let mut grain = Grain::new(
        WIDTH as u32,
        (2 * HALF_FULL_ROUNDS) as u32,
        partial_rounds as u32,
    );
    let mut table = [[KoalaBear::ZERO; WIDTH]; ROUNDS];
    let mut round = 0;
    while round < ROUNDS {
        let mut word = 0;
        while word < WIDTH {
            table[round][word] = grain.next_element();
            word += 1;
        }
        round += 1;
    }
    table
}

/// A Poseidon1 permutation over WIDTH field elements.
#[derive(Debug)]
pub struct Poseidon1<const WIDTH: usize> {
    /// Constants of every round, full and partial alike.
    round_constants: &'static [[KoalaBear; WIDTH]],
    /// Number of partial rounds.
    partial_rounds: usize,
    /// First row of the circulant MDS matrix, as canonical integers.
    mds_row: [u32; WIDTH],
}

impl<const WIDTH: usize> Poseidon1<WIDTH> {
    /// Applies the permutation in place.
    pub fn permute(&self, state: &mut [KoalaBear; WIDTH]) {
        let (first, rest) = self.round_constants.split_at(HALF_FULL_ROUNDS);
        let (partial, last) = rest.split_at(self.partial_rounds);
        for constants in first {
            self.full_round(state, constants);
        }
        for constants in partial {
            self.partial_round(state, constants);
        }
        for constants in last {
            self.full_round(state, constants);
        }
    }

    /// The compression function: the permutation plus its input, truncated to OUT words.
    ///
    /// The feed-forward makes the map one-way, as the tweakable hash requires.
    #[must_use]
    pub fn compress<const OUT: usize>(&self, input: &[KoalaBear; WIDTH]) -> [KoalaBear; OUT] {
        const { assert!(OUT <= WIDTH) };
        let mut state = *input;
        self.permute(&mut state);
        std::array::from_fn(|i| state[i] + input[i])
    }

    /// A full round: constants, the S-box on every word, then the matrix.
    fn full_round(&self, state: &mut [KoalaBear; WIDTH], constants: &[KoalaBear; WIDTH]) {
        for (word, &constant) in state.iter_mut().zip(constants) {
            *word = (*word + constant).cube();
        }
        self.mix(state);
    }

    /// A partial round: constants on every word, the S-box on the first, then the matrix.
    fn partial_round(&self, state: &mut [KoalaBear; WIDTH], constants: &[KoalaBear; WIDTH]) {
        for (word, &constant) in state.iter_mut().zip(constants) {
            *word += constant;
        }
        state[0] = state[0].cube();
        self.mix(state);
    }

    /// Multiplies the state by the circulant matrix: out_i = sum_j row_((j - i) mod WIDTH) * x_j.
    fn mix(&self, state: &mut [KoalaBear; WIDTH]) {
        let input = state.map(|word| u128::from(word.montgomery()));
        for (i, out) in state.iter_mut().enumerate() {
            // Bound: 24 products below 2^31 * 2^31 sum below 2^67, so 128 bits hold them.
            let mut sum = 0_u128;
            for (j, &x) in input.iter().enumerate() {
                sum += u128::from(self.mds_row[(j + WIDTH - i) % WIDTH]) * x;
            }
            *out = fold(sum);
        }
    }
}

/// The element whose Montgomery form is congruent to a sum below 2^67.
///
/// # Algorithm
///
/// The prime's shape gives a cheap first fold, since 2^31 = 2^24 - 1 mod p.
///
/// ```text
/// sum = high * 2^31 + low
///     = high * (2^24 - 1) + low   mod p
/// ```
///
/// High is below 2^36, so the folded sum is below 2^61, inside the Montgomery reduction's range.
const fn fold(sum: u128) -> KoalaBear {
    let high = (sum >> 31) as u64;
    let low = (sum as u64) & ((1 << 31) - 1);
    KoalaBear::from_montgomery_sum(high * ((1 << 24) - 1) + low)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical values to elements.
    fn elements<const N: usize>(values: [u32; N]) -> [KoalaBear; N] {
        values.map(|value| KoalaBear::from_canonical(value).unwrap())
    }

    #[test]
    fn width_16_on_the_counting_state() {
        // Fixture state: words 0, 1, ..., 15.
        let mut state = elements(std::array::from_fn::<u32, 16, _>(|i| i as u32));
        POSEIDON1_16.permute(&mut state);
        assert_eq!(
            state,
            elements([
                610_090_613,
                935_319_874,
                1_893_335_292,
                796_792_199,
                356_405_232,
                552_237_741,
                55_134_556,
                1_215_104_204,
                1_823_723_405,
                1_133_298_033,
                1_780_633_798,
                1_453_946_561,
                710_069_176,
                1_128_629_550,
                1_917_333_254,
                1_175_481_618,
            ])
        );
    }

    #[test]
    fn width_24_on_the_counting_state() {
        // Fixture state: words 0, 1, ..., 23.
        let mut state = elements(std::array::from_fn::<u32, 24, _>(|i| i as u32));
        POSEIDON1_24.permute(&mut state);
        assert_eq!(
            state,
            elements([
                511_672_087,
                215_882_318,
                237_782_537,
                740_528_428,
                712_760_904,
                54_615_367,
                751_514_671,
                110_231_969,
                1_905_276_435,
                992_525_666,
                918_312_360,
                18_628_693,
                749_929_200,
                1_916_418_953,
                691_276_896,
                1_112_901_727,
                1_163_558_623,
                882_867_603,
                673_396_520,
                1_480_278_156,
                1_402_044_758,
                1_693_467_175,
                1_766_273_044,
                433_841_551,
            ])
        );
    }

    #[test]
    fn width_16_on_the_largest_state() {
        // Fixture state: every word p - 1, the largest products the matrix sees.
        let mut state = [KoalaBear::new(KoalaBear::ORDER - 1); 16];
        POSEIDON1_16.permute(&mut state);
        assert_eq!(
            state,
            elements([
                80_767_616,
                383_372_031,
                1_503_356_788,
                2_125_894_918,
                1_946_887_912,
                879_437_609,
                1_712_137_281,
                672_292_544,
                1_911_844_364,
                828_626_166,
                1_140_802_964,
                650_895_436,
                1_866_586_638,
                613_293_787,
                1_870_649_746,
                481_320_165,
            ])
        );
    }

    #[test]
    fn fold_reduces_the_largest_sum() {
        // The largest sum the width-24 matrix produces: 24 products of p - 1 by p - 1.
        let p = u128::from(KoalaBear::ORDER);
        let sum = 24 * (p - 1) * (p - 1);
        assert_eq!(fold(sum).montgomery(), (sum % p) as u32);
    }
}
