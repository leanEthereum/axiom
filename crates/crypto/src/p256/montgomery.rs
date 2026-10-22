//! Montgomery arithmetic modulo an odd integer below 2^256, shared by the field and the scalars.

use std::array;

use crate::{ct::Mask, uint::U256};

/// An odd modulus m below 2^256 with its Montgomery constants for R = 2^256.
///
/// # Overview
///
/// A residue a is held as a R mod m, so a product needs no division by m.
///
/// ```text
/// mont(a R, b R) = a R * b R / R = (a b) R   (mod m)
/// ```
///
/// Every input and output of the operations below is a canonical value in [0, m).
#[derive(Clone, Copy, Debug)]
pub(super) struct Modulus {
    /// The modulus m.
    value: U256,
    /// The word -m^-1 mod 2^64, which cancels the low word in each reduction step.
    inverse: u64,
    /// R^2 mod m, which maps a plain value into Montgomery form.
    r_squared: [u64; 4],
}

impl Modulus {
    /// The constants of an odd modulus, computed at compile time.
    pub(super) const fn new(value: U256) -> Self {
        let mut modulus = Self {
            value,
            inverse: Self::negated_inverse(value.0[0]),
            r_squared: [0; 4],
        };
        // R^2 mod m: 1 doubled 512 times.
        modulus.r_squared = modulus.doubled_times([1, 0, 0, 0], 512);
        modulus
    }

    /// The modulus as an integer.
    pub(super) const fn value(&self) -> U256 {
        self.value
    }

    /// The Montgomery form a R mod m of a canonical value, at compile time.
    ///
    /// It doubles 256 times, never calling the product, so it also checks the product.
    pub(super) const fn encode_const(&self, value: [u64; 4]) -> [u64; 4] {
        self.doubled_times(value, 256)
    }

    /// The word -m^-1 mod 2^64 for odd m, by Newton iteration.
    const fn negated_inverse(low: u64) -> u64 {
        // Each step doubles the correct low bits: 1, 2, 4, 8, 16, 32, 64.
        //
        //     inv * m = 1 mod 2^k  ->  inv (2 - m inv) * m = 1 mod 2^(2k)
        let mut inv = 1_u64;
        let mut step = 0;
        while step < 6 {
            inv = inv.wrapping_mul(2_u64.wrapping_sub(low.wrapping_mul(inv)));
            step += 1;
        }
        inv.wrapping_neg()
    }

    /// The canonical value 2^k a mod m, by k modular doublings, at compile time.
    const fn doubled_times(&self, value: [u64; 4], k: u32) -> [u64; 4] {
        let m = self.value.0;
        let mut r = value;
        let mut step = 0;
        while step < k {
            // Double, then subtract m when the doubled value reaches m or overflows 2^256.
            let overflow = r[3] >> 63;
            r = [
                r[0] << 1,
                (r[1] << 1) | (r[0] >> 63),
                (r[2] << 1) | (r[1] >> 63),
                (r[3] << 1) | (r[2] >> 63),
            ];
            let mut reduced = [0_u64; 4];
            let mut borrow = 0_u64;
            let mut i = 0;
            while i < 4 {
                let (d1, b1) = r[i].overflowing_sub(m[i]);
                let (d2, b2) = d1.overflowing_sub(borrow);
                reduced[i] = d2;
                borrow = (b1 | b2) as u64;
                i += 1;
            }
            if overflow == 1 || borrow == 0 {
                r = reduced;
            }
            step += 1;
        }
        r
    }

    /// Holds when an integer is below m, the canonical range.
    pub(super) fn contains(&self, value: U256) -> Mask {
        // The value is canonical exactly when subtracting m borrows.
        let (_, borrow) = value.sub_with_borrow(self.value);
        Mask::from_bit(borrow)
    }

    /// The sum modulo m.
    pub(super) fn add(&self, a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        // The true sum may reach 2m - 2, which can exceed 2^256 when m > 2^255.
        let (sum, carry) = U256(a).add_with_carry(U256(b));

        // Subtract m once and keep that result when the sum reached m.
        //
        //     carry out of the add        -> sum >= 2^256 > m
        //     no borrow out of sum - m    -> sum >= m
        let (reduced, borrow) = sum.sub_with_borrow(self.value);
        let use_reduced = Mask::from_bit(carry).or(Mask::from_bit(borrow).not());
        array::from_fn(|i| use_reduced.select(reduced.0[i], sum.0[i]))
    }

    /// The difference modulo m.
    pub(super) fn sub(&self, a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        // A borrow means the result wrapped to a - b + 2^256: add m back modulo 2^256.
        let (difference, borrow) = U256(a).sub_with_borrow(U256(b));
        let wrapped = Mask::from_bit(borrow);
        let correction = U256(self.value.0.map(|limb| wrapped.select(limb, 0)));
        difference.add_with_carry(correction).0.0
    }

    /// The Montgomery product a b R^-1 mod m.
    ///
    /// # Algorithm
    ///
    /// Coarsely integrated operand scanning (CIOS), word by word.
    /// Koc, Acar and Kaliski, "Analyzing and comparing Montgomery multiplication algorithms", 1996.
    ///
    /// ```text
    /// for each limb b_i:
    ///     t = t + a b_i              add one row
    ///     f = t_0 * (-m^-1) mod 2^64 choose f so the low word cancels
    ///     t = (t + f m) / 2^64       exact division by one word
    /// ```
    ///
    /// # Invariants
    ///
    /// With a, b < m, each pass keeps t < 2m, so t fits in five words.
    /// One masked subtraction then brings it under m.
    pub(super) fn mul(&self, a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let modulus = self.value.0;

        // Six words: four for t, one for its carry, one spare for the row's overflow.
        let mut t = [0_u64; 6];
        for &bi in &b {
            // Row: t += a * b_i.
            // Each step fits 128 bits: (2^64 - 1)^2 + 2 (2^64 - 1) = 2^128 - 1.
            let mut carry = 0_u128;
            for j in 0..4 {
                let sum = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + carry;
                t[j] = sum as u64;
                carry = sum >> 64;
            }
            let sum = u128::from(t[4]) + carry;
            t[4] = sum as u64;
            t[5] = (sum >> 64) as u64;

            // Reduction: t += f m makes the low word zero.
            // Then shift down one word.
            let factor = t[0].wrapping_mul(self.inverse);
            let sum = u128::from(t[0]) + u128::from(factor) * u128::from(modulus[0]);
            let mut carry = sum >> 64;
            for j in 1..4 {
                let sum = u128::from(t[j]) + u128::from(factor) * u128::from(modulus[j]) + carry;
                t[j - 1] = sum as u64;
                carry = sum >> 64;
            }
            let sum = u128::from(t[4]) + carry;
            t[3] = sum as u64;
            t[4] = t[5] + (sum >> 64) as u64;
        }

        // Final: subtract m when t >= m, judged on the five-word value.
        let value = [t[0], t[1], t[2], t[3]];
        let (reduced, borrow) = U256(value).sub_with_borrow(self.value);
        let use_reduced = Mask::from_bit(t[4]).or(Mask::from_bit(borrow).not());
        array::from_fn(|i| use_reduced.select(reduced.0[i], value[i]))
    }

    /// The Montgomery form a R mod m of a canonical value.
    pub(super) fn encode(&self, a: [u64; 4]) -> [u64; 4] {
        // mont(a, R^2) = a R^2 / R = a R.
        self.mul(a, self.r_squared)
    }

    /// The canonical value a of a Montgomery form a R mod m.
    pub(super) fn decode(&self, a: [u64; 4]) -> [u64; 4] {
        // mont(a R, 1) = a R / R = a.
        self.mul(a, [1, 0, 0, 0])
    }

    /// The power base^e of a Montgomery-form base, for a public exponent.
    ///
    /// # Algorithm
    ///
    /// Fixed 4-bit windows, high to low.
    ///
    /// ```text
    /// table[j] = base^j          for j = 0..15
    /// x = x^16 * table[digit]    for each 4-bit digit of e
    /// ```
    ///
    /// Every window costs four squarings and one product, and the table index is the public digit.
    /// The time therefore depends on the exponent only, never on the base.
    pub(super) fn pow(&self, base: [u64; 4], exponent: U256) -> [u64; 4] {
        // Phase 1: powers of the base, with R mod m standing for 1.
        let one = self.encode_one();
        let mut table = [one; 16];
        for j in 1..16 {
            table[j] = self.mul(table[j - 1], base);
        }

        // Phase 2: 64 windows, high to low.
        let mut x = one;
        for window in (0..64).rev() {
            for _ in 0..4 {
                x = self.mul(x, x);
            }
            let digit = (exponent.0[window / 16] >> ((window % 16) * 4)) & 0xf;
            x = self.mul(x, table[digit as usize]);
        }
        x
    }

    /// The Montgomery form of 1, which is R mod m.
    pub(super) fn encode_one(&self) -> [u64; 4] {
        self.encode([1, 0, 0, 0])
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// The P-256 group order, a modulus whose top limb is far below 2^64.
    const ORDER: Modulus = Modulus::new(U256([
        0xf3b9_cac2_fc63_2551,
        0xbce6_faad_a717_9e84,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_0000_0000,
    ]));

    /// A small odd modulus, so a u128 reference can check every product.
    const SMALL: Modulus = Modulus::new(U256([0xffff_ffff_ffff_ffc5, 0, 0, 0]));

    #[test]
    fn constants() {
        // -m^-1 times m is -1 modulo 2^64.
        assert_eq!(ORDER.inverse.wrapping_mul(ORDER.value.0[0]), u64::MAX);

        // R^2 maps 1 to R, and R back to 1.
        let one = ORDER.encode_one();
        assert_eq!(ORDER.decode(one), [1, 0, 0, 0]);
        assert_eq!(one, ORDER.encode_const([1, 0, 0, 0]));
    }

    proptest! {
        #[test]
        fn products_match_wide_integers(a in any::<u64>(), b in any::<u64>()) {
            // Against u128 arithmetic modulo a 64-bit prime.
            let m = SMALL.value.0[0];
            let (a, b) = (a % m, b % m);
            let expected = (u128::from(a) * u128::from(b) % u128::from(m)) as u64;
            let product = SMALL.decode(
                SMALL.mul(SMALL.encode([a, 0, 0, 0]), SMALL.encode([b, 0, 0, 0])),
            );
            prop_assert_eq!(product, [expected, 0, 0, 0]);

            // The sum and difference too.
            let sum = (u128::from(a) + u128::from(b)) % u128::from(m);
            prop_assert_eq!(SMALL.add([a, 0, 0, 0], [b, 0, 0, 0]), [sum as u64, 0, 0, 0]);
            let difference = (u128::from(a) + u128::from(m) - u128::from(b)) % u128::from(m);
            prop_assert_eq!(SMALL.sub([a, 0, 0, 0], [b, 0, 0, 0]), [difference as u64, 0, 0, 0]);
        }

        #[test]
        fn encoding_matches_doubling(limbs in any::<[u64; 4]>()) {
            // The product by R^2 and 256 modular doublings agree on any canonical value.
            if ORDER.contains(U256(limbs)).reveal() {
                prop_assert_eq!(ORDER.encode(limbs), ORDER.encode_const(limbs));
                prop_assert_eq!(ORDER.decode(ORDER.encode(limbs)), limbs);
            }
        }

        #[test]
        fn powers_add_exponents(a in any::<u64>(), e in any::<u32>(), f in any::<u32>()) {
            // base^e * base^f = base^(e + f).
            let base = ORDER.encode([a, 0, 0, 0]);
            let product = ORDER.mul(
                ORDER.pow(base, U256([u64::from(e), 0, 0, 0])),
                ORDER.pow(base, U256([u64::from(f), 0, 0, 0])),
            );
            let sum = ORDER.pow(base, U256([u64::from(e) + u64::from(f), 0, 0, 0]));
            prop_assert_eq!(product, sum);
        }
    }
}
