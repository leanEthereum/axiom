//! Montgomery arithmetic modulo an odd integer below 2^384, shared by the field and the scalars.

use std::array;

use crate::{ct::Mask, uint::U384};

/// An odd modulus m below 2^384 with its Montgomery constants for R = 2^384.
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
    value: U384,
    /// The word -m^-1 mod 2^64, which cancels the low word in each reduction step.
    inverse: u64,
    /// R^2 mod m, which maps a plain value into Montgomery form.
    r_squared: [u64; 6],
}

impl Modulus {
    /// The constants of an odd modulus, computed at compile time.
    pub(super) const fn new(value: U384) -> Self {
        let mut modulus = Self {
            value,
            inverse: Self::negated_inverse(value.0[0]),
            r_squared: [0; 6],
        };
        // R^2 mod m: 1 doubled 768 times.
        modulus.r_squared = modulus.doubled_times([1, 0, 0, 0, 0, 0], 768);
        modulus
    }

    /// The modulus as an integer.
    pub(super) const fn value(&self) -> U384 {
        self.value
    }

    /// The Montgomery form a R mod m of a canonical value, at compile time.
    ///
    /// It doubles 384 times, never calling the product, so it also checks the product.
    pub(super) const fn encode_const(&self, value: [u64; 6]) -> [u64; 6] {
        self.doubled_times(value, 384)
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
    const fn doubled_times(&self, value: [u64; 6], k: u32) -> [u64; 6] {
        let m = self.value.0;
        let mut r = value;
        let mut step = 0;
        while step < k {
            // Double, then subtract m when the doubled value reaches m or overflows 2^384.
            let overflow = r[5] >> 63;
            let mut i = 5;
            while i > 0 {
                r[i] = (r[i] << 1) | (r[i - 1] >> 63);
                i -= 1;
            }
            r[0] <<= 1;
            let mut reduced = [0_u64; 6];
            let mut borrow = 0_u64;
            let mut i = 0;
            while i < 6 {
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
    pub(super) fn contains(&self, value: U384) -> bool {
        // The value is canonical exactly when subtracting m borrows.
        let (_, borrow) = value.sub_with_borrow(self.value);
        borrow == 1
    }

    /// The sum modulo m.
    pub(super) fn add(&self, a: [u64; 6], b: [u64; 6]) -> [u64; 6] {
        // The true sum may reach 2m - 2, which exceeds 2^384 when m > 2^383.
        let (sum, carry) = U384(a).add_with_carry(U384(b));

        // Subtract m once and keep that result when the sum reached m.
        //
        //     carry out of the add        -> sum >= 2^384 > m
        //     no borrow out of sum - m    -> sum >= m
        let (reduced, borrow) = sum.sub_with_borrow(self.value);
        let use_reduced = Mask::from_bit(carry).or(Mask::from_bit(borrow).not());
        array::from_fn(|i| use_reduced.select(reduced.0[i], sum.0[i]))
    }

    /// The difference modulo m.
    pub(super) fn sub(&self, a: [u64; 6], b: [u64; 6]) -> [u64; 6] {
        // A borrow means the result wrapped to a - b + 2^384: add m back modulo 2^384.
        let (difference, borrow) = U384(a).sub_with_borrow(U384(b));
        let wrapped = Mask::from_bit(borrow);
        let correction = U384(self.value.0.map(|limb| wrapped.select(limb, 0)));
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
    /// With a, b < m, each pass keeps t < 2m, so t fits in seven words.
    /// One masked subtraction then brings it under m.
    pub(super) fn mul(&self, a: [u64; 6], b: [u64; 6]) -> [u64; 6] {
        let modulus = self.value.0;

        // Eight words: six for t, one for its carry, one spare for the row's overflow.
        let mut t = [0_u64; 8];
        for &bi in &b {
            // Row: t += a * b_i.
            // Each step fits 128 bits: (2^64 - 1)^2 + 2 (2^64 - 1) = 2^128 - 1.
            let mut carry = 0_u128;
            for j in 0..6 {
                let sum = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + carry;
                t[j] = sum as u64;
                carry = sum >> 64;
            }
            let sum = u128::from(t[6]) + carry;
            t[6] = sum as u64;
            t[7] = (sum >> 64) as u64;

            // Reduction: t += f m makes the low word zero.
            // Then shift down one word.
            let factor = t[0].wrapping_mul(self.inverse);
            let sum = u128::from(t[0]) + u128::from(factor) * u128::from(modulus[0]);
            let mut carry = sum >> 64;
            for j in 1..6 {
                let sum = u128::from(t[j]) + u128::from(factor) * u128::from(modulus[j]) + carry;
                t[j - 1] = sum as u64;
                carry = sum >> 64;
            }
            let sum = u128::from(t[6]) + carry;
            t[5] = sum as u64;
            t[6] = t[7] + (sum >> 64) as u64;
        }

        // Final: subtract m when t >= m, judged on the seven-word value.
        let value = [t[0], t[1], t[2], t[3], t[4], t[5]];
        let (reduced, borrow) = U384(value).sub_with_borrow(self.value);
        let use_reduced = Mask::from_bit(t[6]).or(Mask::from_bit(borrow).not());
        array::from_fn(|i| use_reduced.select(reduced.0[i], value[i]))
    }

    /// The Montgomery form a R mod m of a canonical value.
    pub(super) fn encode(&self, a: [u64; 6]) -> [u64; 6] {
        // mont(a, R^2) = a R^2 / R = a R.
        self.mul(a, self.r_squared)
    }

    /// The canonical value a of a Montgomery form a R mod m.
    pub(super) fn decode(&self, a: [u64; 6]) -> [u64; 6] {
        // mont(a R, 1) = a R / R = a.
        self.mul(a, [1, 0, 0, 0, 0, 0])
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
    /// Every window costs four squarings and one product.
    /// The exponent indexes the table, so it must be public.
    pub(super) fn pow(&self, base: [u64; 6], exponent: U384) -> [u64; 6] {
        // Phase 1: powers of the base, with R mod m standing for 1.
        let one = self.encode([1, 0, 0, 0, 0, 0]);
        let mut table = [one; 16];
        for j in 1..16 {
            table[j] = self.mul(table[j - 1], base);
        }

        // Phase 2: 96 windows, high to low.
        let mut x = one;
        for window in (0..96).rev() {
            for _ in 0..4 {
                x = self.mul(x, x);
            }
            let digit = (exponent.0[window / 16] >> ((window % 16) * 4)) & 0xf;
            x = self.mul(x, table[digit as usize]);
        }
        x
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// A small odd modulus, so a u128 reference can check every product.
    const SMALL: Modulus = Modulus::new(U384([0xffff_ffff_ffff_ffc5, 0, 0, 0, 0, 0]));

    /// The P-384 field prime, whose top limb is all ones.
    const PRIME: Modulus = Modulus::new(U384([
        0x0000_0000_ffff_ffff,
        0xffff_ffff_0000_0000,
        0xffff_ffff_ffff_fffe,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
    ]));

    #[test]
    fn constants() {
        // -m^-1 times m is -1 modulo 2^64.
        assert_eq!(PRIME.inverse.wrapping_mul(PRIME.value.0[0]), u64::MAX);

        // R^2 maps 1 to R, and R back to 1.
        let one = PRIME.encode([1, 0, 0, 0, 0, 0]);
        assert_eq!(PRIME.decode(one), [1, 0, 0, 0, 0, 0]);
        assert_eq!(one, PRIME.encode_const([1, 0, 0, 0, 0, 0]));
    }

    proptest! {
        #[test]
        fn products_match_wide_integers(a in any::<u64>(), b in any::<u64>()) {
            // Against u128 arithmetic modulo a 64-bit prime.
            let m = SMALL.value.0[0];
            let (a, b) = (a % m, b % m);
            let wide = |x: u64| [x, 0, 0, 0, 0, 0];
            let expected = (u128::from(a) * u128::from(b) % u128::from(m)) as u64;
            let product = SMALL.decode(SMALL.mul(SMALL.encode(wide(a)), SMALL.encode(wide(b))));
            prop_assert_eq!(product, wide(expected));

            // The sum and difference too.
            let sum = (u128::from(a) + u128::from(b)) % u128::from(m);
            prop_assert_eq!(SMALL.add(wide(a), wide(b)), wide(sum as u64));
            let difference = (u128::from(a) + u128::from(m) - u128::from(b)) % u128::from(m);
            prop_assert_eq!(SMALL.sub(wide(a), wide(b)), wide(difference as u64));
        }

        #[test]
        fn encoding_matches_doubling(limbs in any::<[u64; 6]>()) {
            // The product by R^2 and 384 modular doublings agree on any canonical value.
            if PRIME.contains(U384(limbs)) {
                prop_assert_eq!(PRIME.encode(limbs), PRIME.encode_const(limbs));
                prop_assert_eq!(PRIME.decode(PRIME.encode(limbs)), limbs);
            }
        }

        #[test]
        fn powers_add_exponents(a in any::<u64>(), e in any::<u32>(), f in any::<u32>()) {
            // base^e * base^f = base^(e + f).
            let base = PRIME.encode([a, 0, 0, 0, 0, 0]);
            let power = |k: u64| PRIME.pow(base, U384([k, 0, 0, 0, 0, 0]));
            let product = PRIME.mul(power(u64::from(e)), power(u64::from(f)));
            prop_assert_eq!(product, power(u64::from(e) + u64::from(f)));
        }
    }
}
