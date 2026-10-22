//! Montgomery arithmetic modulo an odd integer of run-time width, for RSA moduli and primes.

use super::bignum::BigUint;
use crate::ct::Mask;

/// An odd modulus m of k limbs with its Montgomery constants for R = 2^(64 k).
///
/// # Overview
///
/// A residue a is held as a R mod m, so a product needs no division by m.
///
/// ```text
/// mont(a R, b R) = a R * b R / R = (a b) R   (mod m)
/// ```
///
/// Every residue passed in or out is canonical in [0, m) and k limbs wide.
///
/// # Timing
///
/// Every operation runs in time that depends on k only, except the one named vartime.
/// The constants come from long division and fixed-exponent powers, so secret primes are safe here.
#[derive(Clone, Debug)]
pub(super) struct Modulus {
    /// The modulus m.
    value: BigUint,
    /// The word -m^-1 mod 2^64, which cancels the low word in each reduction step.
    inverse: u64,
    /// R mod m, the Montgomery form of 1.
    one: BigUint,
    /// R^2 mod m, which maps a plain value into Montgomery form.
    r_squared: BigUint,
    /// R^3 mod m, which maps the output of a wide reduction into Montgomery form.
    r_cubed: BigUint,
}

impl Modulus {
    /// The constants of an odd modulus above 1, in the modulus's width.
    pub(super) fn new(value: BigUint) -> Self {
        debug_assert!(value.is_odd(), "Montgomery reduction needs an odd modulus");
        let width = value.width();

        // R mod m by long division of 2^(64 k).
        let mut power = BigUint::zero(width + 1);
        power.limbs_mut()[width] = 1;
        let one = power.rem(&value);

        let mut modulus = Self {
            inverse: Self::negated_inverse(value.limbs()[0]),
            one,
            r_squared: BigUint::zero(width),
            r_cubed: BigUint::zero(width),
            value,
        };

        // R^2 is the Montgomery form of R = 2^(64 k), so it is (2 R)^(64 k) in Montgomery arithmetic.
        // The exponent is public, so the power's time depends on the width only.
        let two = modulus.add(&modulus.one, &modulus.one);
        let exponent = BigUint::from_u64(64 * width as u64, 1);
        modulus.r_squared = modulus.pow_vartime(&two, &exponent);

        // mont(R^2, R^2) = R^4 / R = R^3.
        modulus.r_cubed = modulus.mul(&modulus.r_squared, &modulus.r_squared);
        modulus
    }

    /// The word -m^-1 mod 2^64 for odd m, by Newton iteration.
    const fn negated_inverse(low: u64) -> u64 {
        // Each step doubles the correct low bits: 1, 2, 4, 8, 16, 32, 64.
        //
        //     inv * m = 1 mod 2^j  ->  inv (2 - m inv) * m = 1 mod 2^(2j)
        let mut inv = 1_u64;
        let mut step = 0;
        while step < 6 {
            inv = inv.wrapping_mul(2_u64.wrapping_sub(low.wrapping_mul(inv)));
            step += 1;
        }
        inv.wrapping_neg()
    }

    /// The modulus as an integer.
    pub(super) const fn value(&self) -> &BigUint {
        &self.value
    }

    /// The number of limbs k.
    pub(super) const fn width(&self) -> usize {
        self.value.width()
    }

    /// The Montgomery form of 1, which is R mod m.
    pub(super) const fn one(&self) -> &BigUint {
        &self.one
    }

    /// The sum modulo m.
    pub(super) fn add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        // The true sum may reach 2m - 2, which can exceed 2^(64 k).
        let mut sum = a.clone();
        let carry = sum.add_assign(b);

        // Subtract m once and keep that result when the sum reached m.
        //
        //     carry out of the add        -> sum >= 2^(64 k) > m
        //     no borrow out of sum - m    -> sum >= m
        let mut reduced = sum.clone();
        let borrow = reduced.sub_assign(&self.value);
        sum.assign_if(
            Mask::from_bit(carry).or(Mask::from_bit(borrow).not()),
            &reduced,
        );
        sum
    }

    /// The difference modulo m.
    pub(super) fn sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        // A borrow means the result wrapped to a - b + 2^(64 k): adding m back wraps it home.
        let mut difference = a.clone();
        let borrow = difference.sub_assign(b);
        let mut corrected = difference.clone();
        corrected.add_assign(&self.value);
        difference.assign_if(Mask::from_bit(borrow), &corrected);
        difference
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
    /// With a, b < m, each pass keeps t < 2m, so t fits in k + 1 words.
    /// One masked subtraction then brings it under m, with no branch on the values.
    pub(super) fn mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        let k = self.width();
        let modulus = self.value.limbs();
        let a = a.limbs();

        // k + 2 words: k for t, one for its carry, one spare for the row's overflow.
        let mut scratch = BigUint::zero(k + 2);
        let t = scratch.limbs_mut();
        for &bi in b.limbs() {
            // Row: t += a * b_i.
            // Each step fits 128 bits: (2^64 - 1)^2 + 2 (2^64 - 1) = 2^128 - 1.
            let mut carry = 0_u128;
            for j in 0..k {
                let sum = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + carry;
                t[j] = sum as u64;
                carry = sum >> 64;
            }
            let sum = u128::from(t[k]) + carry;
            t[k] = sum as u64;
            t[k + 1] = (sum >> 64) as u64;

            // Reduction: t += f m makes the low word zero.
            // Then shift down one word.
            let factor = t[0].wrapping_mul(self.inverse);
            let sum = u128::from(t[0]) + u128::from(factor) * u128::from(modulus[0]);
            let mut carry = sum >> 64;
            for j in 1..k {
                let sum = u128::from(t[j]) + u128::from(factor) * u128::from(modulus[j]) + carry;
                t[j - 1] = sum as u64;
                carry = sum >> 64;
            }
            let sum = u128::from(t[k]) + carry;
            t[k - 1] = sum as u64;
            t[k] = t[k + 1] + (sum >> 64) as u64;
        }
        self.reduce_once(&scratch)
    }

    /// The value of t mod m for t < 2m, read from its low k + 1 words.
    fn reduce_once(&self, t: &BigUint) -> BigUint {
        let k = self.width();
        let mut value = BigUint::zero(k);
        value.limbs_mut().copy_from_slice(&t.limbs()[..k]);

        // Subtract m when t >= m, judged on the k + 1 word value.
        let mut reduced = value.clone();
        let borrow = reduced.sub_assign(&self.value);
        let use_reduced = Mask::from_bit(t.limbs()[k]).or(Mask::from_bit(borrow).not());
        value.assign_if(use_reduced, &reduced);
        value
    }

    /// The Montgomery form a R mod m of any value a below m R, at most 2k limbs wide.
    ///
    /// # Algorithm
    ///
    /// Montgomery reduction of the wide value, then one product by R^3.
    ///
    /// ```text
    /// redc(a)          = a R^-1 mod m
    /// mont(a R^-1, R^3) = a R^-1 R^3 R^-1 = a R
    /// ```
    ///
    /// No division by m happens, so the time depends on the widths only.
    /// RSA signing reduces its input modulo each secret prime this way.
    pub(super) fn reduce(&self, wide: &BigUint) -> BigUint {
        self.mul(&self.redc(wide), &self.r_cubed)
    }

    /// Montgomery reduction a R^-1 mod m of a value a below m R, at most 2k limbs wide.
    ///
    /// # Invariants
    ///
    /// Adding f_i m 2^(64 i) for i < k keeps the running value below m R + m R = 2 m R.
    /// After dividing by R it is below 2m, so one masked subtraction finishes it.
    fn redc(&self, wide: &BigUint) -> BigUint {
        let k = self.width();
        debug_assert!(wide.width() <= 2 * k, "the input fits 2k limbs");
        let modulus = self.value.limbs();

        let mut scratch = BigUint::zero(2 * k + 1);
        let t = scratch.limbs_mut();
        t[..wide.width()].copy_from_slice(wide.limbs());
        for i in 0..k {
            // Clear word i by adding f m 2^(64 i), then carry through every word above.
            let factor = t[i].wrapping_mul(self.inverse);
            let mut carry = 0_u128;
            for j in 0..k {
                let sum =
                    u128::from(t[i + j]) + u128::from(factor) * u128::from(modulus[j]) + carry;
                t[i + j] = sum as u64;
                carry = sum >> 64;
            }
            for limb in &mut t[i + k..] {
                let sum = u128::from(*limb) + carry;
                *limb = sum as u64;
                carry = sum >> 64;
            }
        }

        // The low k words are zero: the value is t / R, in words k to 2k.
        let mut high = BigUint::zero(k + 1);
        high.limbs_mut().copy_from_slice(&scratch.limbs()[k..]);
        self.reduce_once(&high)
    }

    /// The Montgomery form a R mod m of a value below m.
    pub(super) fn encode(&self, a: &BigUint) -> BigUint {
        // mont(a, R^2) = a R^2 / R = a R.
        self.mul(a, &self.r_squared)
    }

    /// The value a of a Montgomery form a R mod m.
    pub(super) fn decode(&self, a: &BigUint) -> BigUint {
        // mont(a R, 1) = a R / R = a.
        self.mul(a, &BigUint::from_u64(1, self.width()))
    }

    /// The power of a Montgomery-form base to a public exponent, in Montgomery form.
    ///
    /// Left-to-right square-and-multiply: the exponent's bits steer the products.
    /// The time depends on the exponent, never on the base.
    pub(super) fn pow_vartime(&self, base: &BigUint, exponent: &BigUint) -> BigUint {
        let mut x = self.one.clone();
        for position in (0..exponent.bits_vartime()).rev() {
            x = self.mul(&x, &x);
            if exponent.bit(position) == 1 {
                x = self.mul(&x, base);
            }
        }
        x
    }

    /// The power of a Montgomery-form base to a secret exponent, in Montgomery form, in constant time.
    ///
    /// # Algorithm
    ///
    /// Fixed 4-bit windows over every limb of the exponent, high to low.
    ///
    /// ```text
    /// table[j] = base^j            for j = 0..15
    /// x = x^16 * table[d_i]        for each 4-bit digit d_i of e
    /// ```
    ///
    /// Every window costs four squarings, one full table scan, and one product, even for a zero digit.
    /// The scan blends each entry under a mask, so the digit picks no address.
    /// The time depends on the widths of the modulus and the exponent only.
    pub(super) fn pow(&self, base: &BigUint, exponent: &BigUint) -> BigUint {
        // Phase 1: powers of the base, with R mod m standing for 1.
        let mut table = Vec::with_capacity(16);
        table.push(self.one.clone());
        for j in 1..16 {
            table.push(self.mul(&table[j - 1], base));
        }

        // Phase 2: sixteen windows per limb, high to low.
        let mut x = self.one.clone();
        let mut entry = BigUint::zero(self.width());
        for window in (0..16 * exponent.width()).rev() {
            for _ in 0..4 {
                x = self.mul(&x, &x);
            }
            let digit = exponent.nibble(window);
            for (j, candidate) in (0..).zip(&table) {
                entry.assign_if(Mask::equal(digit, j), candidate);
            }
            x = self.mul(&x, &entry);
        }
        x
    }
}

#[cfg(test)]
mod tests {
    use proptest::{collection, prelude::*};

    use super::*;

    /// An odd modulus of one to five limbs, at least 3, with a non-zero top limb.
    fn arb_modulus() -> impl Strategy<Value = BigUint> {
        collection::vec(any::<u64>(), 1..=5).prop_map(|mut limbs| {
            let top = limbs.len() - 1;
            limbs[top] |= 1 << (limbs[top] % 64);
            limbs[0] |= 1;
            if limbs.len() == 1 {
                limbs[0] |= 3;
            }
            let bytes: Vec<u8> = limbs
                .iter()
                .rev()
                .flat_map(|limb| limb.to_be_bytes())
                .collect();
            BigUint::from_be_bytes(&bytes, limbs.len()).unwrap()
        })
    }

    /// A value of 2k limbs, reduced modulo m by long division.
    fn residue(modulus: &BigUint, seed: &[u64]) -> BigUint {
        let width = 2 * modulus.width();
        let limbs: Vec<u64> = seed.iter().copied().cycle().take(width).collect();
        let bytes: Vec<u8> = limbs
            .iter()
            .rev()
            .flat_map(|limb| limb.to_be_bytes())
            .collect();
        BigUint::from_be_bytes(&bytes, width).unwrap().rem(modulus)
    }

    /// The power by square-and-multiply on plain values, with long division after each product.
    fn pow_reference(modulus: &BigUint, base: &BigUint, exponent: &BigUint) -> BigUint {
        let mut acc = BigUint::from_u64(1, 1).rem(modulus);
        for position in (0..64 * exponent.width()).rev() {
            acc = acc.mul(&acc).rem(modulus);
            if exponent.bit(position) == 1 {
                acc = acc.mul(base).rem(modulus);
            }
        }
        acc
    }

    #[test]
    fn constants_of_a_one_limb_modulus() {
        // m = 2^64 - 59, a prime: R mod m = 59, and R^2 mod m = 59^2.
        let m = Modulus::new(BigUint::from_u64(u64::MAX - 58, 1));
        assert_eq!(m.one().limbs(), &[59]);
        assert_eq!(m.r_squared.limbs(), &[59 * 59]);
        assert_eq!(m.r_cubed.limbs(), &[59 * 59 * 59]);
        assert_eq!(m.inverse.wrapping_mul(u64::MAX - 58), u64::MAX);
    }

    #[test]
    fn wide_reduction_at_the_bound() {
        // m R - 1 is the largest value the reduction accepts, and it is -1 mod m.
        // Fixture: m = 2^64 - 59 in one limb, so m R - 1 = (m - 1) 2^64 + 2^64 - 1.
        let m = Modulus::new(BigUint::from_u64(u64::MAX - 58, 1));
        let mut wide = BigUint::zero(2);
        wide.limbs_mut().copy_from_slice(&[u64::MAX, u64::MAX - 59]);
        assert_eq!(
            m.decode(&m.reduce(&wide)),
            BigUint::from_u64(u64::MAX - 59, 1)
        );
    }

    proptest! {
        #[test]
        fn product_matches_schoolbook_then_division(
            modulus in arb_modulus(),
            a in collection::vec(any::<u64>(), 1..=10),
            b in collection::vec(any::<u64>(), 1..=10),
        ) {
            // decode(mont(encode a, encode b)) = a b mod m, by long division of the full product.
            let m = Modulus::new(modulus.clone());
            let (a, b) = (residue(&modulus, &a), residue(&modulus, &b));
            let product = m.decode(&m.mul(&m.encode(&a), &m.encode(&b)));
            prop_assert_eq!(product, a.mul(&b).rem(&modulus));

            // The sum and difference agree with plain arithmetic too.
            let sum = m.add(&a, &b);
            let mut back = m.sub(&sum, &b);
            prop_assert_eq!(&back, &a);
            back = m.sub(&a, &a);
            prop_assert_eq!(back, BigUint::zero(modulus.width()));
        }

        #[test]
        fn wide_reduction_matches_division(
            modulus in arb_modulus(),
            seed in collection::vec(any::<u64>(), 1..=10),
        ) {
            // Any value below m R reduces to its remainder, in Montgomery form.
            // The product of two residues is below m^2 < m R.
            let m = Modulus::new(modulus.clone());
            let a = residue(&modulus, &seed);
            let wide = a.mul(&a);
            prop_assert_eq!(m.decode(&m.reduce(&wide)), wide.rem(&modulus));
        }

        #[test]
        fn powers_match_square_and_multiply(
            modulus in arb_modulus(),
            seed in collection::vec(any::<u64>(), 1..=10),
            exponent in collection::vec(any::<u64>(), 1..=2),
        ) {
            // The constant-time windows, the variable-time ladder, and the plain reference agree.
            let m = Modulus::new(modulus.clone());
            let base = residue(&modulus, &seed);
            let bytes: Vec<u8> = exponent.iter().rev().flat_map(|limb| limb.to_be_bytes()).collect();
            let exponent = BigUint::from_be_bytes(&bytes, exponent.len()).unwrap();
            let expected = pow_reference(&modulus, &base, &exponent);
            let encoded = m.encode(&base);
            prop_assert_eq!(&m.decode(&m.pow(&encoded, &exponent)), &expected);
            prop_assert_eq!(&m.decode(&m.pow_vartime(&encoded, &exponent)), &expected);
        }
    }
}
