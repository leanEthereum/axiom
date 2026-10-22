//! The KoalaBear prime field, of order p = 2^31 - 2^24 + 1.
//!
//! # Overview
//!
//! Elements live in Montgomery form: a stores a * 2^32 mod p.
//! A product then needs one 64-bit multiply and one Montgomery reduction, with no division.
//!
//! The prime suits the hash for three reasons.
//!
//! - It fits 31 bits, so a sum of two elements fits a 32-bit word.
//! - p - 1 = 127 * 2^24, so gcd(3, p - 1) = 1 and x^3 permutes the field: the cheapest S-box.
//! - p = 127 * 8^8 + 1, so an element splits into eight uniform base-8 digits with tiny rejection.
//!
//! Every operation runs in constant time: reductions select with masks, never with branches.

use std::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Sub},
};

/// The field order p = 2^31 - 2^24 + 1.
const P: u32 = 0x7f00_0001;

/// The inverse of p modulo 2^32, by Newton iteration: each step doubles the correct low bits.
///
/// An odd p is its own inverse modulo 8, and four steps lift 3 correct bits past 32.
const P_INV: u32 = {
    let mut inverse = P;
    let mut step = 0;
    while step < 4 {
        inverse = inverse.wrapping_mul(2_u32.wrapping_sub(P.wrapping_mul(inverse)));
        step += 1;
    }
    inverse
};

/// 2^64 mod p, the Montgomery form of 2^32, which maps a plain residue into Montgomery form.
const R2: u32 = ((1_u128 << 64) % P as u128) as u32;

/// An element of the KoalaBear field.
///
/// # Invariants
///
/// The stored word is the Montgomery form a * 2^32 mod p, always below p.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct KoalaBear {
    /// The Montgomery form, below p.
    monty: u32,
}

impl KoalaBear {
    /// The field order p = 2^31 - 2^24 + 1.
    pub const ORDER: u32 = P;

    /// The additive identity.
    pub const ZERO: Self = Self { monty: 0 };

    /// The multiplicative identity.
    pub const ONE: Self = Self::new(1);

    /// The element congruent to a 32-bit word.
    ///
    /// Any word is accepted: 2^32 < 3p, so two masked subtractions reduce it.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self::from_residue(reduce_word(value))
    }

    /// The element with this canonical value, or none when the value is not below p.
    #[must_use]
    pub const fn from_canonical(value: u32) -> Option<Self> {
        if value < P {
            Some(Self::from_residue(value))
        } else {
            None
        }
    }

    /// The element congruent to a 128-bit integer.
    ///
    /// # Algorithm
    ///
    /// Horner's rule over the four 32-bit limbs, most significant first.
    ///
    /// ```text
    /// x = ((l_3 * 2^32 + l_2) * 2^32 + l_1) * 2^32 + l_0
    /// ```
    ///
    /// Every step is a field multiply and add, so a secret input never meets a division.
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        let shift = Self::new(1 << 31).sum(Self::new(1 << 31));
        let mut acc = Self::ZERO;
        let mut limb = 4;
        while limb > 0 {
            limb -= 1;
            acc = acc
                .product(shift)
                .sum(Self::new((value >> (32 * limb)) as u32));
        }
        acc
    }

    /// The element whose Montgomery form is a word below p.
    ///
    /// A uniform word below p gives a uniform element, which key generation relies on.
    pub(crate) const fn from_montgomery(monty: u32) -> Option<Self> {
        if monty < P {
            Some(Self { monty })
        } else {
            None
        }
    }

    /// The element of a plain residue below p.
    const fn from_residue(residue: u32) -> Self {
        // residue * 2^64 * 2^-32 = residue * 2^32, the Montgomery form.
        Self {
            monty: montgomery_reduce(residue as u64 * R2 as u64),
        }
    }

    /// The element whose Montgomery form is a 64-bit sum of Montgomery forms.
    ///
    /// # Invariants
    ///
    /// The sum must stay below p * 2^32, about 2^63.
    pub(crate) const fn from_montgomery_sum(sum: u64) -> Self {
        // The sum is already the Montgomery form, up to reduction modulo p.
        //
        //     reduce(sum)          = sum * 2^-32
        //     reduce(that * 2^64)  = sum * 2^-32 * 2^64 * 2^-32 = sum
        Self {
            monty: montgomery_reduce(montgomery_reduce(sum) as u64 * R2 as u64),
        }
    }

    /// The canonical value, below p.
    #[must_use]
    pub const fn to_canonical(self) -> u32 {
        montgomery_reduce(self.monty as u64)
    }

    /// The Montgomery form.
    pub(crate) const fn montgomery(self) -> u32 {
        self.monty
    }

    /// The sum, usable in constants.
    const fn sum(self, other: Self) -> Self {
        // Both forms are below 2^31, so the sum fits a word.
        Self {
            monty: reduce_once(self.monty + other.monty),
        }
    }

    /// The difference, usable in constants.
    const fn difference(self, other: Self) -> Self {
        // A borrow means the difference went negative: add p back, selected by a mask.
        let (difference, borrow) = self.monty.overflowing_sub(other.monty);
        Self {
            monty: difference.wrapping_add(P & mask(borrow)),
        }
    }

    /// The product, usable in constants.
    const fn product(self, other: Self) -> Self {
        // (a * 2^32) * (b * 2^32) * 2^-32 = (a * b) * 2^32.
        Self {
            monty: montgomery_reduce(self.monty as u64 * other.monty as u64),
        }
    }

    /// The cube, the S-box of the hash.
    #[must_use]
    pub const fn cube(self) -> Self {
        self.product(self).product(self)
    }

    /// The multiplicative inverse, none for zero.
    ///
    /// Fermat's little theorem gives x^(p - 2) = x^-1.
    /// The exponent is public, but the square-and-multiply chain is for public data only.
    #[must_use]
    pub(crate) fn inverse(self) -> Option<Self> {
        if self == Self::ZERO {
            return None;
        }
        let (mut result, mut base, mut exponent) = (Self::ONE, self, P - 2);
        while exponent > 0 {
            if exponent & 1 == 1 {
                result *= base;
            }
            base *= base;
            exponent >>= 1;
        }
        Some(result)
    }
}

/// An all-ones word when the flag holds, zero otherwise.
const fn mask(flag: bool) -> u32 {
    0_u32.wrapping_sub(flag as u32)
}

/// Subtracts p once when the word is at least p, for words below 2p.
const fn reduce_once(word: u32) -> u32 {
    // The subtraction borrows exactly when the word is below p, and then the word is kept.
    let (difference, borrow) = word.overflowing_sub(P);
    difference.wrapping_add(P & mask(borrow))
}

/// Reduces any word below p, with two masked subtractions.
const fn reduce_word(word: u32) -> u32 {
    // A word below 2^32 = 2p + (2^25 - 2) needs at most two subtractions.
    // The first subtracts p only when the word is at least 2p, keeping the second's input below 2p.
    let (above_twice, borrow) = word.overflowing_sub(2 * P);
    let word = above_twice.wrapping_add((2 * P) & mask(borrow));
    reduce_once(word)
}

/// Montgomery reduction: x * 2^-32 mod p, for x below p * 2^32.
///
/// # Algorithm
///
/// Montgomery, "Modular multiplication without trial division", 1985.
///
/// ```text
/// t = (x mod 2^32) * p^-1 mod 2^32
/// x - t * p is divisible by 2^32, and lies in (-p * 2^32, p * 2^32)
/// ```
///
/// The quotient by 2^32 lands in (-p, p), and a masked addition of p fixes a negative one.
const fn montgomery_reduce(x: u64) -> u32 {
    let t = (x as u32).wrapping_mul(P_INV);
    let (difference, borrow) = x.overflowing_sub(t as u64 * P as u64);
    ((difference >> 32) as u32).wrapping_add(P & mask(borrow))
}

impl fmt::Debug for KoalaBear {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_canonical())
    }
}

impl Add for KoalaBear {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self.sum(other)
    }
}

impl AddAssign for KoalaBear {
    fn add_assign(&mut self, other: Self) {
        *self = self.sum(other);
    }
}

impl Sub for KoalaBear {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self.difference(other)
    }
}

impl Mul for KoalaBear {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        self.product(other)
    }
}

impl MulAssign for KoalaBear {
    fn mul_assign(&mut self, other: Self) {
        *self = self.product(other);
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// An element from its canonical value, reduced with plain integer arithmetic.
    fn reference(value: u64) -> u32 {
        (value % u64::from(P)) as u32
    }

    #[test]
    fn constants() {
        // p * p^-1 = 1 modulo 2^32, and 2^64 mod p from plain arithmetic.
        assert_eq!(P.wrapping_mul(P_INV), 1);
        assert_eq!(R2, ((1_u128 << 64) % u128::from(P)) as u32);

        // p - 1 = 127 * 2^24, so x^3 is a permutation of the field.
        assert_eq!(P - 1, 127 << 24);
        assert_eq!(P, 127 * 8_u32.pow(8) + 1);
    }

    #[test]
    fn boundaries() {
        // Zero, one, p - 1, p, 2p, and the largest word.
        assert_eq!(KoalaBear::new(0), KoalaBear::ZERO);
        assert_eq!(KoalaBear::new(1).to_canonical(), 1);
        assert_eq!(KoalaBear::new(P - 1).to_canonical(), P - 1);
        assert_eq!(KoalaBear::new(P), KoalaBear::ZERO);
        assert_eq!(KoalaBear::new(2 * P), KoalaBear::ZERO);
        assert_eq!(
            KoalaBear::new(u32::MAX).to_canonical(),
            reference(u64::from(u32::MAX))
        );

        // p - 1 is -1: it squares to one and adds to one to make zero.
        let minus_one = KoalaBear::new(P - 1);
        assert_eq!(minus_one * minus_one, KoalaBear::ONE);
        assert_eq!(minus_one + KoalaBear::ONE, KoalaBear::ZERO);
        assert_eq!(KoalaBear::ZERO - KoalaBear::ONE, minus_one);

        // Canonical parsing accepts p - 1 and refuses p.
        assert_eq!(KoalaBear::from_canonical(P - 1), Some(minus_one));
        assert_eq!(KoalaBear::from_canonical(P), None);
        assert_eq!(KoalaBear::from_montgomery(P), None);
    }

    proptest! {
        #[test]
        fn arithmetic_matches_integers(a in 0..P, b in 0..P) {
            let (x, y) = (KoalaBear::new(a), KoalaBear::new(b));
            let (a, b) = (u64::from(a), u64::from(b));
            prop_assert_eq!((x + y).to_canonical(), reference(a + b));
            prop_assert_eq!((x - y).to_canonical(), reference(a + u64::from(P) - b));
            prop_assert_eq!((x * y).to_canonical(), reference(a * b));
            prop_assert_eq!(x.cube().to_canonical(), reference(u64::from(reference(a * a)) * a));
        }

        #[test]
        fn any_word_and_any_u128_reduce(word: u32, wide: u128) {
            prop_assert_eq!(KoalaBear::new(word).to_canonical(), reference(u64::from(word)));
            prop_assert_eq!(
                KoalaBear::from_u128(wide).to_canonical(),
                (wide % u128::from(P)) as u32
            );
        }

        #[test]
        fn montgomery_sums_reduce(terms in prop::collection::vec(0..P, 0..4)) {
            // Up to 3 forms below p sum far below p * 2^32.
            let sum: u64 = terms.iter().map(|&t| u64::from(KoalaBear::new(t).montgomery())).sum();
            let expected = terms.iter().fold(KoalaBear::ZERO, |acc, &t| acc + KoalaBear::new(t));
            prop_assert_eq!(KoalaBear::from_montgomery_sum(sum), expected);
        }
    }
}
