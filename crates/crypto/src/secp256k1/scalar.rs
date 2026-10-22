//! Arithmetic modulo the secp256k1 group order n.

use std::array;

use super::uint::{U256, U320};
use crate::ct::Mask;

/// The group order n in four little-endian 64-bit limbs, per SEC 2, section 2.4.1.
const N: [u64; 4] = [
    0xbfd2_5e8c_d036_4141,
    0xbaae_dce6_af48_a03b,
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
];

/// Half the order, rounded down: the largest s a low-s signature may carry.
const HALF_N: [u64; 4] = [
    0xdfe9_2f46_681b_20a0,
    0x5d57_6e73_57a4_501d,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
];

/// The Montgomery constant -n^-1 mod 2^64.
const N0_INV: u64 = montgomery_inverse(N[0]);

/// The Montgomery constant R^2 mod n for R = 2^256, which maps values into Montgomery form.
const R2: [u64; 4] = r_squared();

/// The exponent n - 2 of Fermat inversion, as little-endian limbs.
const N_MINUS_2: [u64; 4] = [N[0] - 2, N[1], N[2], N[3]];

/// Computes -m^-1 mod 2^64 for odd m by Newton iteration.
const fn montgomery_inverse(m: u64) -> u64 {
    // Each step doubles the correct low bits: 1, 2, 4, 8, 16, 32, 64.
    //
    //     inv * m = 1 mod 2^k  ->  inv (2 - m inv) * m = 1 mod 2^(2k)
    let mut inv = 1_u64;
    let mut step = 0;
    while step < 6 {
        inv = inv.wrapping_mul(2_u64.wrapping_sub(m.wrapping_mul(inv)));
        step += 1;
    }
    inv.wrapping_neg()
}

/// Computes 2^512 mod n by doubling 1 five hundred and twelve times.
const fn r_squared() -> [u64; 4] {
    let mut r = [1_u64, 0, 0, 0];
    let mut step = 0;
    while step < 512 {
        // Double, then subtract n when the doubled value reaches n or overflows.
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
            let (d1, b1) = r[i].overflowing_sub(N[i]);
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

/// An integer modulo n, always held in canonical form below n.
///
/// # Invariants
///
/// The limbs, read little-endian, encode a value in [0, n).
/// The scalar-multiplication proofs of exception-freedom rely on this bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) struct Scalar([u64; 4]);

impl Scalar {
    /// Zero.
    #[cfg(test)]
    pub(super) const ZERO: Self = Self([0; 4]);

    /// One.
    #[cfg(test)]
    pub(super) const ONE: Self = Self([1, 0, 0, 0]);

    /// The order n itself as an integer, for comparisons against field values.
    pub(super) const ORDER: U256 = U256(N);

    /// Decodes 32 big-endian bytes, refusing values at or above n.
    ///
    /// The check runs in constant time and reveals only its outcome.
    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        // Big-endian bytes to little-endian limbs, then the range check.
        let value = U256::from_be_bytes(bytes);
        let (_, borrow) = value.sub_with_borrow(Self::ORDER);
        Mask::from_bit(borrow).reveal().then_some(Self(value.0))
    }

    /// Decodes 32 big-endian bytes and reduces modulo n.
    ///
    /// The second value holds when a reduction happened, that is when the input was at least n.
    pub(super) fn from_bytes_reduced(bytes: &[u8; 32]) -> (Self, Mask) {
        // Any 256-bit value is below 2n, so one conditional subtraction suffices.
        let value = U256::from_be_bytes(bytes);
        let (reduced, borrow) = value.sub_with_borrow(Self::ORDER);
        let overflowed = Mask::from_bit(borrow).not();
        (
            Self(array::from_fn(|i| {
                overflowed.select(reduced.0[i], value.0[i])
            })),
            overflowed,
        )
    }

    /// Encodes as 32 big-endian bytes.
    pub(super) fn to_bytes(self) -> [u8; 32] {
        self.to_uint().to_be_bytes()
    }

    /// The canonical value as an integer.
    pub(super) const fn to_uint(self) -> U256 {
        U256(self.0)
    }

    /// Holds when the scalar is zero.
    pub(super) fn is_zero(self) -> Mask {
        // OR all limbs together and test the result.
        Mask::is_zero(self.0[0] | self.0[1] | self.0[2] | self.0[3])
    }

    /// Holds when the scalar exceeds n / 2, the upper half that low-s signatures avoid.
    pub(super) fn is_high(self) -> Mask {
        // s > n/2 exactly when n/2 - s borrows.
        let (_, borrow) = U256(HALF_N).sub_with_borrow(self.to_uint());
        Mask::from_bit(borrow)
    }

    /// The first scalar when the condition holds, the second otherwise.
    pub(super) fn select(condition: Mask, if_true: Self, if_false: Self) -> Self {
        // Limb by limb, through the mask.
        Self(array::from_fn(|i| {
            condition.select(if_true.0[i], if_false.0[i])
        }))
    }

    /// The 4-bit digit at window i, bits 4i to 4i + 3.
    ///
    /// The window index is public, and the digit stays a secret word.
    pub(super) const fn nibble(self, window: usize) -> u64 {
        // Sixteen 4-bit windows per 64-bit limb.
        (self.0[window / 16] >> ((window % 16) * 4)) & 0xf
    }

    /// The bit at position i.
    #[cfg(test)]
    pub(super) const fn bit(self, position: usize) -> u64 {
        // Sixty-four bits per limb.
        (self.0[position / 64] >> (position % 64)) & 1
    }

    /// The sum.
    #[must_use]
    pub(super) fn add(self, other: Self) -> Self {
        // As in the field: subtract n once when the sum carried or reached n.
        let (sum, carry) = self.to_uint().add_with_carry(other.to_uint());
        let (reduced, borrow) = sum.sub_with_borrow(Self::ORDER);
        let use_reduced = Mask::from_bit(carry).or(Mask::from_bit(borrow).not());
        Self(array::from_fn(|i| {
            use_reduced.select(reduced.0[i], sum.0[i])
        }))
    }

    /// The additive inverse.
    #[must_use]
    pub(super) fn neg(self) -> Self {
        // n - a, except 0 stays 0 rather than becoming n.
        let (difference, _) = Self::ORDER.sub_with_borrow(self.to_uint());
        let zero = self.is_zero();
        Self(difference.0.map(|limb| zero.select(0, limb)))
    }

    /// The product.
    #[must_use]
    pub(super) fn mul(self, other: Self) -> Self {
        // mont(a, b) = a b / R, and mont(a b / R, R^2) = a b.
        Self(Self::montgomery_mul(
            Self::montgomery_mul(self.0, other.0),
            R2,
        ))
    }

    /// The inverse, by Fermat: a^(n - 2), and zero for zero.
    ///
    /// # Algorithm
    ///
    /// Fixed 4-bit windows over the public exponent, all in Montgomery form.
    ///
    /// ```text
    /// table[j] = a^j R          for j = 0..15
    /// x = x^16 * table[digit]   for each 4-bit digit of n - 2, high to low
    /// ```
    ///
    /// The exponent is public, so the digit sequence leaks nothing about the input.
    #[must_use]
    pub(super) fn invert(self) -> Self {
        // Phase 1: powers of a in Montgomery form.
        // R mod n stands for 1.
        let base = Self::montgomery_mul(self.0, R2);
        let one = Self::montgomery_mul([1, 0, 0, 0], R2);
        let mut table = [one; 16];
        for j in 1..16 {
            table[j] = Self::montgomery_mul(table[j - 1], base);
        }

        // Phase 2: 64 windows, high to low.
        let mut x = one;
        for window in (0..64).rev() {
            for _ in 0..4 {
                x = Self::montgomery_mul(x, x);
            }
            let digit = (N_MINUS_2[window / 16] >> ((window % 16) * 4)) & 0xf;
            x = Self::montgomery_mul(x, table[digit as usize]);
        }

        // Phase 3: leave Montgomery form, x R / R = x.
        Self(Self::montgomery_mul(x, [1, 0, 0, 0]))
    }

    /// The signed-digit width-w NAF of the scalar, least significant digit first.
    ///
    /// Every non-zero digit is odd and in (-2^(w-1), 2^(w-1)), and any two are w positions apart.
    /// Used only on public scalars: the digit pattern depends on the value.
    pub(super) fn wnaf_vartime(self, width: u32) -> [i8; 257] {
        // Digit i multiplies 2^i.
        // Most digits stay zero.
        let mut digits = [0_i8; 257];
        let window = 1_u64 << width;

        // A five-limb copy holds the running value, which may reach 2^256 after adding a digit.
        let mut k = U320::from_u256(self.to_uint());
        let mut position = 0;
        while !k.is_zero() {
            if k.low() & 1 == 1 {
                // Take the low w bits as a signed digit, then clear them from k.
                //
                //     low = 0b10011 (19), w = 5 -> digit 19 - 32 = -13, k += 13
                let low = k.low() & (window - 1);
                if low < window / 2 {
                    // A positive digit: subtract it.
                    digits[position] = (low as u8).cast_signed();
                    k.sub_small(low);
                } else {
                    // A negative digit low - 2^w: add its magnitude.
                    // The magnitude is below 2^(w-1), since low is odd.
                    let magnitude = window - low;
                    digits[position] = -(magnitude as u8).cast_signed();
                    k.add_small(magnitude);
                }
            }
            k.halve();
            position += 1;
        }
        digits
    }

    /// The Montgomery product a b R^-1 mod n, for inputs below n.
    ///
    /// # Algorithm
    ///
    /// Coarsely integrated operand scanning (CIOS), word by word.
    ///
    /// ```text
    /// for each limb b_i:
    ///     t = t + a b_i              add one row
    ///     m = t_0 * (-n^-1) mod 2^64 choose m so the low word cancels
    ///     t = (t + m n) / 2^64       exact division by one word
    /// ```
    ///
    /// The result lies in [0, 2n), and one masked subtraction brings it under n.
    fn montgomery_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        // Six words: four for t, one for its carry, one spare for the row's overflow.
        let mut t = [0_u64; 6];
        for &bi in &b {
            // Row: t += a * b_i.
            let mut carry = 0_u128;
            for j in 0..4 {
                let sum = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + carry;
                t[j] = sum as u64;
                carry = sum >> 64;
            }
            let sum = u128::from(t[4]) + carry;
            t[4] = sum as u64;
            t[5] = (sum >> 64) as u64;

            // Reduction: t += m n makes the low word zero.
            // Then shift down one word.
            let m = t[0].wrapping_mul(N0_INV);
            let sum = u128::from(t[0]) + u128::from(m) * u128::from(N[0]);
            let mut carry = sum >> 64;
            for j in 1..4 {
                let sum = u128::from(t[j]) + u128::from(m) * u128::from(N[j]) + carry;
                t[j - 1] = sum as u64;
                carry = sum >> 64;
            }
            let sum = u128::from(t[4]) + carry;
            t[3] = sum as u64;
            t[4] = t[5] + (sum >> 64) as u64;
        }

        // Final: subtract n when t >= n, judged on the five-limb value.
        let value = [t[0], t[1], t[2], t[3]];
        let (reduced, borrow) = U256(value).sub_with_borrow(Self::ORDER);
        let use_reduced = Mask::from_bit(t[4]).or(Mask::from_bit(borrow).not());
        array::from_fn(|i| use_reduced.select(reduced.0[i], value[i]))
    }
}

#[cfg(test)]
pub(super) mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Any scalar, with the edges near 0, n / 2 and n over-represented.
    pub(crate) fn arb_scalar() -> impl Strategy<Value = Scalar> {
        prop_oneof![
            any::<[u8; 32]>().prop_map(|bytes| Scalar::from_bytes_reduced(&bytes).0),
            (0_u64..4).prop_map(|k| Scalar([k, 0, 0, 0])),
            (1_u64..4).prop_map(|k| Scalar([N[0] - k, N[1], N[2], N[3]])),
            (0_u64..3).prop_map(|k| Scalar([HALF_N[0] + k, HALF_N[1], HALF_N[2], HALF_N[3]])),
        ]
    }

    /// The product by shift-and-add, using only addition.
    fn mul_reference(a: Scalar, b: Scalar) -> Scalar {
        // Scan the bits of b from the top: acc = 2 acc + bit * a.
        let mut acc = Scalar::ZERO;
        for bit in (0..256).rev() {
            acc = acc.add(acc);
            if b.bit(bit) == 1 {
                acc = acc.add(a);
            }
        }
        acc
    }

    #[test]
    fn montgomery_constants() {
        // -n^-1 times n is -1 modulo 2^64.
        assert_eq!(N0_INV.wrapping_mul(N[0]), u64::MAX);

        // R^2 in Montgomery form maps 1 to R, and R / R = 1.
        assert_eq!(
            Scalar::montgomery_mul(Scalar::montgomery_mul([1, 0, 0, 0], R2), [1, 0, 0, 0]),
            [1, 0, 0, 0]
        );

        // Half of n: 2 * HALF_N + 1 = n.
        let (doubled, _) = U256(HALF_N).add_with_carry(U256(HALF_N));
        assert_eq!(doubled.add_with_carry(U256([1, 0, 0, 0])).0, Scalar::ORDER);
    }

    #[test]
    fn decoding_bounds() {
        // n - 1 decodes, n does not, and n reduces to 0 with the overflow flag set.
        let mut n_minus_one = Scalar::ORDER.to_be_bytes();
        n_minus_one[31] -= 1;
        assert!(Scalar::from_bytes(&n_minus_one).is_some());
        assert!(Scalar::from_bytes(&Scalar::ORDER.to_be_bytes()).is_none());
        let (reduced, overflowed) = Scalar::from_bytes_reduced(&Scalar::ORDER.to_be_bytes());
        assert_eq!(reduced, Scalar::ZERO);
        assert!(overflowed.reveal());
    }

    #[test]
    fn high_half_boundary() {
        // n/2 rounded down is low.
        // One more is high.
        assert!(!Scalar(HALF_N).is_high().reveal());
        assert!(
            Scalar([HALF_N[0] + 1, HALF_N[1], HALF_N[2], HALF_N[3]])
                .is_high()
                .reveal()
        );
    }

    proptest! {
        #[test]
        fn montgomery_product_matches_shift_and_add(a in arb_scalar(), b in arb_scalar()) {
            // Two Montgomery steps equal the plain product modulo n.
            prop_assert_eq!(a.mul(b), mul_reference(a, b));
        }

        #[test]
        fn ring_laws(a in arb_scalar(), b in arb_scalar(), c in arb_scalar()) {
            // Distributivity, negation, and inversion.
            prop_assert_eq!(a.mul(b.add(c)), a.mul(b).add(a.mul(c)));
            prop_assert_eq!(a.add(a.neg()), Scalar::ZERO);
            if a != Scalar::ZERO {
                prop_assert_eq!(a.mul(a.invert()), Scalar::ONE);
            }

            // Exactly one of a and -a is high, for every non-zero a.
            if a != Scalar::ZERO {
                prop_assert_ne!(a.is_high().reveal(), a.neg().is_high().reveal());
            }
        }

        #[test]
        fn wnaf_digits_rebuild_the_scalar(a in arb_scalar(), width in 2_u32..8) {
            // sum_i digit_i 2^i = a, with odd bounded digits w apart.
            let digits = a.wnaf_vartime(width);
            let mut rebuilt = Scalar::ZERO;
            let mut last_nonzero: Option<usize> = None;
            for (i, &digit) in digits.iter().enumerate().rev() {
                rebuilt = rebuilt.add(rebuilt);
                let magnitude = Scalar([u64::from(digit.unsigned_abs()), 0, 0, 0]);
                let signed = if digit >= 0 { magnitude } else { magnitude.neg() };
                rebuilt = rebuilt.add(signed);
                if digit != 0 {
                    prop_assert_eq!(digit % 2 != 0, true);
                    prop_assert!(i32::from(digit).abs() < 1 << (width - 1));
                    if let Some(previous) = last_nonzero {
                        prop_assert!(previous - i >= width as usize);
                    }
                    last_nonzero = Some(i);
                }
            }
            prop_assert_eq!(rebuilt, a);
        }

        #[test]
        fn bytes_round_trip(a in arb_scalar()) {
            prop_assert_eq!(Scalar::from_bytes(&a.to_bytes()), Some(a));
        }
    }
}
