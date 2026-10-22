//! Arithmetic modulo the secp256k1 field prime p = 2^256 - 2^32 - 977.

use std::array;

use crate::ct::Mask;

/// The prime p in four little-endian 64-bit limbs, per SEC 2, section 2.4.1.
const P: [u64; 4] = [
    0xffff_fffe_ffff_fc2f,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];

/// The fold constant 2^256 - p = 2^32 + 977.
///
/// It is why secp256k1 reduction is cheap: 2^256 = C mod p, and C fits in 33 bits.
const C: u64 = 0x1_0000_03d1;

/// An element of GF(p), always held in canonical form below p.
///
/// # Invariants
///
/// The limbs, read little-endian, encode a value in [0, p).
/// Every operation preserves this, so equality of limbs is equality of elements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) struct FieldElement([u64; 4]);

impl FieldElement {
    /// Zero.
    pub(super) const ZERO: Self = Self([0; 4]);

    /// One.
    pub(super) const ONE: Self = Self([1, 0, 0, 0]);

    /// The curve constant b = 7 of y^2 = x^3 + 7.
    pub(super) const B: Self = Self([7, 0, 0, 0]);

    /// An element from raw limbs that are already below p.
    pub(super) const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    /// Decodes 32 big-endian bytes, refusing values at or above p.
    ///
    /// The check runs in constant time; only its outcome is revealed.
    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let limbs = limbs_from_be_bytes(bytes);

        // The value is canonical exactly when subtracting p borrows.
        let (_, borrow) = sub_with_borrow(limbs, P);
        Mask::from_bit(borrow).reveal().then_some(Self(limbs))
    }

    /// Encodes as 32 big-endian bytes.
    pub(super) fn to_bytes(self) -> [u8; 32] {
        limbs_to_be_bytes(self.0)
    }

    /// Holds when the element is zero.
    pub(super) fn is_zero(self) -> Mask {
        Mask::is_zero(self.0[0] | self.0[1] | self.0[2] | self.0[3])
    }

    /// Holds when the canonical value is odd.
    pub(super) fn is_odd(self) -> Mask {
        Mask::from_bit(self.0[0] & 1)
    }

    /// Holds when the two elements are equal.
    pub(super) fn equals(self, other: Self) -> Mask {
        let difference = (self.0[0] ^ other.0[0])
            | (self.0[1] ^ other.0[1])
            | (self.0[2] ^ other.0[2])
            | (self.0[3] ^ other.0[3]);
        Mask::is_zero(difference)
    }

    /// The first element when the condition holds, the second otherwise.
    pub(super) fn select(condition: Mask, if_true: Self, if_false: Self) -> Self {
        Self(array::from_fn(|i| {
            condition.select(if_true.0[i], if_false.0[i])
        }))
    }

    /// The sum.
    #[must_use]
    pub(super) fn add(self, other: Self) -> Self {
        // The true sum s may reach 2p - 2 < 2^257.
        let (sum, carry) = add_with_carry(self.0, other.0);

        // Subtract p once and keep that result when s >= p.
        //
        //     carry out of the add        -> s >= 2^256 > p
        //     no borrow out of s - p      -> s >= p
        let (reduced, borrow) = sub_with_borrow(sum, P);
        let use_reduced = Mask::from_bit(carry).or(Mask::from_bit(borrow).not());
        Self(array::from_fn(|i| use_reduced.select(reduced[i], sum[i])))
    }

    /// The difference.
    #[must_use]
    pub(super) fn sub(self, other: Self) -> Self {
        // A borrow means the result wrapped to a - b + 2^256: add p back modulo 2^256.
        let (difference, borrow) = sub_with_borrow(self.0, other.0);
        let wrapped = Mask::from_bit(borrow);
        let correction = P.map(|limb| wrapped.select(limb, 0));
        Self(add_with_carry(difference, correction).0)
    }

    /// The additive inverse.
    #[must_use]
    pub(super) fn neg(self) -> Self {
        Self::ZERO.sub(self)
    }

    /// Twice the element.
    #[must_use]
    pub(super) fn double(self) -> Self {
        self.add(self)
    }

    /// The product.
    #[must_use]
    pub(super) fn mul(self, other: Self) -> Self {
        // Schoolbook product into eight limbs, one row of partial products per limb of b.
        let a = self.0;
        let b = other.0;
        let mut wide = [0_u64; 8];
        for (i, &bi) in b.iter().enumerate() {
            let mut carry = 0_u64;
            for (j, &aj) in a.iter().enumerate() {
                // Fits: (2^64 - 1)^2 + 2 (2^64 - 1) = 2^128 - 1.
                let t =
                    u128::from(aj) * u128::from(bi) + u128::from(wide[i + j]) + u128::from(carry);
                wide[i + j] = t as u64;
                carry = (t >> 64) as u64;
            }
            wide[i + 4] = carry;
        }
        Self::reduce_wide(wide)
    }

    /// The square.
    #[must_use]
    pub(super) fn square(self) -> Self {
        self.mul(self)
    }

    /// The square taken k times in a row.
    #[must_use]
    fn square_times(self, k: u32) -> Self {
        let mut x = self;
        for _ in 0..k {
            x = x.square();
        }
        x
    }

    /// Reduces a 512-bit product modulo p.
    ///
    /// # Algorithm
    ///
    /// Split the product at bit 256 and fold the high half down with 2^256 = C mod p.
    ///
    /// ```text
    /// w = high * 2^256 + low = high * C + low          (fits in 256 + 34 bits)
    ///   = top * 2^256 + rest = top * C + rest          (fits in 256 + 1 bits)
    /// ```
    ///
    /// A last carry folds once more, then one conditional subtraction makes it canonical.
    fn reduce_wide(wide: [u64; 8]) -> Self {
        // Fold 1: low + high * C, a 4-limb value plus a top limb below 2^34.
        let mut r = [0_u64; 4];
        let mut carry = 0_u128;
        for i in 0..4 {
            let t = u128::from(wide[i]) + u128::from(wide[i + 4]) * u128::from(C) + carry;
            r[i] = t as u64;
            carry = t >> 64;
        }
        let top = carry as u64;

        // Fold 2: top * C is below 2^67; add it and ripple the carry.
        let mut carry = u128::from(top) * u128::from(C);
        for limb in &mut r {
            let t = u128::from(*limb) + carry;
            *limb = t as u64;
            carry = t >> 64;
        }

        // Fold 3: a carry out of fold 2 is one more 2^256 = C.
        //
        // When it happens, r is below 2^67, so adding C cannot carry again.
        let extra = Mask::from_bit(carry as u64).select(C, 0);
        let (r, _) = add_with_carry(r, [extra, 0, 0, 0]);

        // Final: r < 2^256 < 2p, so one conditional subtraction lands in [0, p).
        let (reduced, borrow) = sub_with_borrow(r, P);
        let keep = Mask::from_bit(borrow);
        Self(array::from_fn(|i| keep.select(r[i], reduced[i])))
    }

    /// The inverse, by Fermat: a^(p - 2), and zero for zero.
    ///
    /// # Algorithm
    ///
    /// The addition chain of libsecp256k1, built from blocks of ones x_k = a^(2^k - 1).
    ///
    /// ```text
    /// x2 x3 x6 x9 x11 x22 x44 x88 x176 x220 x223
    /// p - 2 = (2^223 - 1) 2^33 + (2^22 - 1) 2^10 + 2^5 + 3 * 2^2 + 1
    /// ```
    ///
    /// The chain is fixed, so the time does not depend on the input.
    #[must_use]
    pub(super) fn invert(self) -> Self {
        let (x2, x22, x223) = self.blocks_of_ones();

        // Tail: append the bits of 2^33 - 2^32 - 979 below the 223 leading ones.
        let mut t = x223.square_times(23).mul(x22);
        t = t.square_times(5).mul(self);
        t = t.square_times(3).mul(x2);
        t.square_times(2).mul(self)
    }

    /// A square root, if one exists.
    ///
    /// Since p = 3 mod 4, a root is a^((p + 1) / 4), per SEC 1, section 2.3.4.
    /// The candidate is squared back to tell residues from non-residues.
    pub(super) fn sqrt(self) -> Option<Self> {
        // (p + 1) / 4 = (2^223 - 1) 2^31 + (2^22 - 1) 2^8 + 3 * 2^2.
        let (x2, x22, x223) = self.blocks_of_ones();
        let mut t = x223.square_times(23).mul(x22);
        t = t.square_times(6).mul(x2);
        let root = t.square_times(2);

        // Timing: the check reveals only whether a root exists, a public fact here.
        root.square().equals(self).reveal().then_some(root)
    }

    /// The powers a^(2^k - 1) for k = 2, 22 and 223, shared by inversion and square roots.
    fn blocks_of_ones(self) -> (Self, Self, Self) {
        let x2 = self.square().mul(self);
        let x3 = x2.square().mul(self);
        let x6 = x3.square_times(3).mul(x3);
        let x9 = x6.square_times(3).mul(x3);
        let x11 = x9.square_times(2).mul(x2);
        let x22 = x11.square_times(11).mul(x11);
        let x44 = x22.square_times(22).mul(x22);
        let x88 = x44.square_times(44).mul(x44);
        let x176 = x88.square_times(88).mul(x88);
        let x220 = x176.square_times(44).mul(x44);
        let x223 = x220.square_times(3).mul(x3);
        (x2, x22, x223)
    }
}

/// Little-endian limbs of a 32-byte big-endian integer.
pub(super) fn limbs_from_be_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    // Limb 0 is the least significant, so it comes from the last eight bytes.
    let (words, _) = bytes.as_chunks::<8>();
    array::from_fn(|i| u64::from_be_bytes(words[3 - i]))
}

/// The 32-byte big-endian encoding of little-endian limbs.
pub(super) fn limbs_to_be_bytes(limbs: [u64; 4]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let (words, _) = out.as_chunks_mut::<8>();
    for (word, limb) in words.iter_mut().zip(limbs.iter().rev()) {
        *word = limb.to_be_bytes();
    }
    out
}

/// The 256-bit sum and its carry bit.
pub(super) fn add_with_carry(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0_u64; 4];
    let mut carry = 0_u64;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        out[i] = s2;
        carry = u64::from(c1) | u64::from(c2);
    }
    (out, carry)
}

/// The 256-bit difference and its borrow bit.
pub(super) fn sub_with_borrow(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0_u64; 4];
    let mut borrow = 0_u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    (out, borrow)
}

#[cfg(test)]
pub(super) mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Any field element, with the edges near 0 and p over-represented.
    pub(crate) fn arb_field() -> impl Strategy<Value = FieldElement> {
        prop_oneof![
            any::<[u64; 4]>().prop_filter_map("below p", |limbs| {
                FieldElement::from_bytes(&limbs_to_be_bytes(limbs))
            }),
            (0_u64..4).prop_map(|k| FieldElement([k, 0, 0, 0])),
            (1_u64..4).prop_map(|k| FieldElement([P[0] - k, P[1], P[2], P[3]])),
        ]
    }

    /// The product by shift-and-add: double the accumulator, add a for each set bit of b.
    ///
    /// It uses only addition, so it pins the multiplier and its reduction independently.
    fn mul_reference(a: FieldElement, b: FieldElement) -> FieldElement {
        let mut acc = FieldElement::ZERO;
        for bit in (0..256).rev() {
            acc = acc.double();
            if (b.0[bit / 64] >> (bit % 64)) & 1 == 1 {
                acc = acc.add(a);
            }
        }
        acc
    }

    #[test]
    fn encoding_refuses_p_and_above() {
        // p - 1 is the largest canonical value.
        let mut bytes = limbs_to_be_bytes(P);
        bytes[31] -= 1;
        assert!(FieldElement::from_bytes(&bytes).is_some());

        // p and 2^256 - 1 are refused.
        assert!(FieldElement::from_bytes(&limbs_to_be_bytes(P)).is_none());
        assert!(FieldElement::from_bytes(&[0xff; 32]).is_none());
    }

    #[test]
    fn wrap_around_edges() {
        // (p - 1) + 1 = 0, and 0 - 1 = p - 1.
        let minus_one = FieldElement([P[0] - 1, P[1], P[2], P[3]]);
        assert_eq!(minus_one.add(FieldElement::ONE), FieldElement::ZERO);
        assert_eq!(FieldElement::ZERO.sub(FieldElement::ONE), minus_one);

        // (p - 1)^2 = 1: the largest product, through all three folds.
        assert_eq!(minus_one.square(), FieldElement::ONE);

        // The inverse of zero is zero, as Fermat's exponent gives.
        assert_eq!(FieldElement::ZERO.invert(), FieldElement::ZERO);
    }

    #[test]
    fn square_roots_of_known_values() {
        // 4 has roots 2 and p - 2; the exponent picks one of them.
        let four = FieldElement([4, 0, 0, 0]);
        let root = four.sqrt().unwrap();
        assert!(root == FieldElement([2, 0, 0, 0]) || root == FieldElement([2, 0, 0, 0]).neg());

        // -1 is a non-residue, since p = 3 mod 4.
        assert_eq!(FieldElement::ONE.neg().sqrt(), None);
    }

    proptest! {
        #[test]
        fn multiplication_matches_shift_and_add(a in arb_field(), b in arb_field()) {
            // The fast product and its three-fold reduction equal repeated addition.
            prop_assert_eq!(a.mul(b), mul_reference(a, b));
        }

        #[test]
        fn ring_laws(a in arb_field(), b in arb_field(), c in arb_field()) {
            // Commutativity, associativity, and distributivity.
            prop_assert_eq!(a.mul(b), b.mul(a));
            prop_assert_eq!(a.mul(b).mul(c), a.mul(b.mul(c)));
            prop_assert_eq!(a.mul(b.add(c)), a.mul(b).add(a.mul(c)));

            // Subtraction and negation undo addition.
            prop_assert_eq!(a.add(b).sub(b), a);
            prop_assert_eq!(a.add(a.neg()), FieldElement::ZERO);
        }

        #[test]
        fn inversion_and_roots(a in arb_field()) {
            // a * a^-1 = 1 for every non-zero a.
            if a != FieldElement::ZERO {
                prop_assert_eq!(a.mul(a.invert()), FieldElement::ONE);
            }

            // a^2 always has a root, and that root is a or -a.
            let root = a.square().sqrt().unwrap();
            prop_assert!(root == a || root == a.neg());
        }

        #[test]
        fn bytes_round_trip(a in arb_field()) {
            // Canonical form makes the encoding a bijection on [0, p).
            prop_assert_eq!(FieldElement::from_bytes(&a.to_bytes()), Some(a));
        }
    }
}
