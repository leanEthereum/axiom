//! Arithmetic modulo the P-256 field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1.

use std::array;

use super::montgomery::Modulus;
use crate::{ct::Mask, uint::U256};

/// The prime p in four little-endian 64-bit limbs, per FIPS 186-4, appendix D.1.2.3.
const MODULUS: Modulus = Modulus::new(U256([
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
]));

/// The Fermat inversion exponent p - 2.
const P_MINUS_2: U256 = U256([
    0xffff_ffff_ffff_fffd,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
]);

/// The square root exponent (p + 1) / 4, valid since p = 3 mod 4.
const SQRT_EXPONENT: U256 = U256([
    0x0000_0000_0000_0000,
    0x0000_0000_4000_0000,
    0x4000_0000_0000_0000,
    0x3fff_ffff_c000_0000,
]);

/// An element of GF(p), held in Montgomery form a R mod p with R = 2^256.
///
/// # Invariants
///
/// The limbs encode a R mod p, canonical in [0, p).
/// The map from a to a R is a bijection, so equal limbs mean equal elements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) struct FieldElement([u64; 4]);

impl FieldElement {
    /// Zero.
    pub(super) const ZERO: Self = Self([0; 4]);

    /// One.
    pub(super) const ONE: Self = Self::from_canonical_const([1, 0, 0, 0]);

    /// The curve constant b of y^2 = x^3 - 3x + b, per FIPS 186-4, appendix D.1.2.3.
    pub(super) const B: Self = Self::from_canonical_const([
        0x3bce_3c3e_27d2_604b,
        0x651d_06b0_cc53_b0f6,
        0xb3eb_bd55_7698_86bc,
        0x5ac6_35d8_aa3a_93e7,
    ]);

    /// An element from canonical little-endian limbs below p, at compile time.
    pub(super) const fn from_canonical_const(limbs: [u64; 4]) -> Self {
        Self(MODULUS.encode_const(limbs))
    }

    /// Decodes 32 big-endian bytes, refusing values at or above p.
    ///
    /// The check runs in constant time and reveals only its outcome.
    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Self::from_uint(U256::from_be_bytes(bytes))
    }

    /// The element equal to an integer, refusing values at or above p.
    ///
    /// The check runs in constant time and reveals only its outcome.
    pub(super) fn from_uint(value: U256) -> Option<Self> {
        MODULUS
            .contains(value)
            .reveal()
            .then(|| Self(MODULUS.encode(value.0)))
    }

    /// Encodes as 32 big-endian bytes.
    pub(super) fn to_bytes(self) -> [u8; 32] {
        U256(MODULUS.decode(self.0)).to_be_bytes()
    }

    /// Holds when the element is zero.
    pub(super) fn is_zero(self) -> Mask {
        // Zero is the only element whose Montgomery form is zero.
        Mask::is_zero(self.0[0] | self.0[1] | self.0[2] | self.0[3])
    }

    /// Holds when the canonical value is odd.
    pub(super) fn is_odd(self) -> Mask {
        // Parity belongs to the plain value, so leave Montgomery form first.
        Mask::from_bit(MODULUS.decode(self.0)[0] & 1)
    }

    /// Holds when the two elements are equal.
    pub(super) fn equals(self, other: Self) -> Mask {
        // Canonical form: equal elements have equal limbs, so OR the limb differences.
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
        // Montgomery form is linear: a R + b R = (a + b) R.
        Self(MODULUS.add(self.0, other.0))
    }

    /// The difference.
    #[must_use]
    pub(super) fn sub(self, other: Self) -> Self {
        Self(MODULUS.sub(self.0, other.0))
    }

    /// The additive inverse.
    #[must_use]
    pub(super) fn neg(self) -> Self {
        // -a = 0 - a, with the wrap-around of subtraction.
        Self::ZERO.sub(self)
    }

    /// Twice the element.
    #[must_use]
    pub(super) fn double(self) -> Self {
        self.add(self)
    }

    /// Three times the element.
    #[must_use]
    pub(super) fn triple(self) -> Self {
        self.double().add(self)
    }

    /// The product.
    #[must_use]
    pub(super) fn mul(self, other: Self) -> Self {
        // mont(a R, b R) = (a b) R.
        Self(MODULUS.mul(self.0, other.0))
    }

    /// The square.
    #[must_use]
    pub(super) fn square(self) -> Self {
        self.mul(self)
    }

    /// The inverse, by Fermat: a^(p - 2), and zero for zero.
    ///
    /// The exponent is public, so the time does not depend on the input.
    #[must_use]
    pub(super) fn invert(self) -> Self {
        Self(MODULUS.pow(self.0, P_MINUS_2))
    }

    /// A square root, if one exists.
    ///
    /// Since p = 3 mod 4, a root is a^((p + 1) / 4), per SEC 1, section 2.3.4.
    /// The candidate is squared back to tell residues from non-residues.
    pub(super) fn sqrt(self) -> Option<Self> {
        let root = Self(MODULUS.pow(self.0, SQRT_EXPONENT));

        // Timing: the check reveals only whether a root exists, a public fact here.
        root.square().equals(self).reveal().then_some(root)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use proptest::prelude::*;

    use super::*;

    /// The prime p as an integer.
    const P: U256 = MODULUS.value();

    /// Any field element, with the edges near 0 and p over-represented.
    pub(crate) fn arb_field() -> impl Strategy<Value = FieldElement> {
        prop_oneof![
            any::<[u64; 4]>()
                .prop_filter_map("below p", |limbs| FieldElement::from_uint(U256(limbs))),
            (0_u64..4).prop_map(|k| FieldElement::from_uint(U256([k, 0, 0, 0])).unwrap()),
            (1_u64..4).prop_map(|k| {
                FieldElement::from_uint(U256([P.0[0] - k, P.0[1], P.0[2], P.0[3]])).unwrap()
            }),
        ]
    }

    /// The product by shift-and-add on canonical values.
    ///
    /// It uses only addition, so it pins the Montgomery product independently.
    fn mul_reference(a: FieldElement, b: FieldElement) -> FieldElement {
        // Scan the bits of b from the top: acc = 2 acc + bit * a.
        let bits = MODULUS.decode(b.0);
        let mut acc = FieldElement::ZERO;
        for bit in (0..256).rev() {
            acc = acc.double();
            if (bits[bit / 64] >> (bit % 64)) & 1 == 1 {
                acc = acc.add(a);
            }
        }
        acc
    }

    #[test]
    fn exponents_follow_from_p() {
        // p - 2 + 2 = p, and 4 (p + 1) / 4 - 1 = p.
        let two = U256([2, 0, 0, 0]);
        assert_eq!(P_MINUS_2.add_with_carry(two), (P, 0));
        let (doubled, _) = SQRT_EXPONENT.add_with_carry(SQRT_EXPONENT);
        let (quadrupled, _) = doubled.add_with_carry(doubled);
        assert_eq!(quadrupled.sub_with_borrow(U256([1, 0, 0, 0])), (P, 0));
    }

    #[test]
    fn encoding_refuses_p_and_above() {
        // p - 1 is the largest canonical value.
        let mut bytes = P.to_be_bytes();
        bytes[31] -= 1;
        assert_eq!(
            FieldElement::from_bytes(&bytes).map(FieldElement::to_bytes),
            Some(bytes)
        );

        // p and 2^256 - 1 are refused.
        assert_eq!(FieldElement::from_bytes(&P.to_be_bytes()), None);
        assert_eq!(FieldElement::from_bytes(&[0xff; 32]), None);
    }

    #[test]
    fn wrap_around_edges() {
        // (p - 1) + 1 = 0, and 0 - 1 = p - 1.
        let minus_one = FieldElement::ONE.neg();
        assert_eq!(minus_one.add(FieldElement::ONE), FieldElement::ZERO);
        assert_eq!(FieldElement::ZERO.sub(FieldElement::ONE), minus_one);

        // (p - 1)^2 = 1: the largest product.
        assert_eq!(minus_one.square(), FieldElement::ONE);

        // The inverse of zero is zero, as Fermat's exponent gives.
        assert_eq!(FieldElement::ZERO.invert(), FieldElement::ZERO);

        // p - 1 is even and 1 is odd.
        assert!(!minus_one.is_odd().reveal());
        assert!(FieldElement::ONE.is_odd().reveal());
    }

    #[test]
    fn square_roots_of_known_values() {
        // 4 has roots 2 and p - 2.
        let four = FieldElement::from_uint(U256([4, 0, 0, 0])).unwrap();
        let two = FieldElement::from_uint(U256([2, 0, 0, 0])).unwrap();
        let root = four.sqrt().unwrap();
        assert!(root == two || root == two.neg());

        // -1 is a non-residue, since p = 3 mod 4.
        assert_eq!(FieldElement::ONE.neg().sqrt(), None);
    }

    proptest! {
        #[test]
        fn multiplication_matches_shift_and_add(a in arb_field(), b in arb_field()) {
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
            prop_assert_eq!(a.triple(), a.add(a).add(a));
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
            prop_assert_eq!(FieldElement::from_bytes(&a.to_bytes()), Some(a));
        }
    }
}
