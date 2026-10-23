//! Arithmetic modulo the P-384 field prime p = 2^384 - 2^128 - 2^96 + 2^32 - 1.

use super::montgomery::Modulus;
use crate::uint::U384;

/// The prime p in six little-endian 64-bit limbs, per FIPS 186-4, appendix D.1.2.4.
const MODULUS: Modulus = Modulus::new(U384([
    0x0000_0000_ffff_ffff,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
]));

/// The Fermat inversion exponent p - 2.
#[cfg(test)]
const P_MINUS_2: U384 = U384([
    0x0000_0000_ffff_fffd,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
]);

/// The square root exponent (p + 1) / 4, valid since p = 3 mod 4.
const SQRT_EXPONENT: U384 = U384([
    0x0000_0000_4000_0000,
    0xbfff_ffff_c000_0000,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x3fff_ffff_ffff_ffff,
]);

/// An element of GF(p), held in Montgomery form a R mod p with R = 2^384.
///
/// # Invariants
///
/// The limbs encode a R mod p, canonical in [0, p).
/// The map from a to a R is a bijection, so equal limbs mean equal elements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) struct FieldElement([u64; 6]);

impl FieldElement {
    /// Zero.
    pub(super) const ZERO: Self = Self([0; 6]);

    /// One.
    pub(super) const ONE: Self = Self::from_canonical_const([1, 0, 0, 0, 0, 0]);

    /// The curve constant b of y^2 = x^3 - 3x + b, per FIPS 186-4, appendix D.1.2.4.
    pub(super) const B: Self = Self::from_canonical_const([
        0x2a85_c8ed_d3ec_2aef,
        0xc656_398d_8a2e_d19d,
        0x0314_088f_5013_875a,
        0x181d_9c6e_fe81_4112,
        0x988e_056b_e3f8_2d19,
        0xb331_2fa7_e23e_e7e4,
    ]);

    /// An element from canonical little-endian limbs below p, at compile time.
    pub(super) const fn from_canonical_const(limbs: [u64; 6]) -> Self {
        Self(MODULUS.encode_const(limbs))
    }

    /// Decodes 48 big-endian bytes, refusing values at or above p.
    pub(super) fn from_bytes(bytes: &[u8; 48]) -> Option<Self> {
        Self::from_uint(U384::from_be_bytes(bytes))
    }

    /// The element equal to an integer, refusing values at or above p.
    pub(super) fn from_uint(value: U384) -> Option<Self> {
        MODULUS
            .contains(value)
            .then(|| Self(MODULUS.encode(value.0)))
    }

    /// Encodes as 48 big-endian bytes.
    pub(super) fn to_bytes(self) -> [u8; 48] {
        U384(MODULUS.decode(self.0)).to_be_bytes()
    }

    /// Holds when the element is zero.
    pub(super) fn is_zero(self) -> bool {
        // Zero is the only element whose Montgomery form is zero.
        self == Self::ZERO
    }

    /// Holds when the canonical value is odd.
    pub(super) fn is_odd(self) -> bool {
        // Parity belongs to the plain value, so leave Montgomery form first.
        MODULUS.decode(self.0)[0] & 1 == 1
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
    #[cfg(test)]
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
        (root.square() == self).then_some(root)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use proptest::prelude::*;

    use super::*;

    /// The prime p as an integer.
    const P: U384 = MODULUS.value();

    /// Any field element, with the edges near 0 and p over-represented.
    pub(crate) fn arb_field() -> impl Strategy<Value = FieldElement> {
        prop_oneof![
            any::<[u64; 6]>()
                .prop_filter_map("below p", |limbs| FieldElement::from_uint(U384(limbs))),
            (0_u64..4).prop_map(|k| FieldElement::from_uint(U384([k, 0, 0, 0, 0, 0])).unwrap()),
            (1_u64..4).prop_map(|k| {
                let mut limbs = P.0;
                limbs[0] -= k;
                FieldElement::from_uint(U384(limbs)).unwrap()
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
        for bit in (0..384).rev() {
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
        let two = U384([2, 0, 0, 0, 0, 0]);
        assert_eq!(P_MINUS_2.add_with_carry(two), (P, 0));
        let (doubled, _) = SQRT_EXPONENT.add_with_carry(SQRT_EXPONENT);
        let (quadrupled, _) = doubled.add_with_carry(doubled);
        assert_eq!(quadrupled.sub_with_borrow(U384([1, 0, 0, 0, 0, 0])), (P, 0));
    }

    #[test]
    fn encoding_refuses_p_and_above() {
        // p - 1 is the largest canonical value.
        let mut bytes = P.to_be_bytes();
        bytes[47] -= 1;
        assert_eq!(
            FieldElement::from_bytes(&bytes).map(FieldElement::to_bytes),
            Some(bytes)
        );

        // p and 2^384 - 1 are refused.
        assert_eq!(FieldElement::from_bytes(&P.to_be_bytes()), None);
        assert_eq!(FieldElement::from_bytes(&[0xff; 48]), None);
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
        assert!(!minus_one.is_odd());
        assert!(FieldElement::ONE.is_odd());
    }

    #[test]
    fn square_roots_of_known_values() {
        // 4 has roots 2 and p - 2.
        let four = FieldElement::from_uint(U384([4, 0, 0, 0, 0, 0])).unwrap();
        let two = FieldElement::from_uint(U384([2, 0, 0, 0, 0, 0])).unwrap();
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
            if !a.is_zero() {
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
