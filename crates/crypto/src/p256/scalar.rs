//! Arithmetic modulo the P-256 group order n.

use std::array;

use super::montgomery::Modulus;
use crate::{ct::Mask, uint::U256};

/// The group order n in four little-endian 64-bit limbs, per FIPS 186-4, appendix D.1.2.3.
const MODULUS: Modulus = Modulus::new(U256([
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
]));

/// An integer modulo n, held in canonical form below n.
///
/// # Invariants
///
/// The limbs, read little-endian, encode a value in [0, n).
/// Scalars stay out of Montgomery form, so windows and encodings read the plain value.
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
    pub(super) const ORDER: U256 = MODULUS.value();

    /// Decodes 32 big-endian bytes, refusing values at or above n.
    ///
    /// The check runs in constant time and reveals only its outcome.
    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let value = U256::from_be_bytes(bytes);
        MODULUS.contains(value).reveal().then_some(Self(value.0))
    }

    /// Decodes a value in [1, n), refusing zero and values at or above n.
    ///
    /// Timing: only whether the value is in range is revealed.
    pub(super) fn from_bytes_nonzero(bytes: &[u8; 32]) -> Option<Self> {
        Self::from_bytes(bytes).filter(|value| !value.is_zero().reveal())
    }

    /// Decodes 32 big-endian bytes and reduces modulo n.
    ///
    /// Any 256-bit value is below 2n, so one conditional subtraction suffices.
    pub(super) fn from_bytes_reduced(bytes: &[u8; 32]) -> Self {
        let value = U256::from_be_bytes(bytes);
        let (reduced, borrow) = value.sub_with_borrow(Self::ORDER);
        let keep = Mask::from_bit(borrow);
        Self(array::from_fn(|i| keep.select(value.0[i], reduced.0[i])))
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
        Mask::is_zero(self.0[0] | self.0[1] | self.0[2] | self.0[3])
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
        (self.0[position / 64] >> (position % 64)) & 1
    }

    /// The sum.
    #[must_use]
    pub(super) fn add(self, other: Self) -> Self {
        Self(MODULUS.add(self.0, other.0))
    }

    /// The additive inverse.
    #[cfg(test)]
    #[must_use]
    pub(super) fn neg(self) -> Self {
        Self(MODULUS.sub([0; 4], self.0))
    }

    /// The product.
    #[must_use]
    pub(super) fn mul(self, other: Self) -> Self {
        // mont(a, b) = a b / R, and mont(a b / R, R^2) = a b.
        Self(MODULUS.encode(MODULUS.mul(self.0, other.0)))
    }

    /// The inverse, by Fermat: a^(n - 2), and zero for zero.
    ///
    /// The exponent is public, so the time does not depend on the input.
    #[must_use]
    pub(super) fn invert(self) -> Self {
        // n - 2: the low limb of n ends in 0x51, so no borrow crosses limbs.
        let [n0, n1, n2, n3] = Self::ORDER.0;
        let exponent = U256([n0 - 2, n1, n2, n3]);
        let power = MODULUS.pow(MODULUS.encode(self.0), exponent);
        Self(MODULUS.decode(power))
    }

    /// The signed-digit width-w NAF of the scalar, least significant digit first.
    ///
    /// Used only on public scalars: the digit pattern depends on the value.
    pub(super) fn wnaf_vartime(self, width: u32) -> [i8; 257] {
        self.to_uint().wnaf_vartime(width)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Any scalar, with the edges near 0 and n over-represented.
    pub(crate) fn arb_scalar() -> impl Strategy<Value = Scalar> {
        let n = Scalar::ORDER.0;
        prop_oneof![
            any::<[u8; 32]>().prop_map(|bytes| Scalar::from_bytes_reduced(&bytes)),
            (0_u64..4).prop_map(|k| Scalar([k, 0, 0, 0])),
            (1_u64..4).prop_map(move |k| Scalar([n[0] - k, n[1], n[2], n[3]])),
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
    fn decoding_bounds() {
        // n - 1 decodes, n does not, and n reduces to 0.
        let mut n_minus_one = Scalar::ORDER.to_be_bytes();
        n_minus_one[31] -= 1;
        assert_eq!(Scalar::from_bytes(&n_minus_one), Some(Scalar::ONE.neg()));
        assert_eq!(Scalar::from_bytes(&Scalar::ORDER.to_be_bytes()), None);
        assert_eq!(
            Scalar::from_bytes_reduced(&Scalar::ORDER.to_be_bytes()),
            Scalar::ZERO
        );

        // 2^256 - 1 reduces to 2^256 - 1 - n.
        let (expected, _) = U256([u64::MAX; 4]).sub_with_borrow(Scalar::ORDER);
        assert_eq!(Scalar::from_bytes_reduced(&[0xff; 32]), Scalar(expected.0));

        // Zero is a scalar but not a non-zero one.
        assert_eq!(Scalar::from_bytes_nonzero(&[0; 32]), None);
        assert_eq!(Scalar::from_bytes(&[0; 32]), Some(Scalar::ZERO));
    }

    proptest! {
        #[test]
        fn montgomery_product_matches_shift_and_add(a in arb_scalar(), b in arb_scalar()) {
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
        }

        #[test]
        fn bytes_round_trip(a in arb_scalar()) {
            prop_assert_eq!(Scalar::from_bytes(&a.to_bytes()), Some(a));
        }
    }
}
