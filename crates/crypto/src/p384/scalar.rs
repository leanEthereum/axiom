//! Arithmetic modulo the P-384 group order n.

use super::montgomery::Modulus;
use crate::uint::U384;

/// The group order n in six little-endian 64-bit limbs, per FIPS 186-4, appendix D.1.2.4.
const MODULUS: Modulus = Modulus::new(U384([
    0xecec_196a_ccc5_2973,
    0x581a_0db2_48b0_a77a,
    0xc763_4d81_f437_2ddf,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
]));

/// Bytes in the big-endian encoding of a scalar.
const LEN: usize = 48;

/// An integer modulo n, held in canonical form below n.
///
/// # Invariants
///
/// The limbs, read little-endian, encode a value in [0, n).
/// Scalars stay out of Montgomery form, so windows and encodings read the plain value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) struct Scalar([u64; 6]);

impl Scalar {
    /// Zero.
    #[cfg(test)]
    pub(super) const ZERO: Self = Self([0; 6]);

    /// One.
    #[cfg(test)]
    pub(super) const ONE: Self = Self([1, 0, 0, 0, 0, 0]);

    /// The order n itself as an integer, for comparisons against field values.
    pub(super) const ORDER: U384 = MODULUS.value();

    /// Decodes 48 big-endian bytes, refusing values at or above n.
    pub(super) fn from_bytes(bytes: &[u8; 48]) -> Option<Self> {
        let value = U384::from_be_bytes(bytes);
        MODULUS.contains(value).then_some(Self(value.0))
    }

    /// Decodes a value in [1, n), refusing zero and values at or above n.
    pub(super) fn from_bytes_nonzero(bytes: &[u8; 48]) -> Option<Self> {
        Self::from_bytes(bytes).filter(|value| !value.is_zero())
    }

    /// The integer of a message hash of any length, reduced modulo n.
    ///
    /// This is bits2int then reduction, per FIPS 186-4, section 6.4, and SEC 1, section 4.1.4, step 5.
    /// A hash longer than 384 bits keeps its leftmost 384 bits, which are its first 48 bytes.
    /// A shorter hash is read whole as a big-endian integer.
    pub(super) fn from_hash(hash: &[u8]) -> Self {
        // Left-pad a short hash, truncate a long one.
        let kept = &hash[..hash.len().min(LEN)];
        let mut bytes = [0_u8; LEN];
        bytes[LEN - kept.len()..].copy_from_slice(kept);

        // Any 384-bit value is below 2n, so one conditional subtraction reduces it.
        let value = U384::from_be_bytes(&bytes);
        let (reduced, borrow) = value.sub_with_borrow(Self::ORDER);
        Self(if borrow == 1 { value.0 } else { reduced.0 })
    }

    /// Encodes as 48 big-endian bytes.
    pub(super) fn to_bytes(self) -> [u8; 48] {
        self.to_uint().to_be_bytes()
    }

    /// The canonical value as an integer.
    pub(super) const fn to_uint(self) -> U384 {
        U384(self.0)
    }

    /// Holds when the scalar is zero.
    pub(super) fn is_zero(self) -> bool {
        self.0 == [0; 6]
    }

    /// The 4-bit digit at window i, bits 4i to 4i + 3.
    pub(super) const fn nibble(self, window: usize) -> usize {
        // Sixteen 4-bit windows per 64-bit limb.
        ((self.0[window / 16] >> ((window % 16) * 4)) & 0xf) as usize
    }

    /// The bit at position i.
    #[cfg(test)]
    pub(super) const fn bit(self, position: usize) -> u64 {
        (self.0[position / 64] >> (position % 64)) & 1
    }

    /// The sum.
    #[cfg(test)]
    #[must_use]
    pub(super) fn add(self, other: Self) -> Self {
        Self(MODULUS.add(self.0, other.0))
    }

    /// The additive inverse.
    #[cfg(test)]
    #[must_use]
    pub(super) fn neg(self) -> Self {
        Self(MODULUS.sub([0; 6], self.0))
    }

    /// The product.
    #[must_use]
    pub(super) fn mul(self, other: Self) -> Self {
        // mont(a, b) = a b / R, and mont(a b / R, R^2) = a b.
        Self(MODULUS.encode(MODULUS.mul(self.0, other.0)))
    }

    /// The inverse, by Fermat: a^(n - 2), and zero for zero.
    #[must_use]
    pub(super) fn invert(self) -> Self {
        // n - 2: the low limb of n ends in 0x73, so no borrow crosses limbs.
        let mut exponent = Self::ORDER;
        exponent.0[0] -= 2;
        let power = MODULUS.pow(MODULUS.encode(self.0), exponent);
        Self(MODULUS.decode(power))
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
            any::<[u8; 48]>().prop_map(|bytes| Scalar::from_hash(&bytes)),
            (0_u64..4).prop_map(|k| Scalar([k, 0, 0, 0, 0, 0])),
            (1_u64..4).prop_map(move |k| {
                let mut limbs = n;
                limbs[0] -= k;
                Scalar(limbs)
            }),
        ]
    }

    /// The product by shift-and-add, using only addition.
    fn mul_reference(a: Scalar, b: Scalar) -> Scalar {
        // Scan the bits of b from the top: acc = 2 acc + bit * a.
        let mut acc = Scalar::ZERO;
        for bit in (0..384).rev() {
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
        n_minus_one[47] -= 1;
        assert_eq!(Scalar::from_bytes(&n_minus_one), Some(Scalar::ONE.neg()));
        assert_eq!(Scalar::from_bytes(&Scalar::ORDER.to_be_bytes()), None);
        assert_eq!(
            Scalar::from_hash(&Scalar::ORDER.to_be_bytes()),
            Scalar::ZERO
        );

        // 2^384 - 1 reduces to 2^384 - 1 - n.
        let (expected, _) = U384([u64::MAX; 6]).sub_with_borrow(Scalar::ORDER);
        assert_eq!(Scalar::from_hash(&[0xff; 48]), Scalar(expected.0));

        // Zero is a scalar but not a non-zero one.
        assert_eq!(Scalar::from_bytes_nonzero(&[0; 48]), None);
        assert_eq!(Scalar::from_bytes(&[0; 48]), Some(Scalar::ZERO));
    }

    #[test]
    fn hashes_of_every_length() {
        // A 32-byte hash is read whole: 0x01 followed by 31 zero bytes is 2^248.
        let mut short = [0_u8; 32];
        short[0] = 1;
        let mut expected = [0_u8; 48];
        expected[16] = 1;
        assert_eq!(Scalar::from_hash(&short).to_bytes(), expected);

        // A 64-byte hash keeps its first 48 bytes: the trailing 0xff bytes vanish.
        let mut long = [0xff_u8; 64];
        long[..48].fill(0);
        long[47] = 7;
        let mut seven = [0_u8; 48];
        seven[47] = 7;
        assert_eq!(Scalar::from_hash(&long).to_bytes(), seven);

        // The empty hash is zero.
        assert_eq!(Scalar::from_hash(&[]), Scalar::ZERO);
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
            if !a.is_zero() {
                prop_assert_eq!(a.mul(a.invert()), Scalar::ONE);
            }
        }

        #[test]
        fn bytes_round_trip(a in arb_scalar()) {
            prop_assert_eq!(Scalar::from_bytes(&a.to_bytes()), Some(a));
        }
    }
}
