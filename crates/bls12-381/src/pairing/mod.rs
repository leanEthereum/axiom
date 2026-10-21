//! The optimal ate pairing e: G1 x G2 -> GT, and the target group GT.
//!
//! # Overview
//!
//! The pairing is bilinear and non-degenerate:
//!
//! ```text
//!     e([a] P, [b] Q) = e(P, Q)^{a b},     e(G1 generator, G2 generator) != 1
//! ```
//!
//! BLS verification checks an equality of two pairings.
//! Moving everything to one side turns it into "a product of pairings equals one".
//! That product shares one Miller loop and one final exponentiation, so it costs far less than two pairings.

mod final_exponentiation;
mod miller_loop;

use std::ops::{Mul, MulAssign};

use crate::{BLS_X, Fp12, G1Affine, G2Affine};

/// An element of GT, the order-r subgroup of the multiplicative group of F_{p^12}.
///
/// The group is written multiplicatively: the operator for the group law is multiplication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gt(Fp12);

impl Gt {
    /// The identity of GT, the field element one.
    pub const IDENTITY: Self = Self(Fp12::ONE);

    /// Computes the pairing e(P, Q).
    #[must_use]
    pub fn pairing(p: &G1Affine, q: &G2Affine) -> Self {
        Self::multi_pairing(&[(*p, *q)])
    }

    /// Computes the product of the pairings of every pair, prod_i e(P_i, Q_i).
    ///
    /// One shared Miller loop and one final exponentiation serve every pair.
    /// An empty product, or a product of pairs with an infinite point, is the identity.
    #[must_use]
    pub fn multi_pairing(terms: &[(G1Affine, G2Affine)]) -> Self {
        let f = miller_loop::multi_miller_loop(terms);
        Self(final_exponentiation::final_exponentiation(&f))
    }

    /// Whether this is the identity of GT.
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.0 == Fp12::ONE
    }

    /// Returns the inverse, which on GT is the conjugate.
    #[must_use]
    pub fn invert(&self) -> Self {
        // Every element of GT satisfies x^{p^6 + 1} = 1, so x^{-1} = x^{p^6} = conj(x).
        Self(self.0.conjugate())
    }

    /// The underlying element of F_{p^12}.
    #[must_use]
    pub const fn as_fp12(&self) -> &Fp12 {
        &self.0
    }
}

impl Default for Gt {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl Mul for Gt {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self(self.0 * rhs.0)
    }
}

impl Mul<&Self> for Gt {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self {
        Self(self.0 * rhs.0)
    }
}

impl MulAssign for Gt {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl MulAssign<&Self> for Gt {
    fn mul_assign(&mut self, rhs: &Self) {
        self.0 *= rhs.0;
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{
        G1Projective, G2Projective, Scalar, fp12::tests::arb_fp12, scalar::tests::arb_scalar,
    };

    /// Raises an element of F_{p^12} to a power given as little-endian limbs.
    fn pow(base: &Fp12, exponent: &[u64]) -> Fp12 {
        let mut result = Fp12::ONE;
        for limb in exponent.iter().rev() {
            for bit in (0..64).rev() {
                result = result.square();
                if (limb >> bit) & 1 == 1 {
                    result *= base;
                }
            }
        }
        result
    }

    /// Raises an element of GT to a scalar.
    fn gt_pow(base: &Gt, scalar: &Scalar) -> Gt {
        Gt(pow(&base.0, &scalar.to_canonical()))
    }

    /// The hard-part exponent 3 (p^4 - p^2 + 1) / r, little-endian limbs.
    const HARD_EXPONENT_TIMES_3: [u64; 20] = [
        0xaf44_4bdc_aaab_2f6b,
        0xefcb_3800_a61a_66d5,
        0xb116_bba5_9a18_123a,
        0x554e_727d_129b_e6a3,
        0x8a65_dbc1_cc35_fe5a,
        0x6574_220c_23e5_b6cc,
        0x8c72_178b_c76a_791c,
        0xb415_c7da_454d_4863,
        0x37d4_7f63_9b68_a630,
        0x6a6a_2b0a_b1c4_7526,
        0x6c9a_e962_5394_f594,
        0x6163_cbf0_0bf5_66e4,
        0x877c_5e22_f263_9411,
        0xb0f5_836b_a82b_62de,
        0xe3ae_662e_47a2_4ea0,
        0x8d69_012b_6d18_3f47,
        0xbcf1_3296_f7a8_3fce,
        0x7b69_b9ac_c2cc_45ea,
        0x4237_aa49_4c15_9cdc,
        0x002e_3941_b881_7705,
    ];

    /// The group order r.
    const ORDER: [u64; 4] = [
        0xffff_ffff_0000_0001,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ];

    #[test]
    fn pairing_of_generators_is_a_nontrivial_rth_root_of_unity() {
        let e = Gt::pairing(&G1Affine::GENERATOR, &G2Affine::GENERATOR);
        // Non-degeneracy: the generators do not pair to one.
        assert!(!e.is_identity());
        // The value lies in GT: its r-th power is one.
        assert_eq!(pow(&e.0, &ORDER), Fp12::ONE);
    }

    #[test]
    fn infinity_pairs_to_identity() {
        assert!(Gt::pairing(&G1Affine::IDENTITY, &G2Affine::GENERATOR).is_identity());
        assert!(Gt::pairing(&G1Affine::GENERATOR, &G2Affine::IDENTITY).is_identity());
        assert!(Gt::multi_pairing(&[]).is_identity());
    }

    #[test]
    fn negated_pairs_cancel() {
        // e(P, Q) * e(-P, Q) = e(O, Q) = 1: the shape of every BLS verification.
        let p = G1Affine::GENERATOR;
        let q = G2Affine::GENERATOR;
        assert!(Gt::multi_pairing(&[(p, q), (-p, q)]).is_identity());
    }

    #[test]
    fn exp_by_x_matches_generic_power() {
        // On a cyclotomic element, the sign of x turns into a conjugation.
        let e = Gt::pairing(&G1Affine::GENERATOR, &G2Affine::GENERATOR).0;
        let expected = pow(&e, &[BLS_X]).conjugate();
        assert_eq!(final_exponentiation::exp_by_x(&e), expected);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn bilinearity_holds(a in arb_scalar(), b in arb_scalar()) {
            // e([a] P, [b] Q) = e(P, Q)^{a b}
            let p = G1Affine::from(G1Projective::GENERATOR * a);
            let q = G2Affine::from(G2Projective::GENERATOR * b);
            let base = Gt::pairing(&G1Affine::GENERATOR, &G2Affine::GENERATOR);
            prop_assert_eq!(Gt::pairing(&p, &q), gt_pow(&base, &(a * b)));
        }

        #[test]
        fn multi_pairing_is_the_product_of_pairings(a in arb_scalar(), b in arb_scalar()) {
            let p1 = G1Affine::from(G1Projective::GENERATOR * a);
            let q2 = G2Affine::from(G2Projective::GENERATOR * b);
            let terms = [(p1, G2Affine::GENERATOR), (G1Affine::GENERATOR, q2)];
            let expected =
                Gt::pairing(&p1, &G2Affine::GENERATOR) * Gt::pairing(&G1Affine::GENERATOR, &q2);
            prop_assert_eq!(Gt::multi_pairing(&terms), expected);
        }

        #[test]
        fn final_exponentiation_matches_the_generic_exponent(f in arb_fp12()) {
            prop_assume!(!f.is_zero());
            // Easy part done generically, then the hard exponent by plain square-and-multiply.
            let t = f.conjugate() * f.invert().unwrap();
            let t = t.frobenius_map().frobenius_map() * t;
            let expected = pow(&t, &HARD_EXPONENT_TIMES_3);
            prop_assert_eq!(final_exponentiation::final_exponentiation(&f), expected);
        }
    }
}
