//! The map from F_{p^2} to the twist: simplified SWU on an isogenous curve, then a 3-isogeny.
//!
//! # Overview
//!
//! Simplified SWU needs a curve y^2 = x^3 + A x + B with A B != 0, which the twist (A = 0) is not.
//! RFC 9380 section 6.6.3 therefore maps to a 3-isogenous curve E2' with A' B' != 0.
//! An isogeny then carries the point back.
//!
//! The map runs in two steps:
//!
//! 1. Simplified SWU sends u in F_{p^2} to a point (x', y') on E2'.
//! 2. The 3-isogeny sends (x', y') to a point (x, y) on E'.
//!
//! The output is a point of E', not yet of G2.
//! Cofactor clearing finishes the job.
//! Every input here is public (it derives from the message), so variable-time square roots are fine.

use crate::{Fp, Fp2, G2Projective};

/// The coefficient A' = 240 u of E2', RFC 9380 section 8.8.2.
const A: Fp2 = Fp2::new(
    Fp::ZERO,
    Fp::from_montgomery([
        0xe53a_0000_0313_5242,
        0x0108_0c0f_def8_0285,
        0xe788_9edb_e340_f6bd,
        0x0b51_3751_2631_0601,
        0x02d6_9857_17c7_44ab,
        0x1220_b4e9_79ea_5467,
    ]),
);

/// The coefficient B' = 1012 (1 + u) of E2'.
const B: Fp2 = Fp2::new(
    Fp::from_montgomery([
        0x22ea_0000_0cf8_9db2,
        0x6ec8_32df_7138_0aa4,
        0x6e1b_9440_3db5_a66e,
        0x75bf_3c53_a794_73ba,
        0x3dd3_a569_412c_0a34,
        0x125c_db5e_74dc_4fd1,
    ]),
    Fp::from_montgomery([
        0x22ea_0000_0cf8_9db2,
        0x6ec8_32df_7138_0aa4,
        0x6e1b_9440_3db5_a66e,
        0x75bf_3c53_a794_73ba,
        0x3dd3_a569_412c_0a34,
        0x125c_db5e_74dc_4fd1,
    ]),
);

/// The non-square Z = -(2 + u) chosen by RFC 9380 appendix H.2 for this suite.
const Z: Fp2 = Fp2::new(
    Fp::from_montgomery([
        0x87eb_ffff_fff9_555c,
        0x656f_ffe5_da8f_fffa,
        0x0fd0_7493_45d3_3ad2,
        0xd951_e663_0665_76f4,
        0xde29_1a3d_41e9_80d3,
        0x0815_664c_7dfe_040d,
    ]),
    Fp::from_montgomery([
        0x43f5_ffff_fffc_aaae,
        0x32b7_fff2_ed47_fffd,
        0x07e8_3a49_a2e9_9d69,
        0xeca8_f331_8332_bb7a,
        0xef14_8d1e_a0f4_c069,
        0x040a_b326_3eff_0206,
    ]),
);

/// The constant -B' / A', precomputed for the first SWU candidate.
const MINUS_B_OVER_A: Fp2 = Fp2::new(
    Fp::from_montgomery([
        0x903c_5555_5547_4fb3,
        0x5f98_cc95_ce45_1105,
        0x9f8e_582e_efe0_fade,
        0xc689_46b6_aebb_d062,
        0x467a_4ad1_0ee6_de53,
        0x0e71_46f4_83e2_3a05,
    ]),
    Fp::from_montgomery([
        0x29c2_aaaa_aab8_5af8,
        0xbf13_3368_e30e_eefa,
        0xc7a2_7a72_06cf_fb45,
        0x9dee_04ce_44c9_425c,
        0x04a1_5ce5_3464_ce83,
        0x0b8f_caf5_b59d_ac95,
    ]),
);

/// The constant B' / (Z A'), the first candidate in the exceptional case.
const B_OVER_ZA: Fp2 = Fp2::new(
    Fp::from_montgomery([
        0xf2d8_4444_4441_4324,
        0x2585_c283_93a6_9d00,
        0x5dd3_5cd0_5d97_2c42,
        0xfd96_3b74_4ea8_9b53,
        0x07f5_d9fd_91c1_fa91,
        0x127d_b28a_3ce0_62c4,
    ]),
    Fp::from_montgomery([
        0x5574_3333_333b_3695,
        0xeb72_b871_5908_28fc,
        0x1c18_6171_cb4d_5da5,
        0x34a3_3031_ee95_6644,
        0xc971_692a_149d_16d0,
        0x168a_1e1f_f5de_8b82,
    ]),
);

/// Coefficients k_(1,0..3) of the isogeny's x numerator, RFC 9380 appendix E.3.
const X_NUM: Polynomial = Polynomial {
    coefficients: &[
        Fp2::new(
            Fp::from_montgomery([
                0x47f6_71c7_1ce0_5e62,
                0x06dd_5707_1206_393e,
                0x7c80_cd2a_f3fd_71a2,
                0x0481_03ea_9e6c_d062,
                0xc545_16ac_c8d0_37f6,
                0x1380_8f55_0920_ea41,
            ]),
            Fp::from_montgomery([
                0x47f6_71c7_1ce0_5e62,
                0x06dd_5707_1206_393e,
                0x7c80_cd2a_f3fd_71a2,
                0x0481_03ea_9e6c_d062,
                0xc545_16ac_c8d0_37f6,
                0x1380_8f55_0920_ea41,
            ]),
        ),
        Fp2::new(
            Fp::ZERO,
            Fp::from_montgomery([
                0x5fe5_5555_554c_71d0,
                0x873f_ffdd_236a_aaa3,
                0x6a6b_4619_b26e_f918,
                0x21c2_8884_0887_4945,
                0x2836_cda7_028c_abc5,
                0x0ac7_3310_a7fd_5abd,
            ]),
        ),
        Fp2::new(
            Fp::from_montgomery([
                0x0a0c_5555_5559_71c3,
                0xdb0c_0010_1f9e_aaae,
                0xb1fb_2f94_1d79_7997,
                0xd396_0742_ef41_6e1c,
                0xb700_40e2_c205_56f4,
                0x149d_7861_e581_393b,
            ]),
            Fp::from_montgomery([
                0xaff2_aaaa_aaa6_38e8,
                0x439f_ffee_91b5_5551,
                0xb535_a30c_d937_7c8c,
                0x90e1_4442_0443_a4a2,
                0x941b_66d3_8146_55e2,
                0x0563_9988_53fe_ad5e,
            ]),
        ),
        Fp2::new(
            Fp::from_montgomery([
                0x40aa_c71c_71c7_25ed,
                0x1909_5555_7a84_e38e,
                0xd817_050a_8f41_abc3,
                0xd864_85d4_c87f_6fb1,
                0x696e_b479_f885_d059,
                0x198e_1a74_3280_02d2,
            ]),
            Fp::ZERO,
        ),
    ],
    monic: false,
};

/// Coefficients k_(2,0..1) of the monic x denominator.
const X_DEN: Polynomial = Polynomial {
    coefficients: &[
        Fp2::new(
            Fp::ZERO,
            Fp::from_montgomery([
                0x1f3a_ffff_ff13_ab97,
                0xf25b_fc61_1da3_ff3e,
                0xca37_57cb_3819_b208,
                0x3e64_2736_6f8c_ec18,
                0x0397_7bc8_6095_b089,
                0x04f6_9db1_3f39_a952,
            ]),
        ),
        Fp2::new(
            Fp::from_montgomery([
                0x4476_0000_0027_552e,
                0xdcb8_009a_4348_0020,
                0x6f7e_e9ce_4a6e_8b59,
                0xb103_30b7_c0a9_5bc6,
                0x6140_b1fc_fb1e_54b7,
                0x0381_be09_7f0b_b4e1,
            ]),
            Fp::from_montgomery([
                0x7588_ffff_ffd8_557d,
                0x41f3_ff64_6e0b_ffdf,
                0xf7b1_e8d2_ac42_6aca,
                0xb374_1acd_32db_b6f8,
                0xe9da_f5b9_482d_581f,
                0x167f_53e0_ba74_31b8,
            ]),
        ),
    ],
    monic: true,
};

/// Coefficients k_(3,0..3) of the y numerator.
const Y_NUM: Polynomial = Polynomial {
    coefficients: &[
        Fp2::new(
            Fp::from_montgomery([
                0x96d8_f684_bdfc_77be,
                0xb530_e4f4_3b66_d0e2,
                0x184a_88ff_3796_52fd,
                0x57cb_23ec_fae8_04e1,
                0x0fd2_e39e_ada3_eba9,
                0x08c8_055e_31c5_d5c3,
            ]),
            Fp::from_montgomery([
                0x96d8_f684_bdfc_77be,
                0xb530_e4f4_3b66_d0e2,
                0x184a_88ff_3796_52fd,
                0x57cb_23ec_fae8_04e1,
                0x0fd2_e39e_ada3_eba9,
                0x08c8_055e_31c5_d5c3,
            ]),
        ),
        Fp2::new(
            Fp::ZERO,
            Fp::from_montgomery([
                0xbf0a_71c7_1c91_b406,
                0x4d6d_55d2_8b76_38fd,
                0x9d82_f98e_5f20_5aee,
                0xa27a_a27b_1d1a_18d5,
                0x02c3_b2b2_d293_8e86,
                0x0c7d_1342_0b09_807f,
            ]),
        ),
        Fp2::new(
            Fp::from_montgomery([
                0xd7f9_5555_5553_1c74,
                0x21cf_fff7_48da_aaa8,
                0x5a9a_d186_6c9b_be46,
                0x4870_a221_0221_d251,
                0x4a0d_b369_c0a3_2af1,
                0x02b1_ccc4_29ff_56af,
            ]),
            Fp::from_montgomery([
                0xe205_aaaa_aaac_8e37,
                0xfcdc_0007_6879_5556,
                0x0c96_011a_8a15_37dd,
                0x1c06_a963_f163_406e,
                0x010d_f44c_82a8_81e6,
                0x174f_4526_0f80_8feb,
            ]),
        ),
        Fp2::new(
            Fp::from_montgomery([
                0xa470_bda1_2f67_f35c,
                0xc0fe_38e2_3327_b425,
                0xc9d3_d0f2_c6f0_678d,
                0x1c55_c993_5b5a_982e,
                0x27f6_c0e2_f074_6764,
                0x117c_5e6e_28aa_9054,
            ]),
            Fp::ZERO,
        ),
    ],
    monic: false,
};

/// Coefficients k_(4,0..2) of the monic y denominator.
const Y_DEN: Polynomial = Polynomial {
    coefficients: &[
        Fp2::new(
            Fp::from_montgomery([
                0x0162_ffff_fa76_5adf,
                0x8f7b_ea48_0083_fb75,
                0x561b_3c22_59e9_3611,
                0x11e1_9fc1_a9c8_75d5,
                0xca71_3efc_0036_7660,
                0x03c6_a03d_41da_1151,
            ]),
            Fp::from_montgomery([
                0x0162_ffff_fa76_5adf,
                0x8f7b_ea48_0083_fb75,
                0x561b_3c22_59e9_3611,
                0x11e1_9fc1_a9c8_75d5,
                0xca71_3efc_0036_7660,
                0x03c6_a03d_41da_1151,
            ]),
        ),
        Fp2::new(
            Fp::ZERO,
            Fp::from_montgomery([
                0x5db0_ffff_fd3b_02c5,
                0xd713_f523_58eb_fdba,
                0x5ea6_0761_a84d_161a,
                0xbb2c_75a3_4ea6_c44a,
                0x0ac6_7359_21c1_119b,
                0x0ee3_d913_bdac_fbf6,
            ]),
        ),
        Fp2::new(
            Fp::from_montgomery([
                0x66b1_0000_003a_ffc5,
                0xcb14_00e7_64ec_0030,
                0xa73e_5eb5_6fa5_d106,
                0x8984_c913_a0fe_09a9,
                0x11e1_0afb_78ad_7f13,
                0x0542_9d0e_3e91_8f52,
            ]),
            Fp::from_montgomery([
                0x534d_ffff_ffc4_aae6,
                0x5397_ff17_4c67_ffcf,
                0xbff2_73eb_870b_251d,
                0xdaf2_8271_5287_0915,
                0x393a_9cba_ca9e_2dc3,
                0x14be_74db_faee_5748,
            ]),
        ),
    ],
    monic: true,
};

/// A polynomial over F_{p^2}, with coefficients in ascending degree.
#[derive(Clone, Copy, Debug)]
struct Polynomial {
    /// The coefficients, constant term first.
    coefficients: &'static [Fp2],
    /// Whether one more, implicit, leading coefficient equal to one follows.
    monic: bool,
}

impl Polynomial {
    /// Evaluates the polynomial at x by Horner's rule.
    fn evaluate(&self, x: &Fp2) -> Fp2 {
        // Start from the leading coefficient and fold in one degree per step.
        //
        //     c_0 + x (c_1 + x (c_2 + x c_3))
        let mut acc = if self.monic { Fp2::ONE } else { Fp2::ZERO };
        for coefficient in self.coefficients.iter().rev() {
            acc = acc * x + coefficient;
        }
        acc
    }
}

/// An affine point of the isogenous curve E2': y^2 = x^3 + A' x + B'.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IsoPoint {
    /// The x-coordinate.
    x: Fp2,
    /// The y-coordinate.
    y: Fp2,
}

impl IsoPoint {
    /// Maps a field element to E2' by the simplified Shallue-van de Woestijne-Ulas map.
    ///
    /// The map is deterministic and well-distributed, but not uniform on its own.
    /// Hashing adds two images, which makes the sum indistinguishable from random.
    ///
    /// # Algorithm
    ///
    /// RFC 9380 section 6.6.2, in its plain (non straight-line) form.
    /// Two candidate abscissas are related so that g(x2) = Z^3 u^6 g(x1), where g(x) = x^3 + A' x + B'.
    /// Z is a non-square, so exactly one of g(x1), g(x2) is a square, and that one gives the point.
    pub(crate) fn from_field(u: &Fp2) -> Self {
        // tv1 = Z^2 u^4 + Z u^2
        let z_u2 = Z * u.square();
        let tv1 = z_u2.square() + z_u2;

        // x1 = (-B' / A') (1 + 1 / tv1), or B' / (Z A') in the exceptional case tv1 = 0.
        let x1 = match tv1.invert() {
            Some(inverse) => MINUS_B_OVER_A * (Fp2::ONE + inverse),
            None => B_OVER_ZA,
        };
        let gx1 = Self::curve_rhs(&x1);

        // x2 = Z u^2 x1, the second candidate.
        let x2 = z_u2 * x1;

        // Pick the candidate whose right-hand side is a square.
        let (x, y) = match gx1.sqrt() {
            Some(y1) => (x1, y1),
            None => {
                // Invariant: g(x2) = (Z u^2)^3 g(x1) with Z u^2 a non-square.
                // g(x1) is a non-square here, so the product of two non-squares is a square.
                let y2 = Self::curve_rhs(&x2)
                    .sqrt()
                    .expect("g(x2) is a square whenever g(x1) is not");
                (x2, y2)
            }
        };

        // The sign of y follows the sign of u, which makes the map well defined.
        let y = if u.sgn0() == y.sgn0() { y } else { -y };
        Self { x, y }
    }

    /// Evaluates g(x) = x^3 + A' x + B', the right-hand side of E2'.
    fn curve_rhs(x: &Fp2) -> Fp2 {
        (x.square() + A) * x + B
    }

    /// Carries the point to the twist E' by the 3-isogeny of RFC 9380 appendix E.3.
    ///
    /// The affine map is a pair of rational functions:
    ///
    /// ```text
    ///     x = x_num(x') / x_den(x'),    y = y' * y_num(x') / y_den(x')
    /// ```
    ///
    /// Homogeneous coordinates absorb both denominators, so no inversion is needed:
    ///
    /// ```text
    ///     X = x_num * y_den,    Y = y' * y_num * x_den,    Z = x_den * y_den
    /// ```
    pub(crate) fn to_twist(self) -> G2Projective {
        let x_num = X_NUM.evaluate(&self.x);
        let x_den = X_DEN.evaluate(&self.x);
        let y_num = Y_NUM.evaluate(&self.x);
        let y_den = Y_DEN.evaluate(&self.x);
        G2Projective::from_coordinates(x_num * y_den, self.y * y_num * x_den, x_den * y_den)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{G2Affine, fp2::tests::arb_fp2};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn swu_lands_on_the_isogenous_curve(u in arb_fp2()) {
            let point = IsoPoint::from_field(&u);
            prop_assert_eq!(point.y.square(), IsoPoint::curve_rhs(&point.x));
            // The sign convention: y and u share their sgn0.
            prop_assert_eq!(point.y.sgn0(), u.sgn0());
        }

        #[test]
        fn isogeny_lands_on_the_twist(u in arb_fp2()) {
            let point = IsoPoint::from_field(&u).to_twist();
            prop_assert!(point.is_on_curve());
            prop_assert!(G2Affine::from(point).is_on_curve());
        }
    }

    #[test]
    fn exceptional_input_zero_is_handled() {
        // u = 0 makes tv1 = 0, the branch where x1 = B' / (Z A').
        let point = IsoPoint::from_field(&Fp2::ZERO);
        assert_eq!(point.x, B_OVER_ZA);
        assert_eq!(point.y.square(), IsoPoint::curve_rhs(&point.x));
    }
}
