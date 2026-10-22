//! The group G2: the order-r subgroup of E'(F_{p^2}), where E' is y^2 = x^3 + 4(1 + u).
//!
//! E' is the sextic M-twist of E: the map (x, y) -> (x / w^2, y / w^3) sends it into E(F_{p^12}).
//! Working on the twist keeps coordinates in F_{p^2} instead of F_{p^12}.
//! Signatures in the minimal-pubkey-size variant live here, at 96 bytes each.

mod affine;
mod projective;

pub use affine::{G2_COMPRESSED_BYTES, G2_UNCOMPRESSED_BYTES, G2Affine};
pub use projective::G2Projective;

use crate::{Fp, Fp2};

/// The curve constant b' = 4 + 4u of the twist.
const B: Fp2 = Fp2::new(FOUR, FOUR);

/// The base-field element 4, in Montgomery form.
const FOUR: Fp = Fp::from_montgomery([
    0xaa27_0000_000c_fff3,
    0x53cc_0032_fc34_000a,
    0x478f_e97a_6b0a_807f,
    0xb1d3_7ebe_e6ba_24d7,
    0x8ec9_733b_bf78_ab2f,
    0x09d6_4551_3d83_de7e,
]);

/// The x-coordinate of the standard generator, from the ZCash specification.
const GENERATOR_X: Fp2 = Fp2::new(
    Fp::from_montgomery([
        0xf5f2_8fa2_0294_0a10,
        0xb3f5_fb26_87b4_961a,
        0xa1a8_93b5_3e2a_e580,
        0x9894_999d_1a3c_aee9,
        0x6f67_b763_1863_366b,
        0x0581_9192_4350_bcd7,
    ]),
    Fp::from_montgomery([
        0xa5a9_c075_9e23_f606,
        0xaaa0_c59d_bccd_60c3,
        0x3bb1_7e18_e286_7806,
        0x1b1a_b6cc_8541_b367,
        0xc2b6_ed0e_f215_8547,
        0x1192_2a09_7360_edf3,
    ]),
);

/// The y-coordinate of the standard generator.
const GENERATOR_Y: Fp2 = Fp2::new(
    Fp::from_montgomery([
        0x4c73_0af8_6049_4c4a,
        0x597c_fa1f_5e36_9c5a,
        0xe7e6_856c_aa0a_635a,
        0xbbef_b5e9_6e0d_495f,
        0x07d3_a975_f0ef_25a2,
        0x0083_fd8e_7e80_dae5,
    ]),
    Fp::from_montgomery([
        0xadc0_fc92_df64_b05d,
        0x18aa_270a_2b14_61dc,
        0x86ad_ac6a_3be4_eba0,
        0x7949_5c4e_c93d_a33a,
        0xe717_5850_a43c_caed,
        0x0b2b_c2a1_63de_1bf2,
    ]),
);

/// The constant 1 / (1 + u)^{(p-1)/3} that scales x in the endomorphism psi.
///
/// RFC 9380 appendix G.3 defines psi = untwist, then Frobenius, then twist.
const PSI_X: Fp2 = Fp2::new(
    Fp::ZERO,
    Fp::from_montgomery([
        0x890d_c9e4_8675_45c3,
        0x2af3_2253_3285_a5d5,
        0x5088_0866_309b_7e2c,
        0xa20d_1b8c_7e88_1024,
        0x14e4_f04f_e2db_9068,
        0x14e5_6d3f_1564_853a,
    ]),
);

/// The constant 1 / (1 + u)^{(p-1)/2} that scales y in the endomorphism psi.
const PSI_Y: Fp2 = Fp2::new(
    Fp::from_montgomery([
        0x3e2f_585d_a55c_9ad1,
        0x4294_213d_86c1_8183,
        0x3828_44c8_8b62_3732,
        0x92ad_2afd_1910_3e18,
        0x1d79_4e4f_ac7c_f0b9,
        0x0bd5_92fc_7d82_5ec8,
    ]),
    Fp::from_montgomery([
        0x7bcf_a7a2_5aa3_0fda,
        0xdc17_dec1_2a92_7e7c,
        0x2f08_8dd8_6b4e_bef1,
        0xd1ca_2087_da74_d4a7,
        0x2da2_5966_96ce_bc1d,
        0x0e2b_7eed_bbfd_87d2,
    ]),
);

/// The constant 1 / 2^{(p-1)/3} that scales x in psi^2, a primitive cube root of unity in F_p.
///
/// Applying psi twice conjugates twice, so psi^2 needs no conjugation and y only flips sign.
const PSI2_X: Fp = Fp::from_montgomery([
    0xcd03_c9e4_8671_f071,
    0x5dab_2246_1fcd_a5d2,
    0x5870_42af_d385_1b95,
    0x8eb6_0ebe_01ba_cb9e,
    0x03f9_7d6e_83d0_50d2,
    0x18f0_2065_5463_8741,
]);
