//! The group G1: the order-r subgroup of E(F_p), where E is y^2 = x^3 + 4.
//!
//! The full group E(F_p) has order h * r with cofactor h = (x - 1)^2 / 3.
//! Signatures in the minimal-pubkey-size variant keep public keys here, at 48 bytes each.

mod affine;
mod projective;

pub use affine::{G1_COMPRESSED_BYTES, G1_UNCOMPRESSED_BYTES, G1Affine};
pub use projective::G1Projective;

use crate::Fp;

/// The curve constant b = 4.
const B: Fp = Fp::from_montgomery([
    0xaa27_0000_000c_fff3,
    0x53cc_0032_fc34_000a,
    0x478f_e97a_6b0a_807f,
    0xb1d3_7ebe_e6ba_24d7,
    0x8ec9_733b_bf78_ab2f,
    0x09d6_4551_3d83_de7e,
]);

/// The constant 3b = 12, which the complete addition formulas multiply by.
const B3: Fp = Fp::from_montgomery([
    0x4476_0000_0027_552e,
    0xdcb8_009a_4348_0020,
    0x6f7e_e9ce_4a6e_8b59,
    0xb103_30b7_c0a9_5bc6,
    0x6140_b1fc_fb1e_54b7,
    0x0381_be09_7f0b_b4e1,
]);

/// A primitive cube root of unity in F_p.
///
/// The map (x, y) -> (beta x, y) is an endomorphism of E, because (beta x)^3 = x^3.
/// On G1 it acts as multiplication by -x^2, a cube root of unity modulo r.
/// This root is the one of the two that matches -x^2 rather than x^2 - 1.
const BETA: Fp = Fp::from_montgomery([
    0x30f1_361b_798a_64e8,
    0xf3b8_ddab_7ece_5a2a,
    0x16a8_ca3a_c615_77f7,
    0xc26a_2ff8_74fd_029b,
    0x3636_b766_6070_1c6e,
    0x051b_a4ab_241b_6160,
]);

/// The x-coordinate of the standard generator, from the ZCash specification.
const GENERATOR_X: Fp = Fp::from_montgomery([
    0x5cb3_8790_fd53_0c16,
    0x7817_fc67_9976_fff5,
    0x154f_95c7_143b_a1c1,
    0xf0ae_6acd_f3d0_e747,
    0xedce_6ecc_21db_f440,
    0x1201_7741_9e0b_fb75,
]);

/// The y-coordinate of the standard generator.
const GENERATOR_Y: Fp = Fp::from_montgomery([
    0xbaac_93d5_0ce7_2271,
    0x8c22_631a_7918_fd8e,
    0xdd59_5f13_5707_25ce,
    0x51ac_5829_5040_5194,
    0x0e1c_8c3f_ad00_59c0,
    0x0bbc_3efc_5008_a26a,
]);
