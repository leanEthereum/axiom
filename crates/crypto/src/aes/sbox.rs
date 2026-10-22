//! The bitsliced AES S-box: sixteen bytes as eight bit planes through one Boolean circuit.
//!
//! Table-driven AES leaks its key through cache timing, as Bernstein showed in 2005.
//! Here the S-box is a fixed Boolean circuit, so no address depends on data.

/// Sixteen bytes stored as eight bit planes, plane i holding bit i of every byte.
///
/// Lane k of each plane belongs to byte k, so one gate acts on all sixteen bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BitPlanes([u32; 8]);

impl BitPlanes {
    /// Splits sixteen bytes into bit planes.
    ///
    /// # Algorithm
    ///
    /// Each half is an 8 x 8 bit matrix, and transposing turns its rows into planes.
    ///
    /// The 16 input bytes b0 to b15 pass through two 8 x 8 bit transposes.
    /// The result is eight planes p0 to p7, with 16 lanes each.
    pub(super) fn from_bytes(bytes: &[u8; 16]) -> Self {
        let (halves, _) = bytes.as_chunks::<8>();
        let low = Self::transpose_8x8(u64::from_le_bytes(halves[0]));
        let high = Self::transpose_8x8(u64::from_le_bytes(halves[1]));

        // Plane i: bytes 0..7 in lanes 0..7 from the low half, bytes 8..15 in lanes 8..15.
        let mut planes = [0_u32; 8];
        for (i, plane) in planes.iter_mut().enumerate() {
            *plane = ((low >> (8 * i)) & 0xff) as u32 | ((((high >> (8 * i)) & 0xff) as u32) << 8);
        }
        Self(planes)
    }

    /// Gathers the bit planes back into sixteen bytes.
    pub(super) fn to_bytes(self) -> [u8; 16] {
        // Gather each half's planes, then transpose again.
        // The transpose is its own inverse.
        let mut low = 0_u64;
        let mut high = 0_u64;
        for (i, plane) in self.0.iter().enumerate() {
            low |= u64::from(plane & 0xff) << (8 * i);
            high |= u64::from((plane >> 8) & 0xff) << (8 * i);
        }
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&Self::transpose_8x8(low).to_le_bytes());
        bytes[8..].copy_from_slice(&Self::transpose_8x8(high).to_le_bytes());
        bytes
    }

    /// Applies the AES S-box to every lane with a Boolean circuit.
    ///
    /// The circuit of Boyar and Peralta, "A depth-16 circuit for the AES S-box", 2011.
    /// It computes inversion in GF(2^8) through the tower field GF(((2^2)^2)^2), then the affine map.
    ///
    /// ```text
    /// top linear map    : 8 inputs -> 22 intermediate bits
    /// non-linear middle : GF(2^4) inversion, 32 AND gates in all
    /// bottom linear map : 18 products -> 8 outputs, with the constant 0x63 folded in as NOTs
    /// ```
    #[expect(
        clippy::too_many_lines,
        reason = "one line per gate keeps the circuit auditable"
    )]
    pub(super) const fn substitute(&mut self) {
        // Inputs, most significant plane first.
        let q = &mut self.0;
        let x0 = q[7];
        let x1 = q[6];
        let x2 = q[5];
        let x3 = q[4];
        let x4 = q[3];
        let x5 = q[2];
        let x6 = q[1];
        let x7 = q[0];

        // Top linear transformation.
        let y14 = x3 ^ x5;
        let y13 = x0 ^ x6;
        let y9 = x0 ^ x3;
        let y8 = x0 ^ x5;
        let t0 = x1 ^ x2;
        let y1 = t0 ^ x7;
        let y4 = y1 ^ x3;
        let y12 = y13 ^ y14;
        let y2 = y1 ^ x0;
        let y5 = y1 ^ x6;
        let y3 = y5 ^ y8;
        let t1 = x4 ^ y12;
        let y15 = t1 ^ x5;
        let y20 = t1 ^ x1;
        let y6 = y15 ^ x7;
        let y10 = y15 ^ t0;
        let y11 = y20 ^ y9;
        let y7 = x7 ^ y11;
        let y17 = y10 ^ y11;
        let y19 = y10 ^ y8;
        let y16 = t0 ^ y11;
        let y21 = y13 ^ y16;
        let y18 = x0 ^ y16;

        // Non-linear section: products in GF(2^4), then its inversion.
        let t2 = y12 & y15;
        let t3 = y3 & y6;
        let t4 = t3 ^ t2;
        let t5 = y4 & x7;
        let t6 = t5 ^ t2;
        let t7 = y13 & y16;
        let t8 = y5 & y1;
        let t9 = t8 ^ t7;
        let t10 = y2 & y7;
        let t11 = t10 ^ t7;
        let t12 = y9 & y11;
        let t13 = y14 & y17;
        let t14 = t13 ^ t12;
        let t15 = y8 & y10;
        let t16 = t15 ^ t12;
        let t17 = t4 ^ t14;
        let t18 = t6 ^ t16;
        let t19 = t9 ^ t14;
        let t20 = t11 ^ t16;
        let t21 = t17 ^ y20;
        let t22 = t18 ^ y19;
        let t23 = t19 ^ y21;
        let t24 = t20 ^ y18;

        let t25 = t21 ^ t22;
        let t26 = t21 & t23;
        let t27 = t24 ^ t26;
        let t28 = t25 & t27;
        let t29 = t28 ^ t22;
        let t30 = t23 ^ t24;
        let t31 = t22 ^ t26;
        let t32 = t31 & t30;
        let t33 = t32 ^ t24;
        let t34 = t23 ^ t33;
        let t35 = t27 ^ t33;
        let t36 = t24 & t35;
        let t37 = t36 ^ t34;
        let t38 = t27 ^ t36;
        let t39 = t29 & t38;
        let t40 = t25 ^ t39;

        let t41 = t40 ^ t37;
        let t42 = t29 ^ t33;
        let t43 = t29 ^ t40;
        let t44 = t33 ^ t37;
        let t45 = t42 ^ t41;
        let z0 = t44 & y15;
        let z1 = t37 & y6;
        let z2 = t33 & x7;
        let z3 = t43 & y16;
        let z4 = t40 & y1;
        let z5 = t29 & y7;
        let z6 = t42 & y11;
        let z7 = t45 & y17;
        let z8 = t41 & y10;
        let z9 = t44 & y12;
        let z10 = t37 & y3;
        let z11 = t33 & y4;
        let z12 = t43 & y13;
        let z13 = t40 & y5;
        let z14 = t29 & y2;
        let z15 = t42 & y9;
        let z16 = t45 & y14;
        let z17 = t41 & y8;

        // Bottom linear transformation, with the affine constant 0x63 as complements.
        let t46 = z15 ^ z16;
        let t47 = z10 ^ z11;
        let t48 = z5 ^ z13;
        let t49 = z9 ^ z10;
        let t50 = z2 ^ z12;
        let t51 = z2 ^ z5;
        let t52 = z7 ^ z8;
        let t53 = z0 ^ z3;
        let t54 = z6 ^ z7;
        let t55 = z16 ^ z17;
        let t56 = z12 ^ t48;
        let t57 = t50 ^ t53;
        let t58 = z4 ^ t46;
        let t59 = z3 ^ t54;
        let t60 = t46 ^ t57;
        let t61 = z14 ^ t57;
        let t62 = t52 ^ t58;
        let t63 = t49 ^ t58;
        let t64 = z4 ^ t59;
        let t65 = t61 ^ t62;
        let t66 = z1 ^ t63;
        let s0 = t59 ^ t63;
        let s6 = t56 ^ !t62;
        let s7 = t48 ^ !t60;
        let t67 = t64 ^ t65;
        let s3 = t53 ^ t66;
        let s4 = t51 ^ t66;
        let s5 = t47 ^ t65;
        let s1 = t64 ^ !s3;
        let s2 = t55 ^ !t67;

        // Outputs, most significant plane first.
        *q = [s7, s6, s5, s4, s3, s2, s1, s0];
    }

    /// Transposes an 8 x 8 bit matrix: bit 8r + c moves to bit 8c + r.
    ///
    /// Three delta swaps exchange off-diagonal blocks of size 1, 2, then 4.
    /// The method is that of Hacker's Delight, section 7-3.
    const fn transpose_8x8(mut x: u64) -> u64 {
        // Swap 1 x 1 blocks: bit (r, c) with (r + 1, c - 1) for even r and odd c.
        let t = (x ^ (x >> 7)) & 0x00aa_00aa_00aa_00aa;
        x ^= t ^ (t << 7);
        let t = (x ^ (x >> 14)) & 0x0000_cccc_0000_cccc;
        x ^= t ^ (t << 14);
        let t = (x ^ (x >> 28)) & 0x0000_0000_f0f0_f0f0;
        x ^ t ^ (t << 28)
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use proptest::prelude::*;

    use super::*;
    use crate::aes::state::tests::gf_mul;

    /// The S-box from its definition: inversion, then the affine map of FIPS 197, section 5.1.1.
    fn sbox_reference(byte: u8) -> u8 {
        // a^254 = a^-1 in GF(2^8), and 0 maps to 0.
        let mut inverse = 1_u8;
        for _ in 0..254 {
            inverse = gf_mul(inverse, byte);
        }
        inverse
            ^ inverse.rotate_left(1)
            ^ inverse.rotate_left(2)
            ^ inverse.rotate_left(3)
            ^ inverse.rotate_left(4)
            ^ 0x63
    }

    #[test]
    fn circuit_matches_the_definition_for_every_byte_and_lane() {
        // All 256 inputs, each tried in all 16 lane positions with distinct neighbours.
        for byte in 0..=255_u8 {
            let block: [u8; 16] = array::from_fn(|i| byte.wrapping_add(i as u8 * 17));
            let expected = block.map(sbox_reference);
            let mut planes = BitPlanes::from_bytes(&block);
            planes.substitute();
            assert_eq!(planes.to_bytes(), expected, "input {byte:#04x}");
        }

        // Spot values of FIPS 197, figure 7.
        assert_eq!(sbox_reference(0x00), 0x63);
        assert_eq!(sbox_reference(0x53), 0xed);
    }

    proptest! {
        #[test]
        fn transpose_is_an_involution(x in any::<u64>()) {
            // Transposing twice restores the matrix, and bit (r, c) lands at (c, r).
            prop_assert_eq!(BitPlanes::transpose_8x8(BitPlanes::transpose_8x8(x)), x);
            let t = BitPlanes::transpose_8x8(x);
            for r in 0..8 {
                for c in 0..8 {
                    prop_assert_eq!((x >> (8 * r + c)) & 1, (t >> (8 * c + r)) & 1);
                }
            }
        }

        #[test]
        fn planes_round_trip(bytes in any::<[u8; 16]>()) {
            // Splitting into planes and gathering them back is the identity.
            prop_assert_eq!(BitPlanes::from_bytes(&bytes).to_bytes(), bytes);
        }
    }
}
