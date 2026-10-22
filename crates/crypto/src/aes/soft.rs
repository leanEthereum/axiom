//! Portable AES-128 encryption without lookup tables, the reference for the hardware path.
//!
//! Table-driven AES leaks its key through cache timing, as Bernstein showed in 2005.
//! Here the S-box is a fixed Boolean circuit over bit planes, so no address depends on data.

/// Rounds of AES-128, per FIPS 197, section 5.
pub(super) const ROUNDS: usize = 10;

/// Round constants of the key schedule, per FIPS 197, section 5.2.
///
/// They are the successive powers of x in GF(2^8).
const RCON: [u8; ROUNDS] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// The eleven round keys of one AES-128 key, in the byte order of the state.
pub(super) type RoundKeys = [[u8; 16]; ROUNDS + 1];

/// Expands a 128-bit key into eleven round keys, per FIPS 197, section 5.2.
///
/// ```text
/// w[i] = w[i - 4] ^ SubWord(RotWord(w[i - 1])) ^ Rcon   when i = 0 mod 4
/// w[i] = w[i - 4] ^ w[i - 1]                            otherwise
/// ```
pub(super) fn expand_key(key: &[u8; 16]) -> RoundKeys {
    // Round key 0 is the key itself.
    let mut keys = [[0_u8; 16]; ROUNDS + 1];
    keys[0] = *key;
    for round in 1..=ROUNDS {
        let previous = keys[round - 1];

        // RotWord then SubWord on the last word of the previous round key.
        //
        // The S-box circuit works on 16 bytes at once.
        // The other 12 lanes are idle.
        let mut word = [0_u8; 16];
        word[..4].copy_from_slice(&[previous[13], previous[14], previous[15], previous[12]]);
        sub_bytes(&mut word);
        word[0] ^= RCON[round - 1];

        // Each word chains off the word before it.
        let mut next = [0_u8; 16];
        for i in 0..4 {
            next[i] = previous[i] ^ word[i];
        }
        for i in 4..16 {
            next[i] = previous[i] ^ next[i - 4];
        }
        keys[round] = next;
    }
    keys
}

/// Encrypts one block in place, per FIPS 197, section 5.1.
pub(super) fn encrypt_block(keys: &RoundKeys, block: &mut [u8; 16]) {
    // Initial whitening, then nine full rounds.
    add_round_key(block, &keys[0]);
    for key in &keys[1..ROUNDS] {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, key);
    }
    // The last round skips MixColumns.
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, &keys[ROUNDS]);
}

/// XORs a round key into the state.
fn add_round_key(block: &mut [u8; 16], key: &[u8; 16]) {
    // Byte-wise XOR: the only step that involves the key.
    for (byte, k) in block.iter_mut().zip(key) {
        *byte ^= k;
    }
}

/// Rotates row r of the state left by r positions.
///
/// The state is column-major: byte 4c + r sits in column c, row r.
///
/// ```text
/// row 0:  s0  s4  s8  s12        s0  s4  s8  s12
/// row 1:  s1  s5  s9  s13   ->   s5  s9  s13 s1
/// row 2:  s2  s6  s10 s14        s10 s14 s2  s6
/// row 3:  s3  s7  s11 s15        s15 s3  s7  s11
/// ```
fn shift_rows(block: &mut [u8; 16]) {
    // Read from a copy, since the rotation overwrites its own sources.
    let old = *block;
    for c in 0..4 {
        for r in 0..4 {
            block[4 * c + r] = old[4 * ((c + r) % 4) + r];
        }
    }
}

/// Multiplies every column by the fixed polynomial 3x^3 + x^2 + x + 2, per FIPS 197, section 5.1.3.
fn mix_columns(block: &mut [u8; 16]) {
    // Each 4-byte column is one polynomial over GF(2^8).
    let (columns, _) = block.as_chunks_mut::<4>();
    for column in columns {
        let [a0, a1, a2, a3] = *column;

        // With t = a0 ^ a1 ^ a2 ^ a3, output byte i is a_i ^ t ^ 2 (a_i ^ a_(i+1)).
        // This expands to 2 a_i ^ 3 a_(i+1) ^ a_(i+2) ^ a_(i+3), the matrix row.
        let t = a0 ^ a1 ^ a2 ^ a3;
        column[0] = a0 ^ t ^ xtime(a0 ^ a1);
        column[1] = a1 ^ t ^ xtime(a1 ^ a2);
        column[2] = a2 ^ t ^ xtime(a2 ^ a3);
        column[3] = a3 ^ t ^ xtime(a3 ^ a0);
    }
}

/// Multiplies by x in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, without branching.
const fn xtime(byte: u8) -> u8 {
    // The top bit decides the reduction.
    // Turn it into a mask instead of a branch.
    (byte << 1) ^ (0x1b & 0_u8.wrapping_sub(byte >> 7))
}

/// Applies the S-box to all 16 bytes at once with a bitsliced circuit.
///
/// # Algorithm
///
/// The 16 bytes become 8 bit planes: plane i holds bit i of every byte, one byte per lane.
///
/// ```text
/// bytes  b0 .. b15      -> 8 x 8 bit transposes ->   planes p0 .. p7 (16 lanes each)
/// p7 .. p0              -> 113-gate S-box circuit -> s7 .. s0
/// planes                -> transposes back       ->  bytes
/// ```
pub(super) fn sub_bytes(block: &mut [u8; 16]) {
    // Phase 1: each half is an 8 x 8 bit matrix.
    // Transposing turns its rows into planes.
    let (halves, _) = block.as_chunks::<8>();
    let low = transpose_8x8(u64::from_le_bytes(halves[0]));
    let high = transpose_8x8(u64::from_le_bytes(halves[1]));

    // Plane i: bytes 0..7 in lanes 0..7 from the low half, bytes 8..15 in lanes 8..15.
    let mut planes = [0_u32; 8];
    for (i, plane) in planes.iter_mut().enumerate() {
        *plane = ((low >> (8 * i)) & 0xff) as u32 | ((((high >> (8 * i)) & 0xff) as u32) << 8);
    }

    // Phase 2: the circuit.
    sbox_circuit(&mut planes);

    // Phase 3: gather the planes back and transpose again.
    // The transpose is its own inverse.
    let mut low = 0_u64;
    let mut high = 0_u64;
    for (i, plane) in planes.iter().enumerate() {
        low |= u64::from(plane & 0xff) << (8 * i);
        high |= u64::from((plane >> 8) & 0xff) << (8 * i);
    }
    block[..8].copy_from_slice(&transpose_8x8(low).to_le_bytes());
    block[8..].copy_from_slice(&transpose_8x8(high).to_le_bytes());
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

/// The AES S-box as a Boolean circuit on bit planes, plane 0 holding the low bits.
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
const fn sbox_circuit(q: &mut [u32; 8]) {
    // Inputs, most significant plane first.
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

#[cfg(test)]
mod tests {
    use std::array;

    use proptest::prelude::*;

    use super::*;

    /// Multiplication in GF(2^8) by shift-and-add, branching freely: a test reference only.
    fn gf_mul(mut a: u8, mut b: u8) -> u8 {
        let mut product = 0;
        while b != 0 {
            if b & 1 == 1 {
                product ^= a;
            }
            a = xtime(a);
            b >>= 1;
        }
        product
    }

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
            let mut block: [u8; 16] = array::from_fn(|i| byte.wrapping_add(i as u8 * 17));
            let expected = block.map(sbox_reference);
            sub_bytes(&mut block);
            assert_eq!(block, expected, "input {byte:#04x}");
        }

        // Spot values of FIPS 197, figure 7.
        assert_eq!(sbox_reference(0x00), 0x63);
        assert_eq!(sbox_reference(0x53), 0xed);
    }

    #[test]
    fn fips_197_key_expansion() {
        // FIPS 197, appendix A.1: the last round key of 2b7e1516...
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let keys = expand_key(&key);
        assert_eq!(
            keys[1],
            [
                0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c,
                0x76, 0x05
            ]
        );
        assert_eq!(
            keys[10],
            [
                0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63,
                0x0c, 0xa6
            ]
        );
    }

    proptest! {
        #[test]
        fn transpose_is_an_involution(x in any::<u64>()) {
            // Transposing twice restores the matrix, and bit (r, c) lands at (c, r).
            prop_assert_eq!(transpose_8x8(transpose_8x8(x)), x);
            let t = transpose_8x8(x);
            for r in 0..8 {
                for c in 0..8 {
                    prop_assert_eq!((x >> (8 * r + c)) & 1, (t >> (8 * c + r)) & 1);
                }
            }
        }

        #[test]
        fn mix_columns_matches_the_matrix(column in any::<[u8; 4]>()) {
            // Row i of the circulant matrix (2 3 1 1), by plain GF(2^8) products.
            let mut block = [0_u8; 16];
            block[..4].copy_from_slice(&column);
            mix_columns(&mut block);
            for i in 0..4 {
                let expected = gf_mul(2, column[i])
                    ^ gf_mul(3, column[(i + 1) % 4])
                    ^ column[(i + 2) % 4]
                    ^ column[(i + 3) % 4];
                prop_assert_eq!(block[i], expected);
            }
        }
    }
}
