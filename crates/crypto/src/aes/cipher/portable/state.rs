//! The AES state and the round steps that act on it, per FIPS 197, section 5.1.

use super::sbox::BitPlanes;

/// The 16-byte AES state, column-major: byte 4c + r sits in column c, row r.
///
/// The state is secret, so no round step branches or indexes on its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct State([u8; 16]);

impl State {
    /// The state holding a block.
    pub(super) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The block the state holds.
    pub(super) const fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// XORs a round key into the state.
    pub(super) fn add_round_key(&mut self, key: &[u8; 16]) {
        // Byte-wise XOR: the only step that involves the key.
        for (byte, k) in self.0.iter_mut().zip(key) {
            *byte ^= k;
        }
    }

    /// Applies the S-box to all 16 bytes at once with a bitsliced circuit.
    pub(super) fn sub_bytes(&mut self) {
        // Bytes to bit planes, through the circuit, and back.
        let mut planes = BitPlanes::from_bytes(&self.0);
        planes.substitute();
        self.0 = planes.to_bytes();
    }

    /// Rotates row r of the state left by r positions.
    ///
    /// ```text
    /// row 0:  s0  s4  s8  s12        s0  s4  s8  s12
    /// row 1:  s1  s5  s9  s13   ->   s5  s9  s13 s1
    /// row 2:  s2  s6  s10 s14        s10 s14 s2  s6
    /// row 3:  s3  s7  s11 s15        s15 s3  s7  s11
    /// ```
    pub(super) fn shift_rows(&mut self) {
        // Read from a copy, since the rotation overwrites its own sources.
        let old = self.0;
        for c in 0..4 {
            for r in 0..4 {
                self.0[4 * c + r] = old[4 * ((c + r) % 4) + r];
            }
        }
    }

    /// Multiplies every column by the fixed polynomial 3x^3 + x^2 + x + 2, per FIPS 197, section 5.1.3.
    pub(super) fn mix_columns(&mut self) {
        // Each 4-byte column is one polynomial over GF(2^8).
        let (columns, _) = self.0.as_chunks_mut::<4>();
        for column in columns {
            let [a0, a1, a2, a3] = *column;

            // With t = a0 ^ a1 ^ a2 ^ a3, output byte i is a_i ^ t ^ 2 (a_i ^ a_(i+1)).
            // This expands to 2 a_i ^ 3 a_(i+1) ^ a_(i+2) ^ a_(i+3), the matrix row.
            let t = a0 ^ a1 ^ a2 ^ a3;
            column[0] = a0 ^ t ^ Self::xtime(a0 ^ a1);
            column[1] = a1 ^ t ^ Self::xtime(a1 ^ a2);
            column[2] = a2 ^ t ^ Self::xtime(a2 ^ a3);
            column[3] = a3 ^ t ^ Self::xtime(a3 ^ a0);
        }
    }

    /// Multiplies by x in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, without branching.
    const fn xtime(byte: u8) -> u8 {
        // The top bit decides the reduction.
        // Turn it into a mask instead of a branch.
        (byte << 1) ^ (0x1b & 0_u8.wrapping_sub(byte >> 7))
    }
}

#[cfg(test)]
pub(super) mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Multiplication in GF(2^8) by shift-and-add, branching freely: a test reference only.
    pub(in crate::aes::cipher::portable) fn gf_mul(mut a: u8, mut b: u8) -> u8 {
        let mut product = 0;
        while b != 0 {
            if b & 1 == 1 {
                product ^= a;
            }
            a = State::xtime(a);
            b >>= 1;
        }
        product
    }

    proptest! {
        #[test]
        fn mix_columns_matches_the_matrix(column in any::<[u8; 4]>()) {
            // Row i of the circulant matrix (2 3 1 1), by plain GF(2^8) products.
            let mut bytes = [0_u8; 16];
            bytes[..4].copy_from_slice(&column);
            let mut state = State::from_bytes(bytes);
            state.mix_columns();
            let block = state.to_bytes();
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
