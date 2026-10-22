//! Reduction of a long big-endian integer modulo the BLS12-381 group order r.

use std::hint::black_box;

use crate::keys::wipe::Wipe;

/// An integer below r, reduced from big-endian bytes in constant time.
///
/// It holds secret key material, so it is wiped on drop.
pub(crate) struct Residue {
    /// Little-endian 64-bit limbs, always below r.
    limbs: [u64; 4],
}

impl Residue {
    /// The group order r of BLS12-381, in little-endian limbs.
    ///
    /// r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001.
    const MODULUS: [u64; 4] = [
        0xffff_ffff_0000_0001,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ];

    /// OS2IP of the bytes, modulo r.
    ///
    /// # Algorithm
    ///
    /// Horner's rule over bits, most significant first:
    ///
    /// ```text
    /// acc = 2 acc + bit
    /// acc = acc - r, when that does not borrow
    /// ```
    ///
    /// # Invariants
    ///
    /// acc < r before each step, and r < 2^255.
    /// So 2 acc + 1 <= 2r - 1 < 2^256 fits four limbs, and one subtraction restores acc < r.
    ///
    /// The work depends only on the input length, which is public.
    /// The subtraction is selected by a mask, never by a branch.
    pub(crate) fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut residue = Self { limbs: [0; 4] };
        for &byte in bytes {
            for shift in (0..8).rev() {
                residue.double_add(u64::from((byte >> shift) & 1));
            }
        }
        residue
    }

    /// The residue as 32 big-endian bytes.
    pub(crate) fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0; 32];
        for (chunk, limb) in out
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(self.limbs.iter().rev())
        {
            chunk.copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// Whether the residue is zero.
    ///
    /// Only the key generation retry calls this, and a zero key is never used, so it may branch.
    pub(crate) fn is_zero(&self) -> bool {
        self.limbs.iter().fold(0, |acc, limb| acc | limb) == 0
    }

    /// One Horner step: acc = 2 acc + bit, reduced below r.
    fn double_add(&mut self, bit: u64) {
        // Double and add: shift every limb left by one, carrying the top bit up.
        let mut carry = bit;
        for limb in &mut self.limbs {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        // Invariant: acc < 2^256, so the last carry is zero.

        // Trial subtraction of r, with the borrow chained through the limbs.
        let mut reduced = [0; 4];
        let mut borrow = 0;
        for ((out, &limb), &modulus) in reduced.iter_mut().zip(&self.limbs).zip(&Self::MODULUS) {
            let (difference, under) = limb.overflowing_sub(modulus);
            let (difference, under_again) = difference.overflowing_sub(borrow);
            *out = difference;
            borrow = u64::from(under | under_again);
        }

        // Keep the difference when it did not borrow: mask is all ones exactly then.
        // The barrier stops the optimizer from turning the blend back into a branch.
        let keep = black_box(borrow.wrapping_sub(1));
        for (limb, difference) in self.limbs.iter_mut().zip(reduced) {
            *limb = (difference & keep) | (*limb & !keep);
        }
        reduced.wipe();
    }
}

impl Drop for Residue {
    fn drop(&mut self) {
        self.limbs.wipe();
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// r in big-endian bytes.
    const R: [u8; 32] = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x01,
    ];

    /// Adds two big-endian integers of equal length, carrying out into one more byte.
    fn add(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = vec![0; a.len() + 1];
        let mut carry = 0_u16;
        for i in (0..a.len()).rev() {
            let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
            out[i + 1] = sum as u8;
            carry = sum >> 8;
        }
        out[0] = carry as u8;
        out
    }

    #[test]
    fn the_modulus_and_its_neighbours() {
        // r reduces to zero, r - 1 stays, r + 1 reduces to one.
        assert!(Residue::from_be_bytes(&R).is_zero());
        let mut below = R;
        below[31] = 0x00;
        assert_eq!(Residue::from_be_bytes(&below).to_be_bytes(), below);
        let mut above = R;
        above[31] = 0x02;
        let mut one = [0; 32];
        one[31] = 1;
        assert_eq!(Residue::from_be_bytes(&above).to_be_bytes(), one);
    }

    #[test]
    fn the_largest_48_byte_input() {
        // (2^384 - 1) mod r, computed independently with arbitrary-precision integers.
        let reduced = Residue::from_be_bytes(&[0xff; 48]).to_be_bytes();
        assert_eq!(
            reduced,
            [
                0x2d, 0xbe, 0xaf, 0x1f, 0xd4, 0x84, 0x3a, 0xcb, 0x7a, 0xbb, 0xe5, 0x68, 0x73, 0x69,
                0x51, 0x0a, 0x92, 0x77, 0xef, 0xb8, 0xac, 0x0a, 0x60, 0x0d, 0xcf, 0x2a, 0xb2, 0x1b,
                0xf8, 0x1f, 0x71, 0x2c,
            ]
        );
    }

    #[test]
    fn empty_input_is_zero() {
        assert!(Residue::from_be_bytes(&[]).is_zero());
    }

    proptest! {
        #[test]
        fn values_below_the_modulus_are_fixed(mut bytes in any::<[u8; 32]>()) {
            // Clearing the top two bits leaves x < 2^254 < r, already reduced.
            bytes[0] &= 0x3f;
            prop_assert_eq!(Residue::from_be_bytes(&bytes).to_be_bytes(), bytes);
        }

        #[test]
        fn adding_the_modulus_changes_nothing(bytes in any::<[u8; 32]>()) {
            // x and x + r are congruent, whatever the size of x.
            let plus_r = add(&bytes, &R);
            prop_assert_eq!(
                Residue::from_be_bytes(&plus_r).to_be_bytes(),
                Residue::from_be_bytes(&bytes).to_be_bytes()
            );
        }

        #[test]
        fn leading_zero_bytes_change_nothing(bytes in any::<[u8; 32]>()) {
            // OS2IP ignores leading zeros: a 48-byte encoding equals the 32-byte one.
            let mut wide = [0_u8; 48];
            wide[16..].copy_from_slice(&bytes);
            prop_assert_eq!(
                Residue::from_be_bytes(&wide).to_be_bytes(),
                Residue::from_be_bytes(&bytes).to_be_bytes()
            );
        }
    }
}
