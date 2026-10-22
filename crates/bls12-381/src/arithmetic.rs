//! Fixed-width integers and masks shared by both prime fields.
//!
//! Addition chains use the carry methods of the standard library's unsigned integers.
//! Products and masked subtractions widen to 128 bits, which compiles to the shortest code.

use std::hint::black_box;

/// An unsigned integer of N little-endian 64-bit limbs, limb 0 least significant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Uint<const N: usize>(pub(crate) [u64; N]);

impl<const N: usize> Uint<N> {
    /// Decodes big-endian bytes.
    ///
    /// The input length must be eight times the limb count.
    #[inline]
    pub(crate) fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = [0_u64; N];
        // The last eight bytes hold the least significant limb.
        //
        //     bytes: [ limb N-1 | ... | limb 1 | limb 0 ]
        for (limb, chunk) in limbs.iter_mut().zip(bytes.rchunks_exact(8)) {
            let mut word = [0_u8; 8];
            word.copy_from_slice(chunk);
            *limb = u64::from_be_bytes(word);
        }
        Self(limbs)
    }

    /// The difference modulo 2^(64 N), with a borrow mask: all ones on underflow, zero otherwise.
    ///
    /// The mask comes out of 128-bit arithmetic, not out of a boolean.
    /// The compiler then never sees a two-valued flag it could turn into a branch on secret data.
    #[inline]
    pub(crate) fn sub_with_borrow_mask(self, rhs: Self) -> (Self, u64) {
        let mut out = [0_u64; N];
        let mut borrow = 0_u64;
        for ((out, a), b) in out.iter_mut().zip(self.0).zip(rhs.0) {
            // The top bit of the mask is the borrow itself.
            //
            //     no borrow: wide < 2^64, so the high half is 0
            //     borrow   : wide wraps to 2^128 - k, so the high half is all ones
            let wide = u128::from(a).wrapping_sub(u128::from(b) + u128::from(borrow >> 63));
            *out = wide as u64;
            borrow = (wide >> 64) as u64;
        }
        (Self(out), borrow)
    }

    /// Encodes as big-endian bytes.
    ///
    /// The output length must be eight times the limb count.
    #[inline]
    pub(crate) fn write_be_bytes(&self, out: &mut [u8]) {
        // The least significant limb lands in the last eight bytes.
        for (limb, chunk) in self.0.iter().zip(out.rchunks_exact_mut(8)) {
            chunk.copy_from_slice(&limb.to_be_bytes());
        }
    }
}

/// Computes a + b * c + carry over limbs.
///
/// The standard library's multiply-add compiles to a longer Montgomery loop on this toolchain.
/// This plain 128-bit form keeps the loop at its best length.
///
/// # Returns
///
/// The low 64 bits, then the high 64 bits.
#[inline]
pub(crate) const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    // Bound: (2^64 - 1) + (2^64 - 1)^2 + (2^64 - 1) = 2^128 - 1, so nothing overflows.
    let wide = a as u128 + (b as u128 * c as u128) + carry as u128;
    (wide as u64, (wide >> 64) as u64)
}

/// Turns a boolean into a limb mask: all ones for true, zero for false.
///
/// The value passes through an optimization barrier.
/// That keeps the compiler from turning masked selects back into branches on secret data.
#[inline]
pub(crate) fn mask(choice: bool) -> u64 {
    0_u64.wrapping_sub(u64::from(black_box(choice)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_limb_conversion_round_trips() {
        // Sixteen bytes 0x00..0x0f become two limbs, most significant first on the wire.
        let bytes: Vec<u8> = (0..16).collect();
        let value = Uint::<2>::from_be_bytes(&bytes);
        assert_eq!(value, Uint([0x0809_0a0b_0c0d_0e0f, 0x0001_0203_0405_0607]));

        let mut out = [0_u8; 16];
        value.write_be_bytes(&mut out);
        assert_eq!(out.to_vec(), bytes);
    }

    #[test]
    fn mac_reaches_the_largest_value_without_overflow() {
        // (2^64 - 1) + (2^64 - 1)^2 + (2^64 - 1) = 2^128 - 1.
        assert_eq!(
            mac(u64::MAX, u64::MAX, u64::MAX, u64::MAX),
            (u64::MAX, u64::MAX)
        );
    }

    #[test]
    fn masks_are_all_ones_or_all_zeros() {
        // True widens to 2^64 - 1, false to 0.
        assert_eq!(mask(true), u64::MAX);
        assert_eq!(mask(false), 0);
    }
}
