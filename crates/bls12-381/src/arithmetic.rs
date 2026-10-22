//! Limb primitives shared by both prime fields.
//!
//! Every helper widens to 128 bits, which compiles to one 64x64 multiply and an add-with-carry chain.

use std::hint::black_box;

/// Adds two limbs and an incoming carry.
///
/// # Returns
///
/// The low 64 bits of the sum, then the outgoing carry (0 or 1).
#[inline]
#[allow(
    clippy::cast_possible_truncation,
    reason = "keeping the low limb of a 128-bit sum is the intent"
)]
pub(crate) const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    // Three 64-bit values sum to less than 2^66, so 128 bits never overflow.
    let wide = a as u128 + b as u128 + carry as u128;
    (wide as u64, (wide >> 64) as u64)
}

/// Subtracts a limb and an incoming borrow from another limb.
///
/// The borrow is a mask: zero when no borrow occurred, all ones otherwise.
///
/// # Returns
///
/// The low 64 bits of the difference, then the outgoing borrow mask.
#[inline]
#[allow(
    clippy::cast_possible_truncation,
    reason = "keeping the low limb of a 128-bit difference is the intent"
)]
pub(crate) const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    // The top bit of the borrow mask is the borrow itself.
    //
    //     no borrow: wide < 2^64, so the high half is 0
    //     borrow   : wide wraps to 2^128 - k, so the high half is all ones
    let wide = (a as u128).wrapping_sub(b as u128 + (borrow >> 63) as u128);
    (wide as u64, (wide >> 64) as u64)
}

/// Computes a + b * c + carry over limbs.
///
/// # Returns
///
/// The low 64 bits, then the high 64 bits.
#[inline]
#[allow(
    clippy::cast_possible_truncation,
    reason = "splitting a 128-bit product into two limbs is the intent"
)]
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

/// Interprets big-endian bytes as little-endian 64-bit limbs.
///
/// The input length must be eight times the limb count.
#[inline]
pub(crate) fn limbs_from_be_bytes<const N: usize>(bytes: &[u8]) -> [u64; N] {
    let mut limbs = [0_u64; N];
    // The last eight bytes hold the least significant limb.
    //
    //     bytes: [ limb N-1 | ... | limb 1 | limb 0 ]
    for (limb, chunk) in limbs.iter_mut().zip(bytes.rchunks_exact(8)) {
        let mut word = [0_u8; 8];
        word.copy_from_slice(chunk);
        *limb = u64::from_be_bytes(word);
    }
    limbs
}

/// Writes little-endian 64-bit limbs as big-endian bytes.
///
/// The output length must be eight times the limb count.
#[inline]
pub(crate) fn limbs_to_be_bytes(limbs: &[u64], out: &mut [u8]) {
    // The least significant limb lands in the last eight bytes.
    for (limb, chunk) in limbs.iter().zip(out.rchunks_exact_mut(8)) {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adc_carries_out_of_a_full_limb() {
        // (2^64 - 1) + 1 + 1 = 2^64 + 1: low limb 1, carry 1.
        assert_eq!(adc(u64::MAX, 1, 1), (1, 1));
    }

    #[test]
    fn sbb_borrow_is_a_full_mask() {
        // 0 - 1 wraps to 2^64 - 1 and raises the borrow mask.
        assert_eq!(sbb(0, 1, 0), (u64::MAX, u64::MAX));
        // An incoming borrow mask subtracts exactly one more.
        assert_eq!(sbb(5, 1, u64::MAX), (3, 0));
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
    fn byte_limb_conversion_round_trips() {
        // Sixteen bytes 0x00..0x0f become two limbs, most significant first on the wire.
        let bytes: Vec<u8> = (0..16).collect();
        let limbs: [u64; 2] = limbs_from_be_bytes(&bytes);
        assert_eq!(limbs, [0x0809_0a0b_0c0d_0e0f, 0x0001_0203_0405_0607]);

        let mut out = [0_u8; 16];
        limbs_to_be_bytes(&limbs, &mut out);
        assert_eq!(out.to_vec(), bytes);
    }
}
