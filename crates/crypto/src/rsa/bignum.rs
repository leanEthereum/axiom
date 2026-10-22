//! Unsigned integers of a width fixed at run time, for RSA moduli of 1024 to 8192 bits.

use crate::ct::{Mask, wipe};

/// An unsigned integer in little-endian 64-bit limbs, of a width chosen at creation.
///
/// # Invariants
///
/// The width is a public fact: no operation changes it based on the value.
/// Every operation below runs in time that depends on widths only, unless its name ends in vartime.
/// The limbs are cleared from memory when dropped, since primes and exponents live here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BigUint {
    /// The limbs, limb 0 least significant.
    limbs: Vec<u64>,
}

impl BigUint {
    /// Zero, in the given number of limbs.
    pub(super) fn zero(width: usize) -> Self {
        Self {
            limbs: vec![0; width],
        }
    }

    /// A small value, in the given number of limbs.
    pub(super) fn from_u64(value: u64, width: usize) -> Self {
        let mut out = Self::zero(width);
        out.limbs[0] = value;
        out
    }

    /// Decodes big-endian bytes into the given number of limbs.
    ///
    /// Returns none when the value needs more limbs.
    pub(super) fn from_be_bytes(bytes: &[u8], width: usize) -> Option<Self> {
        // Leading zero bytes carry no value: drop them before measuring the fit.
        let start = bytes
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(bytes.len());
        let bytes = &bytes[start..];
        if bytes.len() > 8 * width {
            return None;
        }
        let mut out = Self::zero(width);
        // Byte i from the end lands in limb i / 8, at bit 8 (i mod 8).
        for (i, &byte) in bytes.iter().rev().enumerate() {
            out.limbs[i / 8] |= u64::from(byte) << (8 * (i % 8));
        }
        Some(out)
    }

    /// Decodes big-endian bytes into the fewest limbs that hold their length, leading zeros dropped.
    ///
    /// The width follows the byte length, never the bit pattern within it.
    pub(super) fn from_be_bytes_minimal(bytes: &[u8]) -> Self {
        let start = bytes
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(bytes.len());
        let width = (bytes.len() - start).div_ceil(8).max(1);
        // Invariant: the width covers every significant byte, so the decoding fits.
        Self::from_be_bytes(&bytes[start..], width).expect("the width covers every byte")
    }

    /// Encodes as exactly len big-endian bytes, per I2OSP of RFC 8017, section 4.1.
    ///
    /// Returns none when the value is at least 256^len.
    pub(super) fn to_be_bytes(&self, len: usize) -> Option<Vec<u8>> {
        // Bytes beyond len must all be zero for the value to fit.
        let mut overflow = 0_u64;
        for i in len..8 * self.width() {
            overflow |= self.byte(i);
        }
        if overflow != 0 {
            return None;
        }
        Some((0..len).rev().map(|i| self.byte(i) as u8).collect())
    }

    /// The byte at position i from the least significant end, zero beyond the width.
    fn byte(&self, i: usize) -> u64 {
        self.limbs
            .get(i / 8)
            .map_or(0, |limb| (limb >> (8 * (i % 8))) & 0xff)
    }

    /// The number of limbs.
    pub(super) const fn width(&self) -> usize {
        self.limbs.len()
    }

    /// The limbs, least significant first.
    pub(super) fn limbs(&self) -> &[u64] {
        &self.limbs
    }

    /// The limbs, mutably.
    pub(super) fn limbs_mut(&mut self) -> &mut [u64] {
        &mut self.limbs
    }

    /// The same value in a different number of limbs.
    ///
    /// Returns none when the value does not fit the new width.
    pub(super) fn resized(&self, width: usize) -> Option<Self> {
        let mut dropped = 0;
        for &limb in self.limbs.iter().skip(width) {
            dropped |= limb;
        }
        if dropped != 0 {
            return None;
        }
        let mut out = Self::zero(width);
        let kept = width.min(self.width());
        out.limbs[..kept].copy_from_slice(&self.limbs[..kept]);
        Some(out)
    }

    /// The bit length, zero for zero, in variable time.
    ///
    /// Used only on public values, such as a modulus or a public exponent.
    pub(super) fn bits_vartime(&self) -> usize {
        match self.limbs.iter().rposition(|&limb| limb != 0) {
            Some(top) => 64 * top + 64 - self.limbs[top].leading_zeros() as usize,
            None => 0,
        }
    }

    /// The bit at position i.
    pub(super) fn bit(&self, position: usize) -> u64 {
        (self.limbs[position / 64] >> (position % 64)) & 1
    }

    /// The 4-bit digit at window i, bits 4i to 4i + 3.
    ///
    /// The window index is public, and the digit stays a secret word.
    pub(super) fn nibble(&self, window: usize) -> u64 {
        (self.limbs[window / 16] >> ((window % 16) * 4)) & 0xf
    }

    /// Holds when the value is odd.
    pub(super) fn is_odd(&self) -> bool {
        self.limbs[0] & 1 == 1
    }

    /// Holds when the two values are equal, compared across the wider width.
    pub(super) fn equals(&self, other: &Self) -> Mask {
        // OR every limb difference, reading zero past the end of the narrower value.
        let width = self.width().max(other.width());
        let mut difference = 0;
        for i in 0..width {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);
            difference |= a ^ b;
        }
        Mask::is_zero(difference)
    }

    /// Holds when the value is below another of the same width.
    pub(super) fn less_than(&self, other: &Self) -> Mask {
        // The value is below exactly when subtracting the other borrows.
        let mut scratch = self.clone();
        Mask::from_bit(scratch.sub_assign(other))
    }

    /// Adds another value of the same width in place and returns the carry bit.
    pub(super) fn add_assign(&mut self, other: &Self) -> u64 {
        debug_assert_eq!(self.width(), other.width(), "operands share a width");
        let mut carry = 0_u128;
        for (a, &b) in self.limbs.iter_mut().zip(&other.limbs) {
            let t = u128::from(*a) + u128::from(b) + carry;
            *a = t as u64;
            carry = t >> 64;
        }
        carry as u64
    }

    /// Subtracts another value of the same width in place and returns the borrow bit.
    pub(super) fn sub_assign(&mut self, other: &Self) -> u64 {
        debug_assert_eq!(self.width(), other.width(), "operands share a width");
        // A borrow leaves the top half of the 128-bit difference all ones.
        let mut borrow = 0_u128;
        for (a, &b) in self.limbs.iter_mut().zip(&other.limbs) {
            let t = u128::from(*a).wrapping_sub(u128::from(b) + borrow);
            *a = t as u64;
            borrow = t >> 127;
        }
        borrow as u64
    }

    /// Replaces the value with another of the same width when the condition holds.
    pub(super) fn assign_if(&mut self, condition: Mask, other: &Self) {
        debug_assert_eq!(self.width(), other.width(), "operands share a width");
        for (a, &b) in self.limbs.iter_mut().zip(&other.limbs) {
            *a = condition.select(b, *a);
        }
    }

    /// The full product, in as many limbs as both operands together.
    ///
    /// Schoolbook multiplication: every limb pair is visited once, whatever the values.
    pub(super) fn mul(&self, other: &Self) -> Self {
        let mut out = Self::zero(self.width() + other.width());
        for (i, &a) in self.limbs.iter().enumerate() {
            // Row i: out += a * other * 2^(64 i).
            // Each step fits 128 bits: (2^64 - 1)^2 + 2 (2^64 - 1) = 2^128 - 1.
            let mut carry = 0_u128;
            for (j, &b) in other.limbs.iter().enumerate() {
                let t = u128::from(out.limbs[i + j]) + u128::from(a) * u128::from(b) + carry;
                out.limbs[i + j] = t as u64;
                carry = t >> 64;
            }
            out.limbs[i + other.width()] = carry as u64;
        }
        out
    }

    /// The remainder modulo a non-zero value, in the modulus's width.
    ///
    /// # Algorithm
    ///
    /// Binary long division, one bit of the dividend at a time, high to low.
    ///
    /// ```text
    /// r = 2 r + bit
    /// r = r - m        when r >= m, chosen by a mask
    /// ```
    ///
    /// # Invariants
    ///
    /// Before each step r < m, so 2 r + 1 < 2 m fits one limb more than m.
    /// The time depends on the two widths only, so secret primes may serve as the modulus.
    pub(super) fn rem(&self, modulus: &Self) -> Self {
        let width = modulus.width();
        let mut divisor = Self::zero(width + 1);
        divisor.limbs[..width].copy_from_slice(&modulus.limbs);

        let mut r = Self::zero(width + 1);
        let mut reduced = Self::zero(width + 1);
        for position in (0..64 * self.width()).rev() {
            // r = 2 r + bit, shifting the top bit of each limb into the next.
            let mut carry = self.bit(position);
            for limb in &mut r.limbs {
                let top = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = top;
            }

            // Keep r - m exactly when the subtraction does not borrow.
            reduced.limbs.copy_from_slice(&r.limbs);
            let borrow = reduced.sub_assign(&divisor);
            r.assign_if(Mask::from_bit(borrow).not(), &reduced);
        }

        // Invariant: r < m now, so the top limb is zero.
        r.limbs.truncate(width);
        r
    }
}

impl Drop for BigUint {
    fn drop(&mut self) {
        wipe(&mut self.limbs);
    }
}

#[cfg(test)]
pub(super) mod tests {
    use proptest::{collection, prelude::*};

    use super::*;

    /// A value from a u128, in two limbs.
    pub(crate) fn from_u128(value: u128) -> BigUint {
        BigUint {
            limbs: vec![value as u64, (value >> 64) as u64],
        }
    }

    /// The low two limbs as a u128.
    fn to_u128(value: &BigUint) -> u128 {
        u128::from(value.limbs[0]) | (u128::from(value.limbs.get(1).copied().unwrap_or(0)) << 64)
    }

    #[test]
    fn byte_codecs() {
        // 0x0102 fits one limb; the leading zero byte is tolerated.
        let value = BigUint::from_be_bytes(&[0, 1, 2], 1).unwrap();
        assert_eq!(value.limbs(), &[0x0102]);
        assert_eq!(value.to_be_bytes(4), Some(vec![0, 0, 1, 2]));

        // Mutation: two significant bytes do not fit one byte.
        assert_eq!(value.to_be_bytes(1), None);

        // Nine significant bytes need two limbs.
        assert_eq!(BigUint::from_be_bytes(&[1; 9], 1), None);
        assert_eq!(
            BigUint::from_be_bytes_minimal(&[0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1]).width(),
            2
        );

        // The empty string and all zeros are zero in one limb.
        assert_eq!(BigUint::from_be_bytes_minimal(&[]), BigUint::zero(1));
        assert_eq!(BigUint::from_be_bytes_minimal(&[0, 0]), BigUint::zero(1));
    }

    #[test]
    fn widths_and_bits() {
        // 2^64 needs two limbs and 65 bits.
        let value = from_u128(1 << 64);
        assert_eq!(value.bits_vartime(), 65);
        assert_eq!(value.resized(1), None);
        assert_eq!(value.resized(3).map(|wide| wide.bits_vartime()), Some(65));
        assert_eq!(BigUint::zero(4).bits_vartime(), 0);
    }

    #[test]
    fn remainder_edges() {
        // Against an 80-bit modulus m: 0, m - 1, m, and m + 1 reduce to 0, m - 1, 0, and 1.
        let m = 0xffff_ffff_ffff_ffff_ffff_u128;
        for (value, expected) in [(0, 0), (m - 1, m - 1), (m, 0), (m + 1, 1)] {
            assert_eq!(to_u128(&from_u128(value).rem(&from_u128(m))), expected);
        }
    }

    proptest! {
        #[test]
        fn products_and_remainders_match_u128(a in any::<u64>(), b in any::<u64>(), m in 1_u128..) {
            // The full product of two one-limb values is their u128 product.
            let product = BigUint::from_u64(a, 1).mul(&BigUint::from_u64(b, 1));
            prop_assert_eq!(to_u128(&product), u128::from(a) * u128::from(b));

            // Binary long division agrees with the u128 remainder.
            let remainder = product.rem(&from_u128(m));
            prop_assert_eq!(remainder.width(), 2);
            prop_assert_eq!(to_u128(&remainder), u128::from(a) * u128::from(b) % m);
        }

        #[test]
        fn add_sub_and_compare_match_u128(a in any::<u128>(), b in any::<u128>()) {
            let (x, y) = (from_u128(a), from_u128(b));
            let mut sum = x.clone();
            let carry = sum.add_assign(&y);
            let (expected, overflow) = a.overflowing_add(b);
            prop_assert_eq!((to_u128(&sum), carry), (expected, u64::from(overflow)));

            let mut difference = x.clone();
            let borrow = difference.sub_assign(&y);
            prop_assert_eq!((to_u128(&difference), borrow), (a.wrapping_sub(b), u64::from(a < b)));
            prop_assert_eq!(x.less_than(&y).reveal(), a < b);
            prop_assert_eq!(x.equals(&y).reveal(), a == b);
        }

        #[test]
        fn bytes_round_trip(bytes in collection::vec(any::<u8>(), 1..80)) {
            // Decoding then encoding at the same length restores the bytes, leading zeros included.
            let value = BigUint::from_be_bytes_minimal(&bytes);
            prop_assert_eq!(value.to_be_bytes(bytes.len()), Some(bytes));
        }
    }
}
