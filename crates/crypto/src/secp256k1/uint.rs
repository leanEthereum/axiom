//! Fixed-width unsigned integers in little-endian 64-bit limbs.
//!
//! Field elements and scalars share the 256-bit form for decoding, encoding, and carry chains.
//! The 320-bit form holds the running value of a signed-digit recoding.

use std::array;

/// An unsigned 256-bit integer, limb 0 least significant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) struct U256(pub(super) [u64; 4]);

impl U256 {
    /// Decodes 32 big-endian bytes.
    pub(super) fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        // Limb 0 is the least significant, so it comes from the last eight bytes.
        let (words, _) = bytes.as_chunks::<8>();
        Self(array::from_fn(|i| u64::from_be_bytes(words[3 - i])))
    }

    /// Encodes as 32 big-endian bytes.
    pub(super) fn to_be_bytes(self) -> [u8; 32] {
        // Limb 3 is the most significant, so it goes first.
        let mut out = [0_u8; 32];
        let (words, _) = out.as_chunks_mut::<8>();
        for (word, limb) in words.iter_mut().zip(self.0.iter().rev()) {
            *word = limb.to_be_bytes();
        }
        out
    }

    /// The sum modulo 2^256 and its carry bit.
    pub(super) fn add_with_carry(self, rhs: Self) -> (Self, u64) {
        // A 128-bit sum per limb lets the compiler emit one add-with-carry chain.
        let mut out = [0_u64; 4];
        let mut carry = 0_u128;
        for ((out, a), b) in out.iter_mut().zip(self.0).zip(rhs.0) {
            let t = u128::from(a) + u128::from(b) + carry;
            *out = t as u64;
            carry = t >> 64;
        }
        (Self(out), carry as u64)
    }

    /// The difference modulo 2^256 and its borrow bit.
    pub(super) fn sub_with_borrow(self, rhs: Self) -> (Self, u64) {
        // A 128-bit difference per limb lets the compiler emit one subtract-with-borrow chain.
        // A borrow leaves the top half all ones, so its top bit is the borrow.
        let mut out = [0_u64; 4];
        let mut borrow = 0_u128;
        for ((out, a), b) in out.iter_mut().zip(self.0).zip(rhs.0) {
            let t = u128::from(a).wrapping_sub(u128::from(b) + borrow);
            *out = t as u64;
            borrow = t >> 127;
        }
        (Self(out), borrow as u64)
    }
}

/// An unsigned 320-bit integer, limb 0 least significant.
///
/// A 256-bit value plus a digit up to 2^7 needs one more limb than the value itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct U320([u64; 5]);

impl U320 {
    /// Widens a 256-bit integer.
    pub(super) const fn from_u256(value: U256) -> Self {
        let [l0, l1, l2, l3] = value.0;
        Self([l0, l1, l2, l3, 0])
    }

    /// Holds when the value is zero.
    pub(super) fn is_zero(&self) -> bool {
        self.0.iter().all(|&limb| limb == 0)
    }

    /// The low 64 bits.
    pub(super) const fn low(&self) -> u64 {
        self.0[0]
    }

    /// Adds a small value.
    pub(super) fn add_small(&mut self, value: u64) {
        // Ripple the carry upwards.
        let mut carry = value;
        for limb in &mut self.0 {
            let (sum, overflow) = limb.overflowing_add(carry);
            *limb = sum;
            carry = u64::from(overflow);
        }
    }

    /// Subtracts a small value, which must not exceed the integer.
    pub(super) fn sub_small(&mut self, value: u64) {
        // Ripple the borrow upwards.
        let mut borrow = value;
        for limb in &mut self.0 {
            let (difference, underflow) = limb.overflowing_sub(borrow);
            *limb = difference;
            borrow = u64::from(underflow);
        }
    }

    /// Halves the integer, dropping the low bit.
    pub(super) fn halve(&mut self) {
        // Each limb takes the low bit of the limb above as its new top bit.
        for i in 0..5 {
            let next = if i < 4 { self.0[i + 1] } else { 0 };
            self.0[i] = (self.0[i] >> 1) | (next << 63);
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn carries_and_borrows_leave_the_top_limb() {
        // (2^256 - 1) + 1 wraps to 0 with a carry, and 0 - 1 wraps back with a borrow.
        let max = U256([u64::MAX; 4]);
        let one = U256([1, 0, 0, 0]);
        assert_eq!(max.add_with_carry(one), (U256::default(), 1));
        assert_eq!(U256::default().sub_with_borrow(one), (max, 1));
    }

    #[test]
    fn small_steps_cross_limb_boundaries() {
        // 2^64 - 1 plus 1 carries into limb 1, and subtracting 1 borrows back.
        let mut value = U320::from_u256(U256([u64::MAX, 0, 0, 0]));
        value.add_small(1);
        assert_eq!(value, U320([0, 1, 0, 0, 0]));
        value.sub_small(1);
        assert_eq!(value, U320([u64::MAX, 0, 0, 0, 0]));

        // Halving 2^64 moves bit 0 of limb 1 into bit 63 of limb 0.
        let mut power = U320([0, 1, 0, 0, 0]);
        power.halve();
        assert_eq!(power, U320([1 << 63, 0, 0, 0, 0]));
        assert!(!power.is_zero());
        assert_eq!(power.low(), 1 << 63);
    }

    proptest! {
        #[test]
        fn bytes_round_trip(bytes in any::<[u8; 32]>()) {
            prop_assert_eq!(U256::from_be_bytes(&bytes).to_be_bytes(), bytes);
        }

        #[test]
        fn add_and_sub_match_wide_integers(a in any::<[u64; 2]>(), b in any::<[u64; 2]>()) {
            // Two-limb operands keep the reference within u128 arithmetic.
            let wide = |limbs: [u64; 2]| u128::from(limbs[0]) | (u128::from(limbs[1]) << 64);
            let (x, y) = (U256([a[0], a[1], 0, 0]), U256([b[0], b[1], 0, 0]));
            let (sum, carry) = x.add_with_carry(y);
            let (expected, overflow) = wide(a).overflowing_add(wide(b));
            prop_assert_eq!(sum, U256([expected as u64, (expected >> 64) as u64, u64::from(overflow), 0]));
            prop_assert_eq!(carry, 0);
            let (difference, borrow) = x.sub_with_borrow(y);
            prop_assert_eq!(borrow, u64::from(wide(a) < wide(b)));
            prop_assert_eq!(difference.add_with_carry(y).0, x);
        }
    }
}
