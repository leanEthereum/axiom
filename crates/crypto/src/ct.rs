//! Constant-time building blocks: masks, selection, comparison, and wiping.
//!
//! Secret-dependent decisions never become branches or table indices.
//! They live in a word that is either all ones or all zeros, and blend values with AND and XOR.

use std::{
    hint::black_box,
    ptr,
    sync::atomic::{Ordering, compiler_fence},
};

/// A secret condition stored as an all-ones or all-zeros word.
///
/// The optimizer sees the word through an opaque barrier.
/// It therefore cannot prove the word is a boolean and turn a blend back into a branch.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Mask(u64);

impl Mask {
    /// The condition that never holds.
    pub(crate) const FALSE: Self = Self(0);

    /// A mask from a bit that is 0 or 1.
    #[inline]
    pub(crate) fn from_bit(bit: u64) -> Self {
        // Invariant: bit is 0 or 1, so 0 - bit is 0 or all ones.
        debug_assert!(bit <= 1, "a mask comes from a single bit");
        Self(black_box(0_u64.wrapping_sub(bit)))
    }

    /// A mask from a public boolean.
    #[cfg(test)]
    pub(crate) fn from_bool(condition: bool) -> Self {
        Self::from_bit(u64::from(condition))
    }

    /// Holds when the word is zero.
    #[inline]
    pub(crate) fn is_zero(word: u64) -> Self {
        // For x != 0, either x or -x has its top bit set.
        //
        //     x = 0      ->  (0 | 0) >> 63  = 0  ->  zero
        //     x = 5      ->  (5 | -5) >> 63 = 1  ->  non-zero
        let nonzero = (word | word.wrapping_neg()) >> 63;
        Self::from_bit(nonzero ^ 1)
    }

    /// Holds when the two words are equal.
    #[inline]
    pub(crate) fn equal(a: u64, b: u64) -> Self {
        Self::is_zero(a ^ b)
    }

    /// Holds when the two byte strings are equal, reading every byte of both.
    ///
    /// The lengths are public, so a length mismatch returns early.
    pub(crate) fn bytes_equal(a: &[u8], b: &[u8]) -> Self {
        if a.len() != b.len() {
            return Self::FALSE;
        }
        // Accumulate every differing bit, then test the accumulator once.
        let difference = a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y));
        Self::is_zero(u64::from(difference))
    }

    /// Holds when both conditions hold.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn and(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Holds when either condition holds.
    #[inline]
    #[must_use]
    pub(crate) const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Holds when the condition does not.
    #[inline]
    #[must_use]
    pub(crate) const fn not(self) -> Self {
        Self(!self.0)
    }

    /// The first word when the condition holds, the second otherwise.
    #[inline]
    pub(crate) const fn select(self, if_true: u64, if_false: u64) -> u64 {
        // Blend: the mask keeps the bits that differ from the false word.
        if_false ^ (self.0 & (if_true ^ if_false))
    }

    /// The raw word, all ones or all zeros.
    #[inline]
    pub(crate) const fn word(self) -> u64 {
        self.0
    }

    /// The lowest bit of the word: 1 when the condition holds.
    #[inline]
    pub(crate) const fn bit(self) -> u64 {
        self.0 & 1
    }

    /// Reveals the condition as a boolean.
    ///
    /// Only call this on a condition the protocol makes public, such as a failed check.
    #[inline]
    pub(crate) const fn reveal(self) -> bool {
        self.0 != 0
    }
}

/// Overwrites every value with its default, in a way the optimizer cannot remove.
///
/// Secret keys call this on drop.
pub(crate) fn wipe<T: Copy + Default>(values: &mut [T]) {
    for value in values.iter_mut() {
        // SAFETY: the pointer comes from a live mutable reference, so it is valid and aligned.
        unsafe {
            ptr::write_volatile(value, T::default());
        }
    }
    // Keep later reads and writes from moving above the wipe.
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn masks_from_bits_and_zero_tests() {
        // Bit 1 gives all ones, bit 0 gives all zeros.
        assert_eq!(Mask::from_bit(1).word(), u64::MAX);
        assert_eq!(Mask::from_bit(0).word(), 0);

        // Zero is the only word the zero test accepts, including at the sign boundary.
        assert!(Mask::is_zero(0).reveal());
        assert!(!Mask::is_zero(1).reveal());
        assert!(!Mask::is_zero(1 << 63).reveal());
        assert!(!Mask::is_zero(u64::MAX).reveal());
    }

    #[test]
    fn byte_strings_compare_in_full() {
        // Equal strings, a one-bit difference in the last byte, and a length mismatch.
        assert!(Mask::bytes_equal(b"tag!", b"tag!").reveal());
        assert!(!Mask::bytes_equal(b"tag!", b"tag ").reveal());
        assert!(!Mask::bytes_equal(b"tag", b"tag!").reveal());
        assert!(Mask::bytes_equal(b"", b"").reveal());
    }

    #[test]
    fn wipe_zeroes_every_value() {
        // A 4-byte secret becomes four zero bytes.
        let mut secret = [0xde_u8, 0xad, 0xbe, 0xef];
        wipe(&mut secret);
        assert_eq!(secret, [0; 4]);
    }

    proptest! {
        #[test]
        fn select_matches_a_branch(a in any::<u64>(), b in any::<u64>(), pick in any::<bool>()) {
            // The blend equals the obvious branch for both conditions.
            let expected = if pick { a } else { b };
            prop_assert_eq!(Mask::from_bool(pick).select(a, b), expected);
        }

        #[test]
        fn logic_matches_booleans(x in any::<bool>(), y in any::<bool>(), a in any::<u64>()) {
            // AND, OR and NOT on masks follow boolean logic.
            let (mx, my) = (Mask::from_bool(x), Mask::from_bool(y));
            prop_assert_eq!(mx.and(my).reveal(), x && y);
            prop_assert_eq!(mx.or(my).reveal(), x || y);
            prop_assert_eq!(mx.not().reveal(), !x);
            prop_assert_eq!(Mask::equal(a, a).reveal(), true);
            prop_assert_eq!(Mask::equal(a, a ^ 1).reveal(), false);
        }
    }
}
