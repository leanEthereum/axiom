//! Overwriting secrets before their memory goes back to the allocator.

use std::{hint::black_box, mem};

/// A buffer that can overwrite its contents in place.
///
/// The write passes through an optimization barrier.
/// The barrier counts as a read, so the compiler cannot discard the write as dead.
pub(crate) trait Wipe {
    /// Overwrites every element with its default value.
    fn wipe(&mut self);
}

impl<T: Copy + Default> Wipe for [T] {
    fn wipe(&mut self) {
        self.fill(T::default());
        black_box(self);
    }
}

impl Wipe for String {
    fn wipe(&mut self) {
        // Why: a string's bytes are only writable through its vector, which reuses the allocation.
        let mut bytes = mem::take(self).into_bytes();
        bytes.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_and_strings_end_up_zeroed() {
        // A 4-byte slice and a 2-char tuple slice are filled with defaults.
        let mut bytes = [1_u8, 2, 3, 4];
        bytes.wipe();
        assert_eq!(bytes, [0; 4]);
        let mut marks = [(230_u8, 'a'), (220, 'b')];
        marks.wipe();
        assert_eq!(marks, [(0, '\0'); 2]);

        // A string is left empty, its buffer zeroed and released.
        let mut text = String::from("secret");
        text.wipe();
        assert_eq!(text, "");
    }
}
