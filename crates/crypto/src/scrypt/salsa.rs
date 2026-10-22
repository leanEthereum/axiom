//! The Salsa20/8 core, the mixing function inside scrypt's block mix.

use crate::ct::wipe;

/// Double rounds in Salsa20/8: eight rounds, two per double round, per RFC 7914, section 3.
const DOUBLE_ROUNDS: usize = 4;

/// One 64-byte Salsa20 block, as sixteen little-endian words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct SalsaBlock(pub(super) [u32; 16]);

impl SalsaBlock {
    /// XORs another block into this one.
    pub(super) fn xor(&mut self, other: &[u32; 16]) {
        for (word, other) in self.0.iter_mut().zip(other) {
            *word ^= other;
        }
    }

    /// Applies the Salsa20/8 core in place, per RFC 7914, section 3.
    ///
    /// The core adds the input back after the rounds, so it is not invertible.
    /// Only additions, rotations, and XORs run, so the time is independent of the data.
    ///
    /// # Performance
    ///
    /// The rounds run on a local copy with every index a literal.
    /// The sixteen words then live in registers, with no loads or stores between rounds.
    pub(super) fn salsa20_8(&mut self) {
        let mut x = *self;
        for _ in 0..DOUBLE_ROUNDS {
            // Column round: each quarter-round starts on a diagonal word and runs down its column.
            x.quarter_round(0, 4, 8, 12);
            x.quarter_round(5, 9, 13, 1);
            x.quarter_round(10, 14, 2, 6);
            x.quarter_round(15, 3, 7, 11);
            // Row round: the same, along the rows of the 4x4 state.
            x.quarter_round(0, 1, 2, 3);
            x.quarter_round(5, 6, 7, 4);
            x.quarter_round(10, 11, 8, 9);
            x.quarter_round(15, 12, 13, 14);
        }
        // Feed-forward: out = rounds(in) + in, word by word modulo 2^32.
        for (word, mixed) in self.0.iter_mut().zip(x.0) {
            *word = word.wrapping_add(mixed);
        }
    }

    /// One Salsa20 quarter-round on four words, per the Salsa20 specification, section 3.
    ///
    /// ```text
    /// b ^= (a + d) <<< 7
    /// c ^= (b + a) <<< 9
    /// d ^= (c + b) <<< 13
    /// a ^= (d + c) <<< 18
    /// ```
    #[inline]
    const fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize) {
        let words = &mut self.0;
        words[b] ^= words[a].wrapping_add(words[d]).rotate_left(7);
        words[c] ^= words[b].wrapping_add(words[a]).rotate_left(9);
        words[d] ^= words[c].wrapping_add(words[b]).rotate_left(13);
        words[a] ^= words[d].wrapping_add(words[c]).rotate_left(18);
    }

    /// Clears the words, which derive from the password.
    pub(super) fn wipe(&mut self) {
        wipe(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads sixteen little-endian words from a hex string of 64 bytes.
    fn words(text: &str) -> [u32; 16] {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect();
        let mut words = [0_u32; 16];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*chunk);
        }
        words
    }

    #[test]
    fn rfc_7914_salsa20_8_vector() {
        // RFC 7914, section 8: the first core call of the first scrypt vector.
        let mut block = SalsaBlock(words(concat!(
            "7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1d",
            "ee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e",
        )));
        block.salsa20_8();
        assert_eq!(
            block,
            SalsaBlock(words(concat!(
                "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29",
                "b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81",
            )))
        );
    }
}
