//! The Salsa20/8 core, the mixing function inside scrypt's block mix.

use crate::ct::wipe;

/// Word positions of the eight quarter-rounds in one Salsa20 double round.
///
/// Each entry is (a, b, c, d) for the steps below, per the Salsa20 specification, section 8:
///
/// ```text
/// b ^= (a + d) <<< 7
/// c ^= (b + a) <<< 9
/// d ^= (c + b) <<< 13
/// a ^= (d + c) <<< 18
/// ```
///
/// The first four act on the columns of the 4x4 state, the last four on its rows.
const DOUBLE_ROUND: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [5, 9, 13, 1],
    [10, 14, 2, 6],
    [15, 3, 7, 11],
    [0, 1, 2, 3],
    [5, 6, 7, 4],
    [10, 11, 8, 9],
    [15, 12, 13, 14],
];

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
    pub(super) fn salsa20_8(&mut self) {
        let input = self.0;
        let x = &mut self.0;
        for _ in 0..DOUBLE_ROUNDS {
            for [a, b, c, d] in DOUBLE_ROUND {
                x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
                x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
                x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
                x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
            }
        }
        // Feed-forward: out = rounds(in) + in, word by word modulo 2^32.
        for (word, input) in x.iter_mut().zip(input) {
            *word = word.wrapping_add(input);
        }
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
