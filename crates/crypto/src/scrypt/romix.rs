//! scrypt's sequential memory-hard mix: a table of N block-mix states, read back in a data-dependent order.

use std::{fmt, mem};

use super::salsa::SalsaBlock;
use crate::ct::wipe;

/// Words in one Salsa20 block of 64 bytes.
const SALSA_WORDS: usize = 16;

/// The ROMix working memory for one parameter set, reused across the p blocks.
///
/// # Overview
///
/// ```text
/// fill  : V_i = X, then X = BlockMix(X), for i = 0 .. N - 1
/// mix   : j = Integerify(X) mod N, then X = BlockMix(X ^ V_j), N times
/// ```
///
/// A block of 128 * r bytes is held as 32 * r little-endian words.
/// Two block buffers alternate as input and output of each block mix, so no step copies a block twice.
pub(super) struct RoMix {
    /// Base-2 logarithm of the cost N.
    log_n: u8,
    /// The table V, filled by appending, so its pages are never zeroed first.
    table: Vec<u32>,
    /// The working block X.
    x: Vec<u32>,
    /// The block mix output, swapped with the working block after each mix.
    y: Vec<u32>,
}

impl RoMix {
    /// Working memory for blocks of 128 * r bytes and a table of 2^log_n blocks.
    ///
    /// The table's capacity is reserved now, so mixing never reallocates.
    pub(super) fn new(log_n: u8, r: usize) -> Self {
        let words = 2 * r * SALSA_WORDS;
        Self {
            log_n,
            table: Vec::with_capacity(words << log_n),
            x: vec![0; words],
            y: vec![0; words],
        }
    }

    /// Replaces one block of 128 * r bytes with its ROMix, per RFC 7914, section 5.
    ///
    /// # Overview
    ///
    /// The table index comes from the working block, which derives from the password.
    /// Memory accesses therefore depend on the password, by design of the memory-hard function.
    /// An attacker who observes cache timing on the same machine learns about the password.
    /// See Percival, "Stronger key derivation via sequential memory-hard functions", 2009, section 5.
    pub(super) fn mix(&mut self, block: &mut [u8]) {
        // Phase 1: X = B, read as little-endian words.
        let (bytes, _) = block.as_chunks::<4>();
        for (word, bytes) in self.x.iter_mut().zip(bytes) {
            *word = u32::from_le_bytes(*bytes);
        }

        // Phase 2: fill the table with the N successive states of X.
        let n = 1_usize << self.log_n;
        self.table.clear();
        for _ in 0..n {
            self.table.extend_from_slice(&self.x);
            self.block_mix();
        }

        // Phase 3: N reads at indices chosen by the current state.
        let words = self.x.len();
        for _ in 0..n {
            let j = self.integerify() & (n - 1);
            for (word, entry) in self.x.iter_mut().zip(&self.table[j * words..][..words]) {
                *word ^= entry;
            }
            self.block_mix();
        }

        // Phase 4: B' = X, written back as little-endian words.
        let (bytes, _) = block.as_chunks_mut::<4>();
        for (bytes, word) in bytes.iter_mut().zip(&self.x) {
            *bytes = word.to_le_bytes();
        }
    }

    /// The low word of the last 64-byte block of X, per RFC 7914, section 5.
    ///
    /// Integerify reads the whole last block as a little-endian integer.
    /// N is a power of two at most 2^32, so only its lowest word survives the reduction.
    fn integerify(&self) -> usize {
        self.x[self.x.len() - SALSA_WORDS] as usize
    }

    /// Replaces X with its BlockMix, per RFC 7914, section 4.
    ///
    /// # Overview
    ///
    /// ```text
    /// T     = B_(2r - 1)
    /// Y_i   = Salsa20/8(T ^ B_i), chaining T = Y_i, for i = 0 .. 2r - 1
    /// B'    = Y_0 || Y_2 || ... || Y_(2r - 2) || Y_1 || Y_3 || ... || Y_(2r - 1)
    /// ```
    fn block_mix(&mut self) {
        let (input, _) = self.x.as_chunks::<SALSA_WORDS>();
        let (output, _) = self.y.as_chunks_mut::<SALSA_WORDS>();
        let r = input.len() / 2;

        // Invariant: a block holds 2r >= 2 Salsa blocks, so the last one exists.
        let mut t = SalsaBlock(input[2 * r - 1]);
        for (i, block) in input.iter().enumerate() {
            t.xor(block);
            t.salsa20_8();
            // Even outputs fill the first half in order, odd outputs the second half.
            output[i / 2 + (i % 2) * r] = t.0;
        }
        t.wipe();

        // The output becomes the next input; the old input is scratch for the next mix.
        mem::swap(&mut self.x, &mut self.y);
    }
}

impl Drop for RoMix {
    fn drop(&mut self) {
        // The table holds every state of X, and V_0 is a one-iteration PBKDF2 of the password.
        // Left in memory, it would let an attacker test passwords without the memory-hard work.
        wipe(&mut self.table);
        wipe(&mut self.x);
        wipe(&mut self.y);
    }
}

impl fmt::Debug for RoMix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The table and blocks derive from the password: never print them.
        f.debug_struct("RoMix")
            .field("log_n", &self.log_n)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a hex string in a test vector.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The input block of RFC 7914, sections 9 and 10, with r = 1.
    const INPUT: &str = concat!(
        "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad",
        "89f68f4811d1e87bcc3bd7400a9ffd29094f0184639574f39ae5a1315217bcd7",
        "894991447213bb226c25b54da86370fbcd984380374666bb8ffcb5bf40c254b0",
        "67d27c51ce4ad5fed829c90b505a571b7f4d1cad6a523cda770e67bceaaf7e89",
    );

    #[test]
    fn rfc_7914_block_mix_vector() {
        // RFC 7914, section 9: one BlockMix with r = 1, two Salsa blocks.
        let mut romix = RoMix::new(1, 1);
        let input = hex(INPUT);
        for (word, bytes) in romix.x.iter_mut().zip(input.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        romix.block_mix();
        let output: Vec<u8> = romix.x.iter().flat_map(|word| word.to_le_bytes()).collect();
        assert_eq!(
            output,
            hex(concat!(
                "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29",
                "b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81",
                "20edc975323881a80540f64c162dcd3c21077cfe5f8d5fe2b1a4168f953678b7",
                "7d3b3d803b60e4ab920996e59b4d53b65d2a225877d5edf5842cb9f14eefe425",
            ))
        );
    }

    #[test]
    fn rfc_7914_romix_vector() {
        // RFC 7914, section 10: ROMix with r = 1 and N = 16 = 2^4.
        let mut block = hex(INPUT);
        RoMix::new(4, 1).mix(&mut block);
        assert_eq!(
            block,
            hex(concat!(
                "79ccc193629debca047f0b70604bf6b62ce3dd4a9626e355fafc6198e6ea2b46",
                "d58413673b99b029d665c357601fb426a0b2f4bba200ee9f0a43d19b571a9c71",
                "ef1142e65d5a266fddca832ce59faa7cac0b9cf1be2bffca300d01ee387619c4",
                "ae12fd4438f203a0e4e1c47ec314861f4e9087cb33396a6873e8f9d2539a4b8e",
            ))
        );
    }

    #[test]
    fn working_memory_is_reused_across_blocks() {
        // Fixture state: a used instance has a full table of 16 entries from block A.
        let mut used = RoMix::new(4, 1);
        let mut a = [0x11_u8; 128];
        used.mix(&mut a);

        // Block B through the used instance must match B through a fresh one.
        // A table left over from A would feed A's states into B's lookups.
        let mut b = hex(INPUT);
        used.mix(&mut b);
        let mut fresh = hex(INPUT);
        RoMix::new(4, 1).mix(&mut fresh);
        assert_eq!(b, fresh);
    }
}
