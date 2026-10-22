//! The block compressor: greedy LZ77 with a hash table of recent positions.
//!
//! The algorithm is the classic reference compressor of snappy 1.1, fragment for fragment.

use std::fmt;

use super::{max_compressed_len, sink::Sink, table::HashTable};

/// Bytes compressed independently, so table positions fit in 16 bits.
///
/// It also caps every copy offset below 2^16, the reach of a 2-byte offset.
const FRAGMENT_LEN: usize = 1 << 16;

/// Bytes left unsearched at the end of a fragment.
///
/// Every load in the search loop then reads 8 bytes without a bounds failure.
/// The tail goes out as a literal.
const INPUT_MARGIN: usize = 15;

/// A block compressor that keeps its hash table between inputs.
///
/// # Performance
///
/// The table holds up to 32 KiB.
/// A gossip pipeline compresses many small messages, and one encoder allocates it once for all.
/// Each fragment clears only the slots its length needs, so small inputs stay cheap.
#[derive(Clone, Default)]
pub struct Encoder {
    /// Storage of the hash table, grown to the largest fragment seen.
    table: Vec<u16>,
}

impl fmt::Debug for Encoder {
    /// Shows the table size, not its thousands of stale positions.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encoder")
            .field("table_slots", &self.table.len())
            .finish()
    }
}

impl Encoder {
    /// An encoder that has not allocated its table yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { table: Vec::new() }
    }

    /// Compresses bytes into a new block.
    ///
    /// # Panics
    ///
    /// Panics when the input exceeds 2^32 - 1 bytes, the most a block can describe.
    #[must_use]
    pub fn compress(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        self.compress_into(input, &mut out);
        out
    }

    /// Appends the compressed block of an input to a buffer.
    ///
    /// Reusing one buffer across calls saves an allocation per message.
    ///
    /// # Panics
    ///
    /// Panics when the input exceeds 2^32 - 1 bytes.
    pub fn compress_into(&mut self, input: &[u8], out: &mut Vec<u8>) {
        let len = u32::try_from(input.len())
            .unwrap_or_else(|_| panic!("snappy block of {} bytes exceeds 2^32 - 1", input.len()));

        // Reserve the worst case once, then write through a slice with no capacity checks.
        //
        // The worst case already counts the preamble.
        let start = out.len();
        out.resize(start + max_compressed_len(input.len()), 0);
        let mut sink = Sink::new(&mut out[start..]);
        sink.preamble(len);

        // The first fragment is the largest, so it sizes the table for all of them.
        //
        // A small message gets a small table: 300 bytes need 512 slots, not 16384.
        let slots = HashTable::slots_for(input.len().min(FRAGMENT_LEN));
        if self.table.len() < slots {
            self.table.resize(slots, 0);
        }
        for fragment in input.chunks(FRAGMENT_LEN) {
            let mut table = HashTable::new(&mut self.table, fragment.len());
            Fragment(fragment).compress(&mut table, &mut sink);
        }

        let written = sink.len();
        out.truncate(start + written);
    }
}

/// One fragment of at most 64 KiB, compressed on its own.
#[derive(Clone, Copy)]
struct Fragment<'a>(&'a [u8]);

impl Fragment<'_> {
    /// Little-endian 4 bytes at a position.
    #[inline]
    fn load32(self, at: usize) -> u32 {
        match self.0[at..].first_chunk::<4>() {
            Some(bytes) => u32::from_le_bytes(*bytes),
            None => unreachable!("callers stay 4 bytes before the end"),
        }
    }

    /// Little-endian 8 bytes at a position.
    #[inline]
    fn load64(self, at: usize) -> u64 {
        match self.0[at..].first_chunk::<8>() {
            Some(bytes) => u64::from_le_bytes(*bytes),
            None => unreachable!("callers stay 8 bytes before the end"),
        }
    }

    /// Number of equal bytes at two positions, the first one earlier in the fragment.
    ///
    /// It compares 8 bytes at a time.
    /// The first differing bit locates the first differing byte.
    #[inline]
    fn match_len(self, earlier: usize, later: usize) -> usize {
        // The later run is the shorter one, so it bounds the match.
        //
        // Zipping whole 8-byte blocks leaves the loop free of bounds checks.
        let (first, _) = self.0[earlier..].as_chunks::<8>();
        let (second, second_tail) = self.0[later..].as_chunks::<8>();
        for (i, (a, b)) in first.iter().zip(second).enumerate() {
            let diff = u64::from_le_bytes(*a) ^ u64::from_le_bytes(*b);
            if diff != 0 {
                // Little-endian: the lowest set bit falls in the first differing byte.
                return 8 * i + (diff.trailing_zeros() / 8) as usize;
            }
        }

        // Fewer than 8 bytes remain after the later run's last whole block.
        let matched = 8 * second.len();
        matched
            + second_tail
                .iter()
                .zip(&self.0[earlier + matched..])
                .take_while(|(a, b)| a == b)
                .count()
    }

    /// Writes the elements of this fragment.
    ///
    /// # Algorithm
    ///
    /// - Hash 4 bytes at the cursor and look up the last position with the same hash.
    /// - On a 4-byte match, emit the pending literal, then the longest copy from there.
    /// - On a miss, step forward, faster the longer no match has turned up.
    ///
    /// ```text
    /// fragment:  [ literal ........ ][ copy ][ copy ][ literal ... ][ copy ] ... [ tail ]
    /// ```
    ///
    /// One cursor marks the start of the pending literal, and the other the scan position.
    /// Matched bytes start at the scan position and become copies.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the low 4 bytes of a load are the word that starts there"
    )]
    fn compress(self, table: &mut HashTable<'_>, sink: &mut Sink<'_>) {
        let len = self.0.len();

        // Start of the bytes not yet emitted.
        let mut next_emit = 0;

        if len >= INPUT_MARGIN {
            // Searching stops here, so every load below stays in bounds.
            let ip_limit = len - INPUT_MARGIN;
            let mut ip = 1;
            let mut next_hash = table.hash(self.load32(ip));

            'fragment: loop {
                // Phase 1: search for a 4-byte match.
                //
                // The step grows by one every 32 misses:
                //
                //     misses  0..31  ->  step 1
                //     misses 32..63  ->  step 2
                //
                // Incompressible data is then skipped quickly instead of hashed byte by byte.
                let mut skip = 32_usize;
                let mut next_ip = ip;
                let mut candidate;
                loop {
                    ip = next_ip;
                    let current_hash = next_hash;
                    next_ip = ip + (skip >> 5);
                    skip += 1;
                    if next_ip > ip_limit {
                        break 'fragment;
                    }
                    next_hash = table.hash(self.load32(next_ip));
                    candidate = table.replace(current_hash, ip);
                    if self.load32(ip) == self.load32(candidate) {
                        break;
                    }
                }

                // Phase 2: the bytes before the match go out as one literal.
                sink.literal(&self.0[next_emit..ip]);

                // Phase 3: emit copies while matches keep following each other.
                loop {
                    // The first 4 bytes are known equal, so extension starts past them.
                    let matched = 4 + self.match_len(candidate + 4, ip + 4);
                    sink.copy(ip - candidate, matched);
                    ip += matched;
                    next_emit = ip;
                    if ip >= ip_limit {
                        break 'fragment;
                    }

                    // Index the two positions before the cursor, and test the cursor itself.
                    //
                    //     word = bytes ip-1 .. ip+6
                    //     low 4 bytes   ->  hash of ip-1, stored
                    //     next 4 bytes  ->  hash of ip, swapped with the stored candidate
                    let word = self.load64(ip - 1);
                    table.insert(table.hash(word as u32), ip - 1);
                    let current = (word >> 8) as u32;
                    candidate = table.replace(table.hash(current), ip);
                    if current != self.load32(candidate) {
                        break;
                    }
                }

                // No immediate match: resume the search one byte further.
                ip += 1;
                next_hash = table.hash(self.load32(ip));
            }
        }

        // The unsearched tail, and whatever followed the last copy, is one literal.
        sink.literal(&self.0[next_emit..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::decompress;

    #[test]
    fn match_length_stops_at_the_first_difference_or_the_end() {
        // 20 bytes: positions 0 and 10 agree on 7 bytes, then differ.
        let mut input = [0_u8; 20];
        input[7] = 1;
        assert_eq!(Fragment(&input).match_len(0, 10), 7);

        // Equal to the end: the later position limits the count.
        let input = [5_u8; 20];
        assert_eq!(Fragment(&input).match_len(0, 3), 17);
    }

    #[test]
    fn one_encoder_compresses_many_inputs_as_fresh_ones_do() {
        // A large input grows the table to 16384 slots, then a small one reuses it.
        let large: Vec<u8> = (0..100_000_u32).map(|i| (i % 97) as u8).collect();
        let small = b"abcabcabcabcabcabcabc".repeat(3);

        let mut encoder = Encoder::new();
        let reused = [encoder.compress(&large), encoder.compress(&small)];

        // Stale slots from the large input never leak into the small one.
        assert_eq!(reused[0], Encoder::new().compress(&large));
        assert_eq!(reused[1], Encoder::new().compress(&small));
        assert_eq!(decompress(&reused[1], small.len()).unwrap(), small);
    }
}
