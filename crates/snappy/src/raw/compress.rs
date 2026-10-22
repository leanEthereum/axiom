//! The block compressor: greedy LZ77 with a hash table of recent positions.
//!
//! The algorithm is the classic reference compressor of snappy 1.1, fragment for fragment.

use super::{max_compressed_len, write_preamble};

/// Bytes compressed independently, so table positions fit in 16 bits.
///
/// It also caps every copy offset below 2^16, the reach of a 2-byte offset.
const FRAGMENT_LEN: usize = 1 << 16;

/// Largest hash table, 2^14 entries of 2 bytes: 32 KiB, which stays in L1 cache.
const MAX_TABLE_BITS: u32 = 14;

/// Smallest hash table, so tiny inputs do not pay for clearing a large one.
const MIN_TABLE_BITS: u32 = 8;

/// Bytes left unsearched at the end of a fragment.
///
/// Every load in the search loop then reads 8 bytes without a bounds failure.
/// The tail goes out as a literal.
const INPUT_MARGIN: usize = 15;

/// Multiplier of the hash: odd, with well-mixed bits, from the reference.
const HASH_MULTIPLIER: u32 = 0x1e35_a7bd;

/// Appends the compressed block of an input to a buffer.
///
/// Reusing one buffer across calls saves an allocation per message.
///
/// # Panics
///
/// Panics when the input exceeds 2^32 - 1 bytes.
pub fn compress_into(input: &[u8], out: &mut Vec<u8>) {
    let len = u32::try_from(input.len())
        .unwrap_or_else(|_| panic!("snappy block of {} bytes exceeds 2^32 - 1", input.len()));
    write_preamble(len, out);

    // Reserve the worst case once, then write through a slice with no capacity checks.
    let start = out.len();
    out.resize(start + max_compressed_len(input.len()), 0);
    let mut sink = Sink {
        buf: &mut out[start..],
        len: 0,
    };

    // One table for all fragments, sized for the first and cleared per fragment.
    //
    // A small message gets a small table: 300 bytes need 512 slots, not 16384.
    let mut table = vec![0_u16; 1 << table_bits(input.len().min(FRAGMENT_LEN))];
    for fragment in input.chunks(FRAGMENT_LEN) {
        compress_fragment(fragment, &mut sink, &mut table);
    }

    let written = sink.len;
    out.truncate(start + written);
}

/// Number of hash bits for a fragment of the given length.
///
/// The table grows with the input up to its cap, rounded up to a power of two.
const fn table_bits(len: usize) -> u32 {
    let bits = len.saturating_sub(1).bit_width();
    if bits < MIN_TABLE_BITS {
        MIN_TABLE_BITS
    } else if bits > MAX_TABLE_BITS {
        MAX_TABLE_BITS
    } else {
        bits
    }
}

/// Hash of 4 bytes, keeping the top bits of a multiplicative hash.
///
/// A shift of 32 - bits leaves a value below 2^bits, a valid table index.
#[inline]
const fn hash(word: u32, shift: u32) -> usize {
    (word.wrapping_mul(HASH_MULTIPLIER) >> shift) as usize
}

/// Little-endian 4 bytes at a position.
#[inline]
fn load32(input: &[u8], at: usize) -> u32 {
    match input[at..].first_chunk::<4>() {
        Some(bytes) => u32::from_le_bytes(*bytes),
        None => unreachable!("callers stay 4 bytes before the end"),
    }
}

/// Little-endian 8 bytes at a position.
#[inline]
fn load64(input: &[u8], at: usize) -> u64 {
    match input[at..].first_chunk::<8>() {
        Some(bytes) => u64::from_le_bytes(*bytes),
        None => unreachable!("callers stay 8 bytes before the end"),
    }
}

/// Compresses one fragment of at most 64 KiB.
///
/// # Algorithm
///
/// - Hash 4 bytes at the cursor and look up the last position with the same hash.
/// - On a 4-byte match, emit the pending literal, then the longest copy from there.
/// - On a miss, step forward, faster the longer no match has turned up.
///
/// ```text
/// fragment:  [ literal ........ ][ copy ][ copy ][ literal ... ][ copy ] ... [ tail ]
///             next_emit      ip   <- matched bytes ->
/// ```
#[expect(
    clippy::cast_possible_truncation,
    reason = "positions in a fragment are below 2^16 and fit the u16 table"
)]
fn compress_fragment(input: &[u8], sink: &mut Sink<'_>, table: &mut [u16]) {
    let len = input.len();
    let bits = table_bits(len);
    let shift = 32 - bits;
    // Only the slots this fragment's hash can reach are used and cleared.
    //
    // Fragments after the first are full 64 KiB ones, so the table is never too short.
    let table = &mut table[..1 << bits];
    table.fill(0);

    // Start of the bytes not yet emitted.
    let mut next_emit = 0;

    if len >= INPUT_MARGIN {
        // Searching stops here, so every load below stays in bounds.
        let ip_limit = len - INPUT_MARGIN;
        let mut ip = 1;
        let mut next_hash = hash(load32(input, ip), shift);

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
                next_hash = hash(load32(input, next_ip), shift);
                candidate = usize::from(table[current_hash]);
                table[current_hash] = ip as u16;
                if load32(input, ip) == load32(input, candidate) {
                    break;
                }
            }

            // Phase 2: the bytes before the match go out as one literal.
            sink.literal(&input[next_emit..ip]);

            // Phase 3: emit copies while matches keep following each other.
            loop {
                // The first 4 bytes are known equal, so extension starts past them.
                let matched = 4 + match_len(input, candidate + 4, ip + 4);
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
                let word = load64(input, ip - 1);
                table[hash(word as u32, shift)] = (ip - 1) as u16;
                let current = (word >> 8) as u32;
                let current_hash = hash(current, shift);
                candidate = usize::from(table[current_hash]);
                table[current_hash] = ip as u16;
                if current != load32(input, candidate) {
                    break;
                }
            }

            // No immediate match: resume the search one byte further.
            ip += 1;
            next_hash = hash(load32(input, ip), shift);
        }
    }

    // The unsearched tail, and whatever followed the last copy, is one literal.
    sink.literal(&input[next_emit..]);
}

/// Number of equal bytes at two positions, the first one earlier in the input.
///
/// It compares 8 bytes at a time.
/// The first differing bit locates the first differing byte.
#[inline]
fn match_len(input: &[u8], earlier: usize, later: usize) -> usize {
    // The later run is the shorter one, so it bounds the match.
    //
    // Zipping whole 8-byte blocks leaves the loop free of bounds checks.
    let (first, _) = input[earlier..].as_chunks::<8>();
    let (second, second_tail) = input[later..].as_chunks::<8>();
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
            .zip(&input[earlier + matched..])
            .take_while(|(a, b)| a == b)
            .count()
}

/// A cursor writing elements into a buffer already sized for the worst case.
struct Sink<'a> {
    /// The output space.
    buf: &'a mut [u8],
    /// Bytes written so far.
    len: usize,
}

impl Sink<'_> {
    /// Writes one byte.
    #[inline]
    const fn push(&mut self, byte: u8) {
        self.buf[self.len] = byte;
        self.len += 1;
    }

    /// Writes a run of bytes.
    #[inline]
    fn extend(&mut self, bytes: &[u8]) {
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    /// Writes a literal element: a tag, then the bytes verbatim.
    ///
    /// ```text
    /// length 1..60:   [ (len - 1) << 2 | 00 ][ bytes ]
    /// length > 60:    [ (59 + k) << 2 | 00 ][ len - 1 as k little-endian bytes ][ bytes ]
    /// ```
    #[expect(
        clippy::cast_possible_truncation,
        reason = "each cast follows a range check that makes it exact"
    )]
    fn literal(&mut self, bytes: &[u8]) {
        let Some(n) = bytes.len().checked_sub(1) else {
            return;
        };
        if n < 60 {
            self.push((n as u8) << 2);
        } else {
            // Count the bytes of len - 1: 1 to 4, since fragments stay below 2^32.
            let extra = n.bit_width().div_ceil(8) as usize;
            self.push(((59 + extra) as u8) << 2);
            self.extend(&n.to_le_bytes()[..extra]);
        }
        self.extend(bytes);
    }

    /// Writes copy elements for a back-reference of any length.
    ///
    /// One element holds at most 64 bytes.
    /// Long matches split into 64-byte pieces that leave at least 4 bytes for the last one.
    /// That keeps the last piece eligible for the short 1-byte-offset form.
    fn copy(&mut self, offset: usize, mut len: usize) {
        while len >= 68 {
            self.copy_upto_64(offset, 64);
            len -= 64;
        }
        // 65..67 bytes: 60 now leaves 5..7 for the last piece.
        if len > 64 {
            self.copy_upto_64(offset, 60);
            len -= 60;
        }
        self.copy_upto_64(offset, len);
    }

    /// Writes one copy element of 1 to 64 bytes in its shortest form.
    ///
    /// ```text
    /// 1-byte offset, len 4..11, offset < 2048:
    ///     [ offset >> 8 : 3 bits | len - 4 : 3 bits | 01 ][ offset & 0xff ]
    /// 2-byte offset, offset < 65536:
    ///     [ len - 1 : 6 bits | 10 ][ offset : u16 little-endian ]
    /// 4-byte offset:
    ///     [ len - 1 : 6 bits | 11 ][ offset : u32 little-endian ]
    /// ```
    #[expect(
        clippy::cast_possible_truncation,
        reason = "each cast follows a range check that makes it exact"
    )]
    fn copy_upto_64(&mut self, offset: usize, len: usize) {
        debug_assert!((1..=64).contains(&len) && offset > 0);
        if (4..12).contains(&len) && offset < 2048 {
            self.push(0b01 | (((len - 4) as u8) << 2) | (((offset >> 8) as u8) << 5));
            self.push(offset as u8);
        } else if offset < 1 << 16 {
            self.push(0b10 | (((len - 1) as u8) << 2));
            self.extend(&(offset as u16).to_le_bytes());
        } else {
            self.push(0b11 | (((len - 1) as u8) << 2));
            self.extend(&(offset as u32).to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::decompress;

    /// The element bytes a sink writes for one call.
    fn emitted(write: impl FnOnce(&mut Sink<'_>)) -> Vec<u8> {
        let mut buf = vec![0; 256];
        let mut sink = Sink {
            buf: &mut buf,
            len: 0,
        };
        write(&mut sink);
        let len = sink.len;
        buf.truncate(len);
        buf
    }

    #[test]
    fn literal_tags_at_each_length_boundary() {
        // 60 bytes: the largest length held in the tag itself, (60 - 1) << 2 = 0xec.
        let bytes = emitted(|s| s.literal(&[7; 60]));
        assert_eq!(bytes[0], 0xec);
        assert_eq!(bytes.len(), 1 + 60);

        // 61 bytes: tag 60 << 2 = 0xf0, then one length byte holding 60.
        let bytes = emitted(|s| s.literal(&[7; 61]));
        assert_eq!(&bytes[..2], &[0xf0, 60]);

        // 257 bytes: len - 1 = 256 needs two bytes, tag 61 << 2 = 0xf4.
        let mut buf = vec![0; 300];
        let mut sink = Sink {
            buf: &mut buf,
            len: 0,
        };
        sink.literal(&[1; 257]);
        assert_eq!(&buf[..3], &[0xf4, 0x00, 0x01]);

        // An empty literal writes nothing.
        assert_eq!(emitted(|s| s.literal(&[])), Vec::<u8>::new());
    }

    #[test]
    fn copy_forms_by_length_and_offset() {
        // Short and near: 1-byte offset, len 11, offset 2047.
        //
        //     tag = (2047 >> 8) << 5 | (11 - 4) << 2 | 01 = 0xfd
        assert_eq!(emitted(|s| s.copy(2047, 11)), [0xfd, 0xff]);

        // Offset 2048 no longer fits 11 bits: 2-byte form, tag (11 - 1) << 2 | 10 = 0x2a.
        assert_eq!(emitted(|s| s.copy(2048, 11)), [0x2a, 0x00, 0x08]);

        // Length 12 no longer fits 3 bits: 2-byte form even for a small offset.
        assert_eq!(emitted(|s| s.copy(1, 12)), [0x2e, 0x01, 0x00]);

        // Offset 65536 needs the 4-byte form, tag (4 - 1) << 2 | 11 = 0x0f.
        assert_eq!(
            emitted(|s| s.copy(65_536, 4)),
            [0x0f, 0x00, 0x00, 0x01, 0x00]
        );
    }

    #[test]
    fn long_copies_split_keeping_four_bytes_for_the_last_piece() {
        // 67 bytes at offset 1: 60 + 7, never 64 + 3.
        //
        //     piece 1: len 60, 2-byte form   [ 0xee, 0x01, 0x00 ]
        //     piece 2: len 7,  1-byte form   [ 0x0d, 0x01 ]
        assert_eq!(emitted(|s| s.copy(1, 67)), [0xee, 0x01, 0x00, 0x0d, 0x01]);

        // 68 bytes: 64 + 4.
        assert_eq!(emitted(|s| s.copy(1, 68)), [0xfe, 0x01, 0x00, 0x01, 0x01]);
    }

    #[test]
    fn four_byte_offsets_decode() {
        // Build a block by hand: 70000 literal bytes, then a 4-byte-offset copy of 8.
        //
        //     output[70000..70008] = output[0..8]
        let head: Vec<u8> = (0..70_000_u32).map(|i| (i % 251) as u8).collect();
        let mut block = Vec::new();
        write_preamble(70_008, &mut block);
        let start = block.len();
        block.resize(start + 70_100, 0);
        let mut sink = Sink {
            buf: &mut block[start..],
            len: 0,
        };
        sink.literal(&head);
        sink.copy(70_000, 8);
        let len = sink.len;
        block.truncate(start + len);

        // The copy reaches back past 2^16, which only the 4-byte form can say.
        let out = decompress(&block, 70_008).unwrap();
        assert_eq!(&out[..70_000], &head[..]);
        assert_eq!(&out[70_000..], &head[..8]);
    }

    #[test]
    fn table_grows_with_the_fragment_up_to_its_cap() {
        // Below 256 bytes: the floor; then the next power of two; then the cap.
        assert_eq!(table_bits(0), MIN_TABLE_BITS);
        assert_eq!(table_bits(256), 8);
        assert_eq!(table_bits(257), 9);
        assert_eq!(table_bits(1 << 14), 14);
        assert_eq!(table_bits(1 << 16), MAX_TABLE_BITS);
    }

    #[test]
    fn match_length_stops_at_the_first_difference_or_the_end() {
        // 20 bytes: positions 0 and 10 agree on 7 bytes, then differ.
        let mut input = [0_u8; 20];
        input[7] = 1;
        assert_eq!(match_len(&input, 0, 10), 7);

        // Equal to the end: the later position limits the count.
        let input = [5_u8; 20];
        assert_eq!(match_len(&input, 0, 3), 17);
    }
}
