//! CRC-32C, the Castagnoli checksum that guards every record on disk.
//!
//! # Overview
//!
//! A checksum turns "the bytes look plausible" into "the bytes are what was written".
//! CRC-32C detects every burst error up to 32 bits and all odd-weight errors.
//! It is the checksum of iSCSI, ext4 metadata, LevelDB and RocksDB.
//!
//! Castagnoli's polynomial has a larger minimum Hamming distance than the Ethernet one.
//! x86-64 CPUs also compute it in hardware since SSE4.2, at about one byte per cycle per stream.
//!
//! # Algorithm
//!
//! The scalar path processes eight bytes per step with eight lookup tables, "slicing-by-8".
//! The hardware path feeds eight bytes per instruction to the dedicated CRC unit.
//! Both compute the same reflected CRC with initial value and final XOR of all ones.

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{_mm_crc32_u8, _mm_crc32_u64};

/// The Castagnoli polynomial 0x1EDC6F41, bit-reversed for least-significant-bit-first processing.
///
/// See Castagnoli, Brauer and Herrmann, "Optimization of cyclic redundancy-check codes", 1993.
const POLYNOMIAL: u32 = 0x82f6_3b78;

/// Eight lookup tables for slicing-by-8.
///
/// Table k maps a byte to its contribution after k further zero bytes have been shifted in.
static TABLES: [[u32; 256]; 8] = build_tables();

/// Builds the slicing-by-8 tables at compile time.
const fn build_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0; 256]; 8];

    // Table 0 is the classic byte-at-a-time table.
    //
    //     table_0[b] = b * x^32 mod P, computed by eight shift-and-reduce steps.
    let mut byte = 0;
    while byte < 256 {
        let mut crc = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            // Shift one bit out; reduce by the polynomial when the bit leaving was set.
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        tables[0][byte] = crc;
        byte += 1;
    }

    // Table k extends table k - 1 by one more zero byte.
    //
    //     table_k[b] = table_{k-1}[b] advanced through one byte of zeros.
    let mut k = 1;
    while k < 8 {
        let mut byte = 0;
        while byte < 256 {
            let previous = tables[k - 1][byte];
            tables[k][byte] = (previous >> 8) ^ tables[0][(previous & 0xff) as usize];
            byte += 1;
        }
        k += 1;
    }
    tables
}

/// A running CRC-32C over a stream of byte slices.
///
/// Feeding a message in pieces gives the same checksum as feeding it at once.
/// That lets recovery checksum a 300 MB value through a small read buffer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Crc32c {
    /// The register before the final inversion.
    state: u32,
}

impl Crc32c {
    /// Starts a checksum with the all-ones initial register.
    pub(crate) const fn new() -> Self {
        Self { state: !0 }
    }

    /// Feeds more bytes into the checksum, on the fastest path the CPU offers.
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("sse4.2") {
            // SAFETY: the runtime check above proves the CPU executes SSE4.2 instructions.
            unsafe {
                self.update_sse42(bytes);
            }
            return;
        }
        self.update_scalar(bytes);
    }

    /// Returns the checksum of every byte fed so far.
    pub(crate) const fn finish(self) -> u32 {
        // The final inversion makes leading and trailing zero bytes change the result.
        !self.state
    }

    /// Returns the checksum of one contiguous message.
    pub(crate) fn checksum(bytes: &[u8]) -> u32 {
        let mut crc = Self::new();
        crc.update(bytes);
        crc.finish()
    }

    /// Advances the register with slicing-by-8 tables.
    ///
    /// This is the reference every specialized path must equal.
    fn update_scalar(&mut self, bytes: &[u8]) {
        let mut state = self.state;
        let (words, tail) = bytes.as_chunks::<8>();
        for word in words {
            // Fold the register into the low four bytes, then look up all eight bytes at once.
            //
            //     byte 0 has the most zero bytes still to pass through, so it uses table 7.
            //     byte 7 is the last one in, so it uses table 0.
            let w = u64::from_le_bytes(*word) ^ u64::from(state);
            state = TABLES[7][(w & 0xff) as usize]
                ^ TABLES[6][((w >> 8) & 0xff) as usize]
                ^ TABLES[5][((w >> 16) & 0xff) as usize]
                ^ TABLES[4][((w >> 24) & 0xff) as usize]
                ^ TABLES[3][((w >> 32) & 0xff) as usize]
                ^ TABLES[2][((w >> 40) & 0xff) as usize]
                ^ TABLES[1][((w >> 48) & 0xff) as usize]
                ^ TABLES[0][(w >> 56) as usize];
        }
        for &byte in tail {
            // Fewer than eight bytes remain: fall back to one table lookup per byte.
            state = (state >> 8) ^ TABLES[0][((state ^ u32::from(byte)) & 0xff) as usize];
        }
        self.state = state;
    }

    /// Advances the register with the SSE4.2 CRC32 instruction.
    ///
    /// The instruction computes exactly the reflected Castagnoli CRC, register in and register out.
    ///
    /// # Performance
    ///
    /// One 8-byte instruction has a latency of three cycles, so one stream runs near 8 GB/s.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse4.2")]
    fn update_sse42(&mut self, bytes: &[u8]) {
        let (words, tail) = bytes.as_chunks::<8>();
        let mut wide = u64::from(self.state);
        for word in words {
            // The 64-bit form zero-extends its 32-bit result, so the register stays in the low half.
            wide = _mm_crc32_u64(wide, u64::from_le_bytes(*word));
        }
        let mut state = wide as u32;
        for &byte in tail {
            state = _mm_crc32_u8(state, byte);
        }
        self.state = state;
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn check_value_matches_the_published_catalogue() {
        // The CRC catalogue's check value for CRC-32C is the checksum of "123456789".
        assert_eq!(Crc32c::checksum(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn rfc_3720_vectors() {
        // iSCSI (RFC 3720, appendix B.4) publishes CRC-32C values for 32-byte patterns.
        //
        //     32 zero bytes        -> 0x8a9136aa
        //     32 bytes of 0xff     -> 0x62a8ab43
        //     bytes 0x00..0x1f     -> 0x46dd794e
        assert_eq!(Crc32c::checksum(&[0; 32]), 0x8a91_36aa);
        assert_eq!(Crc32c::checksum(&[0xff; 32]), 0x62a8_ab43);
        let ascending: Vec<u8> = (0..32).collect();
        assert_eq!(Crc32c::checksum(&ascending), 0x46dd_794e);
    }

    #[test]
    fn empty_message_has_zero_checksum() {
        // All-ones in, nothing absorbed, all-ones inverted: zero.
        assert_eq!(Crc32c::checksum(&[]), 0);
    }

    proptest! {
        #[test]
        fn dispatch_equals_scalar_reference(bytes in proptest::collection::vec(any::<u8>(), 0..300), seed: u32) {
            // The hardware path, when present, must agree with the tables on any register.
            let mut dispatched = Crc32c { state: seed };
            let mut scalar = dispatched;
            dispatched.update(&bytes);
            scalar.update_scalar(&bytes);
            prop_assert_eq!(dispatched.state, scalar.state);
        }

        #[test]
        fn streaming_equals_one_shot(bytes in proptest::collection::vec(any::<u8>(), 0..300), cut in 0usize..300) {
            // Split the message at an arbitrary point and feed the halves separately.
            let cut = cut.min(bytes.len());
            let mut crc = Crc32c::new();
            crc.update(&bytes[..cut]);
            crc.update(&bytes[cut..]);
            prop_assert_eq!(crc.finish(), Crc32c::checksum(&bytes));
        }

        #[test]
        fn single_bit_flips_are_detected(bytes in proptest::collection::vec(any::<u8>(), 1..300), bit in 0usize..2400) {
            // A CRC detects every single-bit error, at every position.
            let bit = bit % (bytes.len() * 8);
            let mut flipped = bytes.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            prop_assert_ne!(Crc32c::checksum(&flipped), Crc32c::checksum(&bytes));
        }
    }
}
