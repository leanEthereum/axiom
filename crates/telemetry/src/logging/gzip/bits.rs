//! Packing variable-width fields into bytes, least significant bit first.

use std::io::{self, Write};

use crate::logging::gzip::tables::Code;

/// Packed bytes are handed to the sink once this many accumulate.
///
/// One handoff per 64 KiB keeps writes large while the buffer stays bounded.
const SPILL: usize = 1 << 16;

/// Packs fields into bytes, filling each byte from its least significant bit.
///
/// Source: RFC 1951 section 3.1.1, which fixes this packing order.
#[derive(Debug, Default)]
pub(super) struct BitWriter {
    /// Whole bytes not yet handed to the sink.
    bytes: Vec<u8>,

    /// Bits not yet forming a whole byte, right-aligned.
    pending: u64,

    /// How many bits of the pending word are in use, always below 8 between calls.
    count: u32,
}

impl BitWriter {
    /// Appends a field of up to 32 bits, least significant bit first.
    pub(super) fn put(&mut self, value: u32, width: u32) {
        // Bound: fewer than 8 pending bits plus at most 32 new ones fit in 64.
        self.pending |= u64::from(value) << self.count;
        self.count += width;
        while self.count >= 8 {
            self.bytes.push(self.pending as u8);
            self.pending >>= 8;
            self.count -= 8;
        }
    }

    /// Appends a Huffman code word, most significant bit first.
    pub(super) fn put_code(&mut self, code: Code) {
        // Huffman codes are the one field packed from the top bit, so reverse them.
        self.put(code.bits.reverse_bits() >> (32 - code.width), code.width);
    }

    /// Hands the packed bytes to a sink once enough have accumulated.
    pub(super) fn spill<W: Write>(&mut self, sink: &mut W) -> io::Result<()> {
        if self.bytes.len() >= SPILL {
            sink.write_all(&self.bytes)?;
            self.bytes.clear();
        }
        Ok(())
    }

    /// Pads the last byte with zero bits and hands every byte to a sink.
    pub(super) fn finish<W: Write>(mut self, sink: &mut W) -> io::Result<()> {
        // Zero padding up to the byte boundary is what a decoder skips.
        if self.count > 0 {
            self.bytes.push(self.pending as u8);
        }
        sink.write_all(&self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_fill_from_the_low_bit() {
        // Fields 1 in 1 bit, 1 in 2 bits, then the code 0000001 in 7 bits.
        //
        //     byte 0 = 0x03: bit 0 holds 1, bits 1-2 hold 1, bits 3-7 the code's first five zeros
        //     byte 1 = 0x02: bit 0 holds the code's sixth bit 0, bit 1 its last bit 1
        let mut writer = BitWriter::default();
        writer.put(1, 1);
        writer.put(1, 2);
        writer.put_code(Code { bits: 1, width: 7 });
        let mut out = Vec::new();
        writer.finish(&mut out).unwrap();
        assert_eq!(out, [0x03, 0x02]);
    }
}
