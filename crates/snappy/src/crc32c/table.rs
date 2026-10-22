//! Portable CRC-32C by slicing-by-8 tables, the reference every other path must match.

/// The Castagnoli polynomial 0x1EDC6F41, bit-reversed for least-significant-bit-first order.
const POLYNOMIAL: u32 = 0x82f6_3b78;

/// Eight tables of 256 entries, built at compile time.
///
/// Table 0 advances the CRC by one byte.
/// Table k advances it by one byte followed by k zero bytes.
///
/// ```text
/// T[0][b] = crc of the single byte b
/// T[k][b] = (T[k-1][b] >> 8) ^ T[0][T[k-1][b] & 0xff]
/// ```
static TABLES: [[u32; 256]; 8] = build_tables();

/// Builds the slicing tables.
const fn build_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0_u32; 256]; 8];

    // Table 0: shift each byte through the polynomial bit by bit.
    let mut byte = 0_u32;
    while byte < 256 {
        let mut crc = byte;
        let mut bit = 0;
        while bit < 8 {
            // Reflected division step: shift right, and fold in the polynomial on a carry.
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        tables[0][byte as usize] = crc;
        byte += 1;
    }

    // Tables 1..7: each one is the previous table pushed through one more zero byte.
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

/// Advances a raw CRC state over the bytes.
///
/// The state is the inverted CRC, as the hardware instructions use it.
pub(crate) fn update(mut crc: u32, bytes: &[u8]) -> u32 {
    let (blocks, tail) = bytes.as_chunks::<8>();
    for block in blocks {
        // Fold the state into the first four bytes, then look up all eight at once.
        //
        //     bytes:   b0 b1 b2 b3 b4 b5 b6 b7
        //     tables:  T7 T6 T5 T4 T3 T2 T1 T0
        //
        // Byte i still has 7 - i bytes after it in the block, hence table 7 - i.
        let [b0, b1, b2, b3, b4, b5, b6, b7] = *block;
        let low = crc ^ u32::from_le_bytes([b0, b1, b2, b3]);
        let [l0, l1, l2, l3] = low.to_le_bytes();
        crc = TABLES[7][usize::from(l0)]
            ^ TABLES[6][usize::from(l1)]
            ^ TABLES[5][usize::from(l2)]
            ^ TABLES[4][usize::from(l3)]
            ^ TABLES[3][usize::from(b4)]
            ^ TABLES[2][usize::from(b5)]
            ^ TABLES[1][usize::from(b6)]
            ^ TABLES[0][usize::from(b7)];
    }

    // Fewer than 8 bytes remain: one table lookup per byte.
    for &byte in tail {
        let index = usize::from(crc.to_le_bytes()[0] ^ byte);
        crc = TABLES[0][index] ^ (crc >> 8);
    }
    crc
}

/// Advances a raw CRC state one bit at a time, the textbook definition.
///
/// Tests pin the table path to this one.
#[cfg(test)]
pub(crate) fn update_bitwise(mut crc: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
        }
    }
    crc
}
