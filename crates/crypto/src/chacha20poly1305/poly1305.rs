//! The Poly1305 one-time authenticator of RFC 8439, section 2.5.

use std::fmt;

use crate::ct::{Mask, wipe};

/// Bytes in one message block.
const BLOCK_LEN: usize = 16;

/// The low 44 bits of a limb.
const MASK_44: u64 = (1 << 44) - 1;

/// The low 42 bits of a limb.
const MASK_42: u64 = (1 << 42) - 1;

/// A one-time MAC over GF(2^130 - 5).
///
/// # Overview
///
/// The key splits into a clamped multiplier r and a final pad s.
///
/// ```text
/// h = 0
/// for each 16-byte block m:  h = (h + m + 2^128) * r   mod 2^130 - 5
/// tag = (h + s) mod 2^128
/// ```
///
/// A short last block is padded with one 0x01 byte instead of the 2^128 bit.
///
/// # Accumulator
///
/// The 130-bit accumulator lives in three limbs of 44, 44 and 42 bits.
///
/// ```text
///    bit 130     88        44         0
///         | h2:42 | h1:44  |  h0:44   |
/// ```
///
/// A limb product is under 2^88, so a sum of three fits a 128-bit word with room to spare.
/// Products past bit 130 wrap around with a factor of 5, since 2^130 = 5 mod p.
///
/// # Security
///
/// A key must authenticate one message only.
/// Two tags under one key reveal r and allow forgeries.
#[derive(Clone)]
pub struct Poly1305 {
    /// The clamped multiplier r in limbs.
    r: [u64; 3],
    /// The final pad s, added mod 2^128.
    s: [u64; 2],
    /// The accumulator h in limbs, each a little above its nominal width between blocks.
    h: [u64; 3],
    /// Bytes of the current block not yet absorbed.
    buffer: [u8; BLOCK_LEN],
    /// How many bytes of the buffer are filled, always below a block.
    filled: usize,
}

impl Poly1305 {
    /// Bytes in a key: r then s.
    pub const KEY_LEN: usize = 32;

    /// Bytes in a tag.
    pub const TAG_LEN: usize = 16;

    /// An authenticator keyed with a one-time key.
    #[must_use]
    pub const fn new(key: &[u8; Self::KEY_LEN]) -> Self {
        let (words, _) = key.as_chunks::<8>();
        let t0 = u64::from_le_bytes(words[0]);
        let t1 = u64::from_le_bytes(words[1]);

        // Clamp r and split it into limbs at bits 44 and 88, per RFC 8439, section 2.5.1.
        //
        // Clamping clears the top 4 bits of bytes 3, 7, 11, 15 and the low 2 bits of 4, 8, 12.
        // The masks below apply both rules to each limb's slice of r.
        let r = [
            t0 & 0xffc_0fff_ffff,
            ((t0 >> 44) | (t1 << 20)) & 0xfff_ffc0_ffff,
            (t1 >> 24) & 0x00f_ffff_fc0f,
        ];
        let s = [u64::from_le_bytes(words[2]), u64::from_le_bytes(words[3])];

        Self {
            r,
            s,
            h: [0; 3],
            buffer: [0; BLOCK_LEN],
            filled: 0,
        }
    }

    /// The tag of one message under a one-time key.
    #[must_use]
    pub fn mac(key: &[u8; Self::KEY_LEN], message: &[u8]) -> [u8; Self::TAG_LEN] {
        let mut mac = Self::new(key);
        mac.update(message);
        mac.finalize()
    }

    /// Feeds more message bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        // Phase 1: top up a partly filled block.
        if self.filled > 0 {
            let take = (BLOCK_LEN - self.filled).min(data.len());
            self.buffer[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled < BLOCK_LEN {
                return;
            }
            let block = self.buffer;
            self.absorb(&block, 1 << 40);
            self.filled = 0;
        }

        // Phase 2: whole blocks straight from the input, each with its 2^128 bit.
        let (blocks, tail) = data.as_chunks::<BLOCK_LEN>();
        for block in blocks {
            self.absorb(block, 1 << 40);
        }

        // Phase 3: keep the tail.
        self.buffer[..tail.len()].copy_from_slice(tail);
        self.filled = tail.len();
    }

    /// Feeds bytes, then zeros up to the next 16-byte boundary.
    ///
    /// The AEAD construction of RFC 8439, section 2.8, pads each field this way.
    /// The zero-padded block counts as a whole block and keeps its 2^128 bit.
    pub(crate) fn update_padded(&mut self, data: &[u8]) {
        self.update(data);
        if self.filled > 0 {
            self.buffer[self.filled..].fill(0);
            let block = self.buffer;
            self.absorb(&block, 1 << 40);
            self.filled = 0;
        }
    }

    /// The tag of every byte fed so far.
    #[must_use]
    pub fn finalize(mut self) -> [u8; Self::TAG_LEN] {
        // Phase 1: a short last block gets a 0x01 byte instead of the 2^128 bit.
        if self.filled > 0 {
            let mut block = [0_u8; BLOCK_LEN];
            block[..self.filled].copy_from_slice(&self.buffer[..self.filled]);
            block[self.filled] = 1;
            self.absorb(&block, 0);
        }
        let [mut h0, mut h1, mut h2] = self.h;

        // Phase 2: carry the limbs fully, twice, so each fits its width and h < 2^130.
        for _ in 0..2 {
            h1 += h0 >> 44;
            h0 &= MASK_44;
            h2 += h1 >> 44;
            h1 &= MASK_44;
            h0 += (h2 >> 42) * 5;
            h2 &= MASK_42;
        }
        h1 += h0 >> 44;
        h0 &= MASK_44;

        // Phase 3: compute g = h + 5 - 2^130 = h - p.
        //
        //     g negative (top bit set) -> h < p, keep h
        //     g non-negative           -> h >= p, take g
        let mut g0 = h0 + 5;
        let mut g1 = h1 + (g0 >> 44);
        g0 &= MASK_44;
        let g2 = (h2 + (g1 >> 44)).wrapping_sub(1 << 42);
        g1 &= MASK_44;
        let keep_h = Mask::from_bit(g2 >> 63);
        h0 = keep_h.select(h0, g0);
        h1 = keep_h.select(h1, g1);
        h2 = keep_h.select(h2, g2 & MASK_42);

        // Phase 4: tag = (h + s) mod 2^128, rejoining the limbs into two 64-bit words.
        let low = h0 | (h1 << 44);
        let high = (h1 >> 20) | (h2 << 24);
        let (low, carry) = low.overflowing_add(self.s[0]);
        let high = high.wrapping_add(self.s[1]).wrapping_add(u64::from(carry));

        let mut tag = [0_u8; Self::TAG_LEN];
        tag[..8].copy_from_slice(&low.to_le_bytes());
        tag[8..].copy_from_slice(&high.to_le_bytes());
        tag
    }

    /// Absorbs one block: h = (h + m + high * 2^88) * r mod 2^130 - 5.
    ///
    /// The high bit argument is 2^40 for a whole block, placing the pad bit at 2^128.
    fn absorb(&mut self, block: &[u8; BLOCK_LEN], high_bit: u64) {
        let [r0, r1, r2] = self.r;
        let [mut h0, mut h1, mut h2] = self.h;

        // Phase 1: add the block, split into 44, 44 and 40 bits plus the pad bit.
        let (words, _) = block.as_chunks::<8>();
        let t0 = u64::from_le_bytes(words[0]);
        let t1 = u64::from_le_bytes(words[1]);
        h0 += t0 & MASK_44;
        h1 += ((t0 >> 44) | (t1 << 20)) & MASK_44;
        h2 += ((t1 >> 24) & MASK_42) | high_bit;

        // Phase 2: schoolbook product with wrap-around.
        //
        // Limb weights are 2^0, 2^44, 2^88.
        // A product of weight 2^132 or 2^176 wraps to 2^2 * 5 = 20 times weight 2^0 or 2^44.
        //
        //     d0 = h0 r0 + 20 h1 r2 + 20 h2 r1
        //     d1 = h0 r1 +    h1 r0 + 20 h2 r2
        //     d2 = h0 r2 +    h1 r1 +    h2 r0
        //
        // Clamping keeps r1, r2 below 2^44, so 20 r stays below 2^49 and every sum below 2^128.
        let s1 = r1 * 20;
        let s2 = r2 * 20;
        let wide = |a: u64, b: u64| u128::from(a) * u128::from(b);
        let d0 = wide(h0, r0) + wide(h1, s2) + wide(h2, s1);
        let mut d1 = wide(h0, r1) + wide(h1, r0) + wide(h2, s2);
        let mut d2 = wide(h0, r2) + wide(h1, r1) + wide(h2, r0);

        // Phase 3: partial carry, leaving each limb a few bits over its width.
        //
        //     d0 -> h0 (44 bits), carry into d1
        //     d1 -> h1 (44 bits), carry into d2
        //     d2 -> h2 (42 bits), carry * 5 back into h0
        d1 += d0 >> 44;
        h0 = (d0 as u64) & MASK_44;
        d2 += d1 >> 44;
        h1 = (d1 as u64) & MASK_44;
        let carry = (d2 >> 42) as u64;
        h2 = (d2 as u64) & MASK_42;
        h0 += carry * 5;
        h1 += h0 >> 44;
        h0 &= MASK_44;

        self.h = [h0, h1, h2];
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        wipe(&mut self.r);
        wipe(&mut self.s);
        wipe(&mut self.h);
        wipe(&mut self.buffer);
    }
}

impl fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key and the accumulator are secret: never print them.
        f.debug_struct("Poly1305").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Decodes a hex string in a test vector.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The tag computed with arbitrary-precision arithmetic, straight from the definition.
    ///
    /// Numbers are little-endian vectors of 32-bit words.
    fn reference_mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
        // Clamp r with the byte masks of RFC 8439, section 2.5.1.
        let mut r_bytes: [u8; 16] = key[..16].try_into().unwrap();
        for i in [3, 7, 11, 15] {
            r_bytes[i] &= 0b0000_1111;
        }
        for i in [4, 8, 12] {
            r_bytes[i] &= 0b1111_1100;
        }
        let r = u128::from_le_bytes(r_bytes);
        let s = u128::from_le_bytes(key[16..].try_into().unwrap());

        // h is kept as (high, low) with high < 4, so h < 2^130 always.
        let p_low = u128::MAX - 4;
        let (mut high, mut low) = (0_u128, 0_u128);
        for chunk in message.chunks(16) {
            // Add the block with its 0x01 byte above the data.
            let mut bytes = [0_u8; 17];
            bytes[..chunk.len()].copy_from_slice(chunk);
            bytes[chunk.len()] = 1;
            let m_low = u128::from_le_bytes(bytes[..16].try_into().unwrap());
            let (sum, carry) = low.overflowing_add(m_low);
            low = sum;
            high += u128::from(bytes[16]) + u128::from(carry);

            // Multiply by r with shift-and-add mod 2^130 - 5, one bit of r at a time.
            let (mut acc_high, mut acc_low) = (0_u128, 0_u128);
            for bit in (0..128).rev() {
                // Double the accumulator, then reduce.
                acc_high = (acc_high << 1) | (acc_low >> 127);
                acc_low <<= 1;
                (acc_high, acc_low) = reduce(acc_high, acc_low, p_low);
                if (r >> bit) & 1 == 1 {
                    let (sum, carry) = acc_low.overflowing_add(low);
                    acc_low = sum;
                    acc_high += high + u128::from(carry);
                    (acc_high, acc_low) = reduce(acc_high, acc_low, p_low);
                }
            }
            (high, low) = (acc_high, acc_low);
        }
        low.wrapping_add(s).to_le_bytes()
    }

    /// Brings a value below 2^131 under p = 2^130 - 5.
    fn reduce(mut high: u128, mut low: u128, p_low: u128) -> (u128, u128) {
        // Fold bits at and above 2^130: x = a + 2^130 b is a + 5b mod p.
        while high >= 4 {
            let b = high >> 2;
            high &= 3;
            let (sum, carry) = low.overflowing_add(b * 5);
            low = sum;
            high += u128::from(carry);
        }
        // One subtraction of p when x >= p = 3 * 2^128 + (2^128 - 5).
        if high == 3 && low >= p_low {
            (0, low - p_low)
        } else {
            (high, low)
        }
    }

    #[test]
    fn rfc_8439_mac_vector() {
        // RFC 8439, section 2.5.2: "Cryptographic Forum Research Group", 34 bytes.
        let key: [u8; 32] = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .try_into()
            .unwrap();
        assert_eq!(
            Poly1305::mac(&key, b"Cryptographic Forum Research Group").to_vec(),
            hex("a8061dc1305136c6c22b8baf0c0127a9")
        );
    }

    #[test]
    fn rfc_8439_edge_vectors() {
        // RFC 8439, appendix A.3, vectors 5, 6, 10 and 11: reductions at the edge of p.
        //
        //     5  : h reaches 2^130 - 5 + small, so the final subtraction fires
        //     6  : s pushes h + s past 2^128, so the carry must be dropped
        //     10, 11 : the partial carry chain runs through every limb
        let mut key = [0_u8; 32];
        key[0] = 2;
        assert_eq!(
            Poly1305::mac(&key, &[0xff; 16]).to_vec(),
            hex("03000000000000000000000000000000")
        );

        let mut key = [0_u8; 32];
        key[0] = 2;
        key[16..].fill(0xff);
        let mut message = [0_u8; 16];
        message[0] = 2;
        assert_eq!(
            Poly1305::mac(&key, &message).to_vec(),
            hex("03000000000000000000000000000000")
        );

        let mut key = [0_u8; 32];
        key[0] = 1;
        key[8] = 4;
        let message = hex(concat!(
            "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000",
            "00000000000000000000000000000000",
        ));
        assert_eq!(
            Poly1305::mac(&key, &message).to_vec(),
            hex("13000000000000000000000000000000")
        );

        // Vector 10 appends one more block, and the tag gains a carry into byte 8.
        let mut longer = message;
        longer.extend(hex("01000000000000000000000000000000"));
        assert_eq!(
            Poly1305::mac(&key, &longer).to_vec(),
            hex("14000000000000005500000000000000")
        );
    }

    proptest! {
        #[test]
        fn limbs_match_the_wide_integer_reference(
            key in any::<[u8; 32]>(),
            message in prop::collection::vec(any::<u8>(), 0..100),
        ) {
            // The 44-bit limb arithmetic equals the textbook computation on wide integers.
            prop_assert_eq!(Poly1305::mac(&key, &message), reference_mac(&key, &message));
        }

        #[test]
        fn saturated_inputs_match_the_reference(blocks in 1_usize..8, s in any::<[u8; 16]>()) {
            // All-ones r and message: the largest limbs the clamp allows.
            let mut key = [0xff_u8; 32];
            key[16..].copy_from_slice(&s);
            let message = vec![0xff; blocks * 16];
            prop_assert_eq!(Poly1305::mac(&key, &message), reference_mac(&key, &message));
        }

        #[test]
        fn pieces_authenticate_like_the_whole(
            key in any::<[u8; 32]>(),
            message in prop::collection::vec(any::<u8>(), 0..200),
            cut in any::<prop::sample::Index>(),
        ) {
            // Splitting the message anywhere gives the one-shot tag.
            let at = cut.index(message.len() + 1);
            let mut mac = Poly1305::new(&key);
            mac.update(&message[..at]);
            mac.update(&message[at..]);
            prop_assert_eq!(mac.finalize(), Poly1305::mac(&key, &message));
        }
    }
}
