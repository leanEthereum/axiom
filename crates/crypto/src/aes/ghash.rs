//! GHASH, the polynomial hash that authenticates GCM, per NIST SP 800-38D, section 6.4.

#[cfg(target_arch = "x86_64")]
use std::arch::is_x86_feature_detected;
use std::slice;

use super::BLOCK_LEN;
#[cfg(target_arch = "x86_64")]
use super::clmul;
use crate::ct::wipe;

/// A running GHASH under one hash key H.
///
/// # Overview
///
/// ```text
/// Y_0 = 0
/// Y_i = (Y_(i-1) ^ X_i) * H     in GF(2^128) = GF(2)[x] / (x^128 + x^7 + x^2 + x + 1)
/// ```
///
/// # Representation
///
/// GCM writes polynomials bit-reflected: the first bit of a block is the coefficient of x^0.
/// Each block is reversed once on entry, so arithmetic runs in the natural order.
///
/// ```text
/// bytes   : b0 = [x^0 x^1 ... x^7]  b1 = [x^8 ... x^15]  ...   (most significant bit first)
/// u128    : bit i = coefficient of x^i
/// ```
///
/// Then a carry-less product is a plain shift-and-XOR product, and reduction folds bits above 127.
pub(super) struct Ghash {
    /// H, H^2, H^3, H^4, in the natural bit order.
    powers: [u128; 4],
    /// The running value Y, in the natural bit order.
    acc: u128,
    /// Whether the CPU offers PCLMULQDQ and SSSE3.
    hardware: bool,
}

impl Ghash {
    /// A hash keyed by H = AES_K(0^128), on the fastest path the CPU supports.
    pub(super) fn new(h: &[u8; BLOCK_LEN]) -> Self {
        Self::with_path(h, Self::hardware_available())
    }

    /// A hash keyed by H on a chosen path.
    pub(super) fn with_path(h: &[u8; BLOCK_LEN], hardware: bool) -> Self {
        // Four powers let the hardware path fold four blocks per reduction.
        let h = Self::to_natural(h);
        let h2 = Self::mul(h, h);
        let h3 = Self::mul(h2, h);
        let h4 = Self::mul(h3, h);
        Self {
            powers: [h, h2, h3, h4],
            acc: 0,
            hardware,
        }
    }

    /// Whether this CPU runs the hardware path.
    #[cfg(target_arch = "x86_64")]
    fn hardware_available() -> bool {
        is_x86_feature_detected!("pclmulqdq") && is_x86_feature_detected!("ssse3")
    }

    /// Whether this CPU runs the hardware path.
    #[cfg(not(target_arch = "x86_64"))]
    const fn hardware_available() -> bool {
        false
    }

    /// Absorbs the data, then zeros up to the next block boundary.
    ///
    /// GCM pads the AAD and the ciphertext this way, per SP 800-38D, section 7.1.
    pub(super) fn update_padded(&mut self, data: &[u8]) {
        // Whole blocks go straight in.
        // A short tail is zero-padded to one more block.
        let (blocks, tail) = data.as_chunks::<BLOCK_LEN>();
        self.update_blocks(blocks);
        if !tail.is_empty() {
            let mut last = [0_u8; BLOCK_LEN];
            last[..tail.len()].copy_from_slice(tail);
            self.update_blocks(&[last]);
        }
    }

    /// Absorbs whole blocks.
    pub(super) fn update_blocks(&mut self, blocks: &[[u8; BLOCK_LEN]]) {
        #[cfg(target_arch = "x86_64")]
        if self.hardware {
            // SAFETY: the flag is set only when the CPU reports PCLMULQDQ and SSSE3.
            // Those are the features the function enables.
            self.acc = unsafe { clmul::update(&self.powers, self.acc, blocks) };
            return;
        }
        self.acc = Self::update_portable(self.powers[0], self.acc, blocks);
    }

    /// Absorbs whole blocks one at a time, the reference for the hardware path.
    fn update_portable(h: u128, mut acc: u128, blocks: &[[u8; BLOCK_LEN]]) -> u128 {
        // Horner's rule, one block at a time.
        for block in blocks {
            acc = Self::mul(acc ^ Self::to_natural(block), h);
        }
        acc
    }

    /// The hash value Y, back in GCM's byte order.
    pub(super) const fn finalize(&self) -> [u8; BLOCK_LEN] {
        // Reversing all 128 bits undoes the entry conversion.
        self.acc.reverse_bits().to_be_bytes()
    }

    /// A block in the natural bit order: bit i is the coefficient of x^i.
    pub(super) const fn to_natural(block: &[u8; BLOCK_LEN]) -> u128 {
        // The first byte's top bit is x^0.
        // As a big-endian integer it is bit 127, so reverse.
        u128::from_be_bytes(*block).reverse_bits()
    }

    /// The product a * b in GF(2^128), in constant time.
    pub(super) fn mul(a: u128, b: u128) -> u128 {
        // A 256-bit carry-less product, then reduction modulo the GCM polynomial.
        let (high, low) = clmul_128(a, b);
        reduce(high, low)
    }
}

impl Drop for Ghash {
    fn drop(&mut self) {
        // H is a secret derived from the key.
        wipe(&mut self.powers);
        wipe(slice::from_mut(&mut self.acc));
    }
}

/// The 256-bit carry-less product of two 128-bit polynomials, by Karatsuba.
///
/// ```text
/// a b = a1 b1 x^128 + ((a0 + a1)(b0 + b1) + a0 b0 + a1 b1) x^64 + a0 b0
/// ```
fn clmul_128(a: u128, b: u128) -> (u128, u128) {
    // Split both operands into 64-bit halves: three half products replace four.
    let (a0, a1) = (a as u64, (a >> 64) as u64);
    let (b0, b1) = (b as u64, (b >> 64) as u64);
    let low = clmul_64(a0, b0);
    let high = clmul_64(a1, b1);
    let middle = clmul_64(a0 ^ a1, b0 ^ b1) ^ low ^ high;
    (high ^ (middle >> 64), low ^ (middle << 64))
}

/// The 128-bit carry-less product of two 64-bit polynomials.
///
/// The low half comes straight from a masked integer product.
/// The high half is the low half of the bit-reversed product, reversed back.
///
/// ```text
/// rev(a) rev(b) = rev_127(a b)   so   high(a b) = rev(low(rev(a) rev(b))) >> 1
/// ```
fn clmul_64(a: u64, b: u64) -> u128 {
    // The low half directly, the high half through bit reversal.
    let low = clmul_64_low(a, b);
    let high = clmul_64_low(a.reverse_bits(), b.reverse_bits()).reverse_bits() >> 1;
    (u128::from(high) << 64) | u128::from(low)
}

/// The low 64 bits of a carry-less product, with integer multiplications.
///
/// # Algorithm
///
/// Keep every fourth bit of each operand, leaving three-bit holes between them.
/// An integer product then sums at most 15 terms per kept position below bit 60.
/// Such a sum fits in four bits, so its carries stay inside the holes.
///
/// Only position 60 can sum 16 terms, and that carry leaves the word.
/// Masking afterwards keeps exactly the parity, which is the carry-less coefficient.
///
/// ```text
/// x0 = x & 0x1111..   positions 0 mod 4
/// z0 = x0 y0 ^ x1 y3 ^ x2 y2 ^ x3 y1   every term lands on positions 0 mod 4
/// ```
///
/// This is the constant-time multiplier of BearSSL.
/// It relies on integer multiplication taking constant time, as it does on 64-bit CPUs.
const fn clmul_64_low(x: u64, y: u64) -> u64 {
    // Masks selecting the bit positions 0, 1, 2 and 3 mod 4.
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = 0x2222_2222_2222_2222;
    const M2: u64 = 0x4444_4444_4444_4444;
    const M3: u64 = 0x8888_8888_8888_8888;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);

    // Group the 16 partial products by the residue of their bit positions mod 4.
    let z0 = x0.wrapping_mul(y0) ^ x1.wrapping_mul(y3) ^ x2.wrapping_mul(y2) ^ x3.wrapping_mul(y1);
    let z1 = x0.wrapping_mul(y1) ^ x1.wrapping_mul(y0) ^ x2.wrapping_mul(y3) ^ x3.wrapping_mul(y2);
    let z2 = x0.wrapping_mul(y2) ^ x1.wrapping_mul(y1) ^ x2.wrapping_mul(y0) ^ x3.wrapping_mul(y3);
    let z3 = x0.wrapping_mul(y3) ^ x1.wrapping_mul(y2) ^ x2.wrapping_mul(y1) ^ x3.wrapping_mul(y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// Reduces a 256-bit product modulo x^128 + x^7 + x^2 + x + 1.
///
/// ```text
/// high x^128 = high (x^7 + x^2 + x + 1)
/// ```
///
/// The shifts push up to 7 bits past bit 127, and those fold back once more.
const fn reduce(high: u128, low: u128) -> u128 {
    // Bits of high pushed past bit 127 by the shifts by 1, 2 and 7.
    let overflow = (high >> 127) ^ (high >> 126) ^ (high >> 121);
    low ^ high
        ^ (high << 1)
        ^ (high << 2)
        ^ (high << 7)
        ^ overflow
        ^ (overflow << 1)
        ^ (overflow << 2)
        ^ (overflow << 7)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// The carry-less product bit by bit, the textbook definition.
    fn clmul_reference(a: u128, b: u128) -> (u128, u128) {
        let (mut high, mut low) = (0_u128, 0_u128);
        for i in 0..128 {
            if (b >> i) & 1 == 1 {
                low ^= a << i;
                if i > 0 {
                    high ^= a >> (128 - i);
                }
            }
        }
        (high, low)
    }

    /// Multiplication in GCM's own bit order, by algorithm 1 of SP 800-38D.
    ///
    /// It shifts right and folds with R = 0xe1 || 0^120.
    fn gcm_mul_reference(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
        let x = u128::from_be_bytes(*x);
        let mut v = u128::from_be_bytes(*y);
        let mut z = 0_u128;
        for i in 0..128 {
            if (x >> (127 - i)) & 1 == 1 {
                z ^= v;
            }
            let carry = v & 1;
            v >>= 1;
            if carry == 1 {
                v ^= 0xe1 << 120;
            }
        }
        z.to_be_bytes()
    }

    #[test]
    fn sp_800_38d_ghash_example() {
        // GCM test case 2 of McGrew and Viega: one ciphertext block, then the lengths.
        // The hash key is H = AES_0(0).
        let h = 0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2e_u128.to_be_bytes();
        let ciphertext = 0x0388_dace_60b6_a392_f328_c2b9_71b2_fe78_u128.to_be_bytes();
        let lengths = 0x0000_0000_0000_0000_0000_0000_0000_0080_u128.to_be_bytes();
        for hardware in [false, Ghash::hardware_available()] {
            let mut ghash = Ghash::with_path(&h, hardware);
            ghash.update_blocks(&[ciphertext, lengths]);
            assert_eq!(
                ghash.finalize(),
                0xf38c_bb1a_d692_23dc_c345_7ae5_b6b0_f885_u128.to_be_bytes()
            );
        }
    }

    proptest! {
        #[test]
        fn carry_less_product_matches_the_definition(a in any::<u128>(), b in any::<u128>()) {
            // The masked-integer Karatsuba product equals bit-by-bit shift and XOR.
            prop_assert_eq!(clmul_128(a, b), clmul_reference(a, b));
        }

        #[test]
        fn field_product_matches_the_specification(x in any::<[u8; 16]>(), y in any::<[u8; 16]>()) {
            // Reversing, multiplying, and reducing equals SP 800-38D's own algorithm.
            let product = Ghash::mul(Ghash::to_natural(&x), Ghash::to_natural(&y));
            prop_assert_eq!(product.reverse_bits().to_be_bytes(), gcm_mul_reference(&x, &y));
        }

        #[test]
        fn hardware_path_matches_the_portable_path(
            h in any::<[u8; 16]>(),
            data in prop::collection::vec(any::<u8>(), 0..300),
            split in any::<prop::sample::Index>(),
        ) {
            // Two uneven calls exercise the 4-block aggregation and its remainder.
            let at = split.index(data.len() + 1);
            let mut fast = Ghash::new(&h);
            fast.update_padded(&data[..at]);
            fast.update_padded(&data[at..]);
            let mut reference = Ghash::with_path(&h, false);
            reference.update_padded(&data[..at]);
            reference.update_padded(&data[at..]);
            prop_assert_eq!(fast.finalize(), reference.finalize());
        }
    }
}
