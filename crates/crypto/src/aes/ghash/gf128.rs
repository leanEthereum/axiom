//! The GHASH field GF(2^128) = GF(2)[x] / (x^128 + x^7 + x^2 + x + 1), per NIST SP 800-38D, section 6.3.
//!
//! Its constant-time product is the portable reference of every carry-less multiplier.

use std::ops::{BitXor, Mul};

use super::BLOCK_LEN;

/// An element of the GHASH field in the natural bit order: bit i is the coefficient of x^i.
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Gf128(u128);

impl Gf128 {
    /// The additive identity.
    pub(super) const ZERO: Self = Self(0);

    /// The element a GCM block encodes.
    pub(super) const fn from_block(block: &[u8; BLOCK_LEN]) -> Self {
        // The first byte's top bit is x^0.
        // As a big-endian integer it is bit 127, so reverse.
        Self::from_bits(u128::from_be_bytes(*block).reverse_bits())
    }

    /// The GCM block that encodes the element.
    pub(super) const fn to_block(self) -> [u8; BLOCK_LEN] {
        // Reversing all 128 bits undoes the entry conversion.
        self.to_bits().reverse_bits().to_be_bytes()
    }

    /// The element whose coefficients are the bits of the integer.
    pub(super) const fn from_bits(bits: u128) -> Self {
        Self(bits)
    }

    /// The coefficients of the element as the bits of an integer.
    pub(super) const fn to_bits(self) -> u128 {
        self.0
    }
}

impl BitXor for Gf128 {
    type Output = Self;

    /// Field addition, which is XOR in characteristic 2.
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Mul for Gf128 {
    type Output = Self;

    /// The field product, in constant time.
    fn mul(self, rhs: Self) -> Self {
        // A 256-bit carry-less product, then reduction modulo the GCM polynomial.
        Self(WideProduct::new(self.0, rhs.0).reduce())
    }
}

/// The unreduced 256-bit carry-less product of two 128-bit polynomials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WideProduct {
    /// The coefficients of x^128 to x^255.
    high: u128,
    /// The coefficients of x^0 to x^127.
    low: u128,
}

impl WideProduct {
    /// The product of two polynomials, by Karatsuba.
    ///
    /// ```text
    /// a b = a1 b1 x^128 + ((a0 + a1)(b0 + b1) + a0 b0 + a1 b1) x^64 + a0 b0
    /// ```
    fn new(a: u128, b: u128) -> Self {
        // Split both operands into 64-bit halves: three half products replace four.
        let (a0, a1) = (a as u64, (a >> 64) as u64);
        let (b0, b1) = (b as u64, (b >> 64) as u64);
        let low = Self::clmul_64(a0, b0);
        let high = Self::clmul_64(a1, b1);
        let middle = Self::clmul_64(a0 ^ a1, b0 ^ b1) ^ low ^ high;
        Self {
            high: high ^ (middle >> 64),
            low: low ^ (middle << 64),
        }
    }

    /// Reduces the product modulo x^128 + x^7 + x^2 + x + 1.
    ///
    /// ```text
    /// high x^128 = high (x^7 + x^2 + x + 1)
    /// ```
    ///
    /// The shifts push up to 7 bits past bit 127, and those fold back once more.
    const fn reduce(self) -> u128 {
        let Self { high, low } = self;
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
    /// The method is due to Thomas Pornin, from his 2017 notes on constant-time GHASH.
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
        let z0 =
            x0.wrapping_mul(y0) ^ x1.wrapping_mul(y3) ^ x2.wrapping_mul(y2) ^ x3.wrapping_mul(y1);
        let z1 =
            x0.wrapping_mul(y1) ^ x1.wrapping_mul(y0) ^ x2.wrapping_mul(y3) ^ x3.wrapping_mul(y2);
        let z2 =
            x0.wrapping_mul(y2) ^ x1.wrapping_mul(y1) ^ x2.wrapping_mul(y0) ^ x3.wrapping_mul(y3);
        let z3 =
            x0.wrapping_mul(y3) ^ x1.wrapping_mul(y2) ^ x2.wrapping_mul(y1) ^ x3.wrapping_mul(y0);
        (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
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
        let low = Self::clmul_64_low(a, b);
        let high = Self::clmul_64_low(a.reverse_bits(), b.reverse_bits()).reverse_bits() >> 1;
        (u128::from(high) << 64) | u128::from(low)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// The carry-less product bit by bit, the textbook definition.
    fn clmul_reference(a: u128, b: u128) -> WideProduct {
        let (mut high, mut low) = (0_u128, 0_u128);
        for i in 0..128 {
            if (b >> i) & 1 == 1 {
                low ^= a << i;
                if i > 0 {
                    high ^= a >> (128 - i);
                }
            }
        }
        WideProduct { high, low }
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

    proptest! {
        #[test]
        fn carry_less_product_matches_the_definition(a in any::<u128>(), b in any::<u128>()) {
            // The masked-integer Karatsuba product equals bit-by-bit shift and XOR.
            prop_assert_eq!(WideProduct::new(a, b), clmul_reference(a, b));
        }

        #[test]
        fn field_product_matches_the_specification(x in any::<[u8; 16]>(), y in any::<[u8; 16]>()) {
            // Reversing, multiplying, and reducing equals SP 800-38D's own algorithm.
            let product = Gf128::from_block(&x) * Gf128::from_block(&y);
            prop_assert_eq!(product.to_block(), gcm_mul_reference(&x, &y));
        }
    }
}
