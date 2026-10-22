//! Canonical decimal strings, the beacon API's form of every unsigned integer.
//!
//! See `Uint64` and `Uint256` in `types/primitive.yaml` of `ethereum/beacon-APIs`.
//!
//! ```text
//!     "0", "1024"      accepted
//!     ""               rejected     no digit
//!     "+1", "1.0"      rejected     only digits
//!     "007"            rejected     leading zero
//! ```

use std::fmt::Write;

use axiom_ssz::U256;
use thiserror::Error;

/// Most digits a 64-bit value can need, the 20 of 18446744073709551615.
const U64_DIGITS: usize = 20;

/// Most digits a 256-bit value can need, the 78 of 2^256 - 1.
const U256_DIGITS: usize = 78;

/// The largest 64-bit value, as the error message prints it.
const U64_MAX: &str = "18446744073709551615";

/// The largest 256-bit value, as the error message prints it.
const U256_MAX: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129639935";

/// A string that is not a canonical decimal of the expected width.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DecimalError {
    /// The string has no digit.
    #[error("decimal string is empty")]
    Empty,

    /// A byte that is not a decimal digit, such as a sign, a dot, or a space.
    #[error("invalid decimal digit at byte {offset}")]
    InvalidDigit {
        /// Byte offset of the offending character.
        offset: usize,
    },

    /// A zero before the first significant digit, which would give a value two spellings.
    #[error("decimal string has a leading zero")]
    LeadingZero,

    /// The value exceeds the range of its integer type.
    #[error("decimal of {digits} digits exceeds the maximum {max}")]
    Overflow {
        /// Number of digits in the string.
        digits: usize,
        /// The largest value the type holds.
        max: &'static str,
    },
}

/// The digits of a canonical decimal string, checked but not yet converted.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Decimal<'a>(&'a str);

impl<'a> Decimal<'a> {
    /// Checks the grammar: one or more digits, and no leading zero unless the value is zero.
    pub(crate) fn parse(text: &'a str) -> Result<Self, DecimalError> {
        let bytes = text.as_bytes();
        if bytes.is_empty() {
            return Err(DecimalError::Empty);
        }
        if let Some(offset) = bytes.iter().position(|byte| !byte.is_ascii_digit()) {
            return Err(DecimalError::InvalidDigit { offset });
        }
        // "0" is zero's only spelling, so a zero may lead only when it stands alone.
        if bytes.len() > 1 && bytes[0] == b'0' {
            return Err(DecimalError::LeadingZero);
        }
        Ok(Self(text))
    }

    /// The value as a 64-bit integer.
    pub(crate) fn to_u64(self) -> Result<u64, DecimalError> {
        let overflow = DecimalError::Overflow {
            digits: self.0.len(),
            max: U64_MAX,
        };
        // A string longer than the widest value overflows without a single multiplication.
        if self.0.len() > U64_DIGITS {
            return Err(overflow);
        }
        self.0.bytes().try_fold(0_u64, |value, digit| {
            value
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(digit - b'0')))
                .ok_or(overflow)
        })
    }

    /// The value as a 256-bit integer.
    pub(crate) fn to_u256(self) -> Result<U256, DecimalError> {
        let overflow = DecimalError::Overflow {
            digits: self.0.len(),
            max: U256_MAX,
        };
        // The conversion costs 32 byte steps per digit.
        // Bounding the digit count first keeps a megabyte of digits from costing that much.
        if self.0.len() > U256_DIGITS {
            return Err(overflow);
        }
        // The grammar holds, so the only failure left is a value of 2^256 or more.
        U256::from_decimal(self.0).ok_or(overflow)
    }

    /// The decimal text of a 256-bit integer.
    ///
    /// # Algorithm
    ///
    /// Long division of the four 64-bit limbs by 10^19, the largest power of ten below 2^64.
    /// Each division yields 19 digits, so four or five rounds print any value.
    ///
    /// Every intermediate stays in range:
    ///
    /// ```text
    ///     remainder < 10^19 < 2^64
    ///     remainder * 2^64 + limb < 2^128
    /// ```
    pub(crate) fn render_u256(value: U256) -> String {
        /// The largest power of ten that fits a limb.
        const CHUNK: u128 = 10_000_000_000_000_000_000;

        // Little-endian limbs, the order the bytes are stored in.
        let (words, _) = value.0.as_chunks::<8>();
        let mut limbs = [0_u64; 4];
        for (limb, word) in limbs.iter_mut().zip(words) {
            *limb = u64::from_le_bytes(*word);
        }

        // Peel 19 digits at a time off the low end, until the quotient is zero.
        let mut chunks = Vec::new();
        loop {
            let mut remainder = 0_u128;
            for limb in limbs.iter_mut().rev() {
                let current = (remainder << 64) | u128::from(*limb);
                *limb = (current / CHUNK) as u64;
                remainder = current % CHUNK;
            }
            chunks.push(remainder as u64);
            if limbs.iter().all(|limb| *limb == 0) {
                break;
            }
        }

        // The most significant chunk prints bare, every later one padded to 19 digits.
        let mut chunks = chunks.into_iter().rev();
        let mut out = chunks.next().unwrap_or_default().to_string();
        for chunk in chunks {
            // Writing into a string cannot fail.
            let _ = write!(out, "{chunk:019}");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn grammar_accepts_canonical_decimals() {
        // Zero, a single digit, and a multi-digit value with an inner zero.
        assert_eq!(Decimal::parse("0").and_then(Decimal::to_u64), Ok(0));
        assert_eq!(Decimal::parse("7").and_then(Decimal::to_u64), Ok(7));
        assert_eq!(Decimal::parse("1024").and_then(Decimal::to_u64), Ok(1024));
    }

    #[test]
    fn grammar_rejects_every_malformed_form() {
        // Each case pairs a text with the rule it breaks.
        //
        //     ""       no digit
        //     "+1"     a sign at byte 0
        //     "-1"     a sign at byte 0
        //     "1.0"    a dot at byte 1
        //     "1e3"    an exponent marker at byte 1
        //     " 1"     a space at byte 0
        //     "0x10"   a hex prefix, the x at byte 1
        //     "00"     a leading zero
        //     "0012"   a leading zero
        let cases = [
            ("", DecimalError::Empty),
            ("+1", DecimalError::InvalidDigit { offset: 0 }),
            ("-1", DecimalError::InvalidDigit { offset: 0 }),
            ("1.0", DecimalError::InvalidDigit { offset: 1 }),
            ("1e3", DecimalError::InvalidDigit { offset: 1 }),
            (" 1", DecimalError::InvalidDigit { offset: 0 }),
            ("0x10", DecimalError::InvalidDigit { offset: 1 }),
            ("00", DecimalError::LeadingZero),
            ("0012", DecimalError::LeadingZero),
        ];
        for (text, error) in cases {
            assert_eq!(Decimal::parse(text).map(|_| ()), Err(error), "{text:?}");
        }
    }

    #[test]
    fn u64_range_ends_at_its_maximum() {
        // 2^64 - 1 is the largest value; 2^64 has the same 20 digits and overflows.
        assert_eq!(
            Decimal::parse(U64_MAX).and_then(Decimal::to_u64),
            Ok(u64::MAX)
        );
        assert_eq!(
            Decimal::parse("18446744073709551616").and_then(Decimal::to_u64),
            Err(DecimalError::Overflow {
                digits: 20,
                max: U64_MAX
            })
        );

        // 21 digits overflow before any arithmetic.
        assert_eq!(
            Decimal::parse("100000000000000000000").and_then(Decimal::to_u64),
            Err(DecimalError::Overflow {
                digits: 21,
                max: U64_MAX
            })
        );
    }

    #[test]
    fn u256_range_ends_at_its_maximum() {
        // 2^256 - 1 prints as its 78 digits and reads back.
        assert_eq!(Decimal::render_u256(U256::MAX), U256_MAX);
        assert_eq!(
            Decimal::parse(U256_MAX).and_then(Decimal::to_u256),
            Ok(U256::MAX)
        );

        // 2^256 has the same 78 digits and overflows.
        let two_to_256 =
            "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert_eq!(
            Decimal::parse(two_to_256).and_then(Decimal::to_u256),
            Err(DecimalError::Overflow {
                digits: 78,
                max: U256_MAX
            })
        );

        // A 79-digit string overflows without a conversion.
        let long = "1".repeat(79);
        assert_eq!(
            Decimal::parse(&long).and_then(Decimal::to_u256),
            Err(DecimalError::Overflow {
                digits: 79,
                max: U256_MAX
            })
        );
    }

    #[test]
    fn u256_renders_across_chunk_boundaries() {
        // Zero is a single digit.
        assert_eq!(Decimal::render_u256(U256::ZERO), "0");

        // 10^19 is the first value of two chunks, so the low chunk prints as 19 zeros.
        let ten_pow_19 = U256::from_u128(10_000_000_000_000_000_000);
        assert_eq!(Decimal::render_u256(ten_pow_19), "10000000000000000000");

        // 2^128 spans three limbs' worth of digits.
        let mut two_to_128 = U256::ZERO;
        two_to_128.0[16] = 1;
        assert_eq!(
            Decimal::render_u256(two_to_128),
            "340282366920938463463374607431768211456"
        );
    }

    proptest! {
        #[test]
        fn u64_matches_the_standard_rendering(value in any::<u64>()) {
            // The standard library prints the canonical form, which reads back.
            let text = value.to_string();
            prop_assert_eq!(Decimal::parse(&text).and_then(Decimal::to_u64), Ok(value));
        }

        #[test]
        fn u256_round_trips(bytes in any::<[u8; 32]>()) {
            // Any 256-bit value prints canonically and reads back.
            let value = U256(bytes);
            let text = Decimal::render_u256(value);
            prop_assert_eq!(Decimal::parse(&text).and_then(Decimal::to_u256), Ok(value));
        }

        #[test]
        fn u256_agrees_with_u128_below_2_128(value in any::<u128>()) {
            // The reference: the standard rendering of the same value as a u128.
            prop_assert_eq!(Decimal::render_u256(U256::from_u128(value)), value.to_string());
        }
    }
}
