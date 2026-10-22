//! JSON numbers, kept as the text they were written with.

use std::{fmt, str::FromStr};

use thiserror::Error;

/// A JSON number, stored as its validated text.
///
/// The text always matches the grammar of RFC 8259 section 6.
/// Keeping text rather than a float preserves every digit of a large integer.
/// Two numbers are equal when their texts are equal, so `1.0` differs from `1`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Number(String);

impl Number {
    /// The number as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The value as an unsigned integer, when written as one and in range.
    ///
    /// A fraction or an exponent yields nothing, even when the value is whole.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        // The grammar already holds, so plain digits mean a non-negative integer.
        if self.0.bytes().all(|byte| byte.is_ascii_digit()) {
            // Out of range values, past 2^64 - 1, fail here.
            self.0.parse().ok()
        } else {
            None
        }
    }

    /// The value as a signed integer, when written as one and in range.
    ///
    /// A fraction or an exponent yields nothing, even when the value is whole.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        // Strip the optional sign, then require plain digits as for unsigned values.
        let digits = self.0.strip_prefix('-').unwrap_or(&self.0);
        if digits.bytes().all(|byte| byte.is_ascii_digit()) {
            // Out of range values, outside -2^63 to 2^63 - 1, fail here.
            self.0.parse().ok()
        } else {
            None
        }
    }

    /// The nearest double, when the value is finite as a double.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        // The JSON grammar is a subset of what the standard float parser reads.
        // An exponent like 1e400 parses to infinity, which is rejected.
        self.0.parse::<f64>().ok().filter(|value| value.is_finite())
    }

    /// Wraps text the caller has already checked against the grammar.
    pub(crate) const fn from_validated(text: String) -> Self {
        Self(text)
    }

    /// Scans one number starting at a position.
    ///
    /// Returns the position just past the number.
    /// On failure, returns the offset of the first byte that breaks the grammar.
    ///
    /// ```text
    ///     number = [ "-" ] int [ frac ] [ exp ]
    ///     int    = "0" / ( digit1-9 *digit )
    ///     frac   = "." 1*digit
    ///     exp    = ( "e" / "E" ) [ "-" / "+" ] 1*digit
    /// ```
    pub(crate) fn scan(bytes: &[u8], start: usize) -> Result<usize, usize> {
        let mut at = start;

        // Optional minus sign.
        // A plus sign is not part of the grammar.
        if bytes.get(at) == Some(&b'-') {
            at += 1;
        }

        // Integer part: a lone zero, or a nonzero digit and any digits after it.
        match bytes.get(at) {
            // "0" ends the integer part; "01" is rejected by the caller seeing a digit next.
            Some(b'0') => at += 1,
            Some(b'1'..=b'9') => at = skip_digits(bytes, at + 1),
            // "-", "-a", or "." with no digit before it.
            _ => return Err(at),
        }

        // Optional fraction: a dot and at least one digit.
        if bytes.get(at) == Some(&b'.') {
            let digits = at + 1;
            at = skip_digits(bytes, digits);
            // "1." has no digit after the dot.
            if at == digits {
                return Err(at);
            }
        }

        // Optional exponent: e or E, an optional sign, and at least one digit.
        if matches!(bytes.get(at), Some(b'e' | b'E')) {
            at += 1;
            if matches!(bytes.get(at), Some(b'+' | b'-')) {
                at += 1;
            }
            let digits = at;
            at = skip_digits(bytes, digits);
            // "1e" or "1e+" has no exponent digit.
            if at == digits {
                return Err(at);
            }
        }

        // A digit right after a lone zero means a leading zero, as in "012".
        if bytes.get(at).is_some_and(u8::is_ascii_digit) {
            return Err(at);
        }
        Ok(at)
    }
}

/// Advances past a run of ASCII digits.
fn skip_digits(bytes: &[u8], mut at: usize) -> usize {
    // Stop at the first non-digit or at the end of the input.
    while bytes.get(at).is_some_and(u8::is_ascii_digit) {
        at += 1;
    }
    at
}

impl FromStr for Number {
    type Err = NumberError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // The whole text must be one number, with nothing before or after it.
        match Self::scan(text.as_bytes(), 0) {
            Ok(end) if end == text.len() => Ok(Self(text.to_owned())),
            Ok(end) | Err(end) => Err(NumberError { offset: end }),
        }
    }
}

impl From<u64> for Number {
    fn from(value: u64) -> Self {
        // Decimal rendering of an integer always fits the grammar.
        Self(value.to_string())
    }
}

impl From<i64> for Number {
    fn from(value: i64) -> Self {
        // Decimal rendering of an integer, with a leading minus when negative.
        Self(value.to_string())
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A text that is not exactly one JSON number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("malformed number at byte {offset}")]
pub struct NumberError {
    /// Byte offset of the first byte that breaks the grammar.
    offset: usize,
}

impl NumberError {
    /// Byte offset of the first byte that breaks the grammar.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar_accepts_every_part() {
        // Each optional part of the grammar, alone and combined.
        for text in ["0", "-0", "7", "-12", "0.5", "1.25e3", "1E-2", "-0.0e+0"] {
            assert_eq!(text.parse::<Number>().map(|n| n.0), Ok(text.to_owned()));
        }
    }

    #[test]
    fn grammar_rejects_at_the_breaking_byte() {
        // Each case pairs a text with the offset of its first bad byte.
        //
        //     "01"   leading zero, the 1 at offset 1 breaks it
        //     "1."   no fraction digit, the end at offset 2
        //     "1e+"  no exponent digit, the end at offset 3
        //     "+1"   plus sign, offset 0
        //     "-"    no digit, the end at offset 1
        //     ".5"   no integer part, offset 0
        //     "1 "   trailing space, offset 1
        let cases = [
            ("01", 1),
            ("1.", 2),
            ("1e+", 3),
            ("+1", 0),
            ("-", 1),
            (".5", 0),
            ("1 ", 1),
        ];
        for (text, offset) in cases {
            assert_eq!(
                text.parse::<Number>(),
                Err(NumberError { offset }),
                "{text}"
            );
        }
    }

    #[test]
    fn integer_views_require_integer_text() {
        // 2^64 - 1 is the largest unsigned value; one more overflows.
        let max: Number = "18446744073709551615".parse().unwrap();
        let over: Number = "18446744073709551616".parse().unwrap();
        assert_eq!(max.as_u64(), Some(u64::MAX));
        assert_eq!(over.as_u64(), None);

        // -2^63 is the smallest signed value.
        let min: Number = "-9223372036854775808".parse().unwrap();
        assert_eq!(min.as_i64(), Some(i64::MIN));
        assert_eq!(min.as_u64(), None);

        // A whole value written with an exponent is not an integer view.
        let exponent: Number = "1e2".parse().unwrap();
        assert_eq!(exponent.as_u64(), None);
        assert_eq!(exponent.as_f64(), Some(100.0));
    }

    #[test]
    fn float_view_rejects_infinity() {
        // 1e400 is past the largest double, about 1.8e308.
        let huge: Number = "1e400".parse().unwrap();
        assert_eq!(huge.as_f64(), None);
    }
}
