//! UUIDs, which name keystores.

use std::{fmt, io, str::FromStr};

use crate::keys::{OsEntropy, UuidError};

/// A 128-bit UUID, written in the 8-4-4-4-12 hex form of RFC 9562, section 4.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uuid([u8; 16]);

impl Uuid {
    /// Characters in the text form: 32 digits and 4 hyphens.
    const TEXT_LEN: usize = 36;

    /// Byte offsets of the hyphens in the text form.
    const HYPHENS: [usize; 4] = [8, 13, 18, 23];

    /// A version 4 UUID from 16 random bytes, per RFC 9562, section 5.4.
    ///
    /// Six bits are fixed: the version 0b0100 and the variant 0b10.
    /// The other 122 bits are the caller's.
    #[must_use]
    pub const fn from_random_bytes(mut bytes: [u8; 16]) -> Self {
        // Version: the high nibble of byte 6.
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        // Variant: the two high bits of byte 8.
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self(bytes)
    }

    /// A fresh version 4 UUID from the operating system's entropy.
    ///
    /// # Errors
    ///
    /// Fails when the entropy source cannot be read.
    pub fn random() -> io::Result<Self> {
        Ok(Self::from_random_bytes(OsEntropy::array()?))
    }

    /// The 16 bytes, in the order the text form writes them.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for Uuid {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl FromStr for Uuid {
    type Err = UuidError;

    /// Parses the 8-4-4-4-12 form, in either case.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = text.as_bytes();
        if bytes.len() != Self::TEXT_LEN {
            return Err(UuidError::Length {
                expected: Self::TEXT_LEN,
                actual: bytes.len(),
            });
        }
        if let Some(&offset) = Self::HYPHENS.iter().find(|&&offset| bytes[offset] != b'-') {
            return Err(UuidError::Hyphen { offset });
        }

        // The 32 digits, with the offset each sits at in the text.
        let mut digits = (0..Self::TEXT_LEN).filter(|offset| !Self::HYPHENS.contains(offset));
        let mut out = [0; 16];
        for byte in &mut out {
            for _ in 0..2 {
                // Invariant: 36 offsets minus 4 hyphens leave exactly 32 digits.
                let offset = digits.next().expect("32 digit positions");
                let value = char::from(bytes[offset])
                    .to_digit(16)
                    .ok_or(UuidError::Digit { offset })?;
                // Invariant: a hex digit is below 16, so it fits the low nibble.
                *byte = (*byte << 4) | value as u8;
            }
        }
        Ok(Self(out))
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Groups of 4, 2, 2, 2, and 6 bytes.
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_eip_keystore_uuid_round_trips() {
        // The uuid of the EIP-2335 scrypt vector, a version 4 UUID.
        let text = "1d85ae20-35c5-4611-98e8-aa14a633906f";
        let uuid: Uuid = text.parse().unwrap();
        assert_eq!(
            *uuid.as_bytes(),
            [
                0x1d, 0x85, 0xae, 0x20, 0x35, 0xc5, 0x46, 0x11, 0x98, 0xe8, 0xaa, 0x14, 0xa6, 0x33,
                0x90, 0x6f
            ]
        );
        assert_eq!(uuid.to_string(), text);

        // Uppercase parses to the same value, and prints back in lowercase.
        assert_eq!(text.to_uppercase().parse(), Ok(uuid));
    }

    #[test]
    fn random_bytes_get_the_version_and_variant() {
        // All ones: the version nibble becomes 4, the variant bits 0b10.
        let uuid = Uuid::from_random_bytes([0xff; 16]);
        assert_eq!(uuid.to_string(), "ffffffff-ffff-4fff-bfff-ffffffffffff");
        // All zeros: only the fixed bits are set.
        let uuid = Uuid::from_random_bytes([0; 16]);
        assert_eq!(uuid.to_string(), "00000000-0000-4000-8000-000000000000");
    }

    #[test]
    fn malformed_text_is_refused_where_it_breaks() {
        assert_eq!(
            "1d85ae20-35c5-4611-98e8".parse::<Uuid>(),
            Err(UuidError::Length {
                expected: 36,
                actual: 23
            })
        );
        // The third hyphen, at offset 18, is a digit instead.
        assert_eq!(
            "1d85ae20-35c5-4611898e8-aa14a633906f".parse::<Uuid>(),
            Err(UuidError::Hyphen { offset: 18 })
        );
        // A g at offset 35, the last digit.
        assert_eq!(
            "1d85ae20-35c5-4611-98e8-aa14a633906g".parse::<Uuid>(),
            Err(UuidError::Digit { offset: 35 })
        );
    }
}
