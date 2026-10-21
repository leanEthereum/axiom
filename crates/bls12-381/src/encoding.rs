//! The three flag bits of the ZCash point encoding, shared by G1 and G2.
//!
//! The field modulus has 381 bits, so the top three bits of a big-endian coordinate are free.
//! The encoding stores metadata there, in the first byte:
//!
//! ```text
//!     bit 7  compression  set for the compressed form (x only), clear for x || y
//!     bit 6  infinity     set only for the point at infinity
//!     bit 5  sort         compressed form only: set when y is the larger of +-y
//! ```
//!
//! The format is specified in the ZCash protocol, appendix "BLS12-381 encoding".

use crate::PointDecodeError;

/// The three metadata bits carried by the first byte of an encoded point.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Flags {
    /// Whether the encoding holds only the x-coordinate.
    pub(crate) compression: bool,
    /// Whether the encoding is the point at infinity.
    pub(crate) infinity: bool,
    /// Whether y is the lexicographically largest of the two candidate roots.
    pub(crate) sort: bool,
}

impl Flags {
    /// Mask of the compression bit.
    const COMPRESSION: u8 = 0x80;
    /// Mask of the infinity bit.
    const INFINITY: u8 = 0x40;
    /// Mask of the sort bit.
    const SORT: u8 = 0x20;

    /// Reads the flags from the first byte and clears them, leaving only coordinate bits.
    pub(crate) const fn take(bytes: &mut [u8]) -> Self {
        let first = bytes[0];
        bytes[0] &= !(Self::COMPRESSION | Self::INFINITY | Self::SORT);
        Self {
            compression: first & Self::COMPRESSION != 0,
            infinity: first & Self::INFINITY != 0,
            sort: first & Self::SORT != 0,
        }
    }

    /// Writes the flags into the first byte, which must have its top three bits clear.
    pub(crate) const fn put(self, bytes: &mut [u8]) {
        if self.compression {
            bytes[0] |= Self::COMPRESSION;
        }
        if self.infinity {
            bytes[0] |= Self::INFINITY;
        }
        if self.sort {
            bytes[0] |= Self::SORT;
        }
    }

    /// Checks the flags against the expected form and the remaining payload bits.
    ///
    /// # Returns
    ///
    /// Whether the encoding is a valid encoding of the point at infinity.
    pub(crate) fn validate(
        self,
        compressed: bool,
        payload: &[u8],
    ) -> Result<bool, PointDecodeError> {
        // The form is fixed by the length, so the flag must agree with it.
        if self.compression != compressed {
            return Err(PointDecodeError::InvalidCompressionFlag);
        }
        // Only the compressed form needs a sign; uncompressed carries y itself.
        if !compressed && self.sort {
            return Err(PointDecodeError::UnexpectedSortFlag);
        }
        if self.infinity {
            // Infinity has no coordinates and no sign: every other bit must be zero.
            if self.sort || payload.iter().any(|byte| *byte != 0) {
                return Err(PointDecodeError::InvalidInfinityEncoding);
            }
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_splits_flags_from_coordinate_bits() {
        // 0xbf = 1011_1111: compression and sort set, infinity clear, coordinate bits 0x1f.
        let mut bytes = [0xbf, 0x01];
        let flags = Flags::take(&mut bytes);
        assert_eq!(
            flags,
            Flags {
                compression: true,
                infinity: false,
                sort: true
            }
        );
        assert_eq!(bytes, [0x1f, 0x01]);

        // Writing the flags back restores the original byte.
        flags.put(&mut bytes);
        assert_eq!(bytes, [0xbf, 0x01]);
    }

    #[test]
    fn infinity_rejects_any_other_bit() {
        let flags = Flags {
            compression: true,
            infinity: true,
            sort: false,
        };
        // A clean payload decodes as infinity.
        assert_eq!(flags.validate(true, &[0, 0]), Ok(true));
        // A single stray bit makes it invalid.
        assert_eq!(
            flags.validate(true, &[0, 1]),
            Err(PointDecodeError::InvalidInfinityEncoding)
        );
    }

    #[test]
    fn form_must_match_compression_flag() {
        // An uncompressed-length input claiming compression is rejected first.
        let flags = Flags {
            compression: true,
            ..Flags::default()
        };
        assert_eq!(
            flags.validate(false, &[0]),
            Err(PointDecodeError::InvalidCompressionFlag)
        );
    }
}
