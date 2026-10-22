//! A cursor over received bytes, for headers, frames, and transport parameters.

use super::{DecodeError, VarInt};

/// Reads big-endian fields and varints off the front of a byte slice.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a> {
    /// The bytes not yet read.
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over the whole input.
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { rest: input }
    }

    /// Bytes left.
    pub(crate) const fn remaining(&self) -> usize {
        self.rest.len()
    }

    /// Whether every byte has been read.
    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The bytes left, without consuming them.
    pub(crate) const fn peek_rest(&self) -> &'a [u8] {
        self.rest
    }

    /// Takes a number of bytes.
    pub(crate) const fn bytes(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if self.rest.len() < len {
            return Err(DecodeError::Truncated {
                needed: len,
                available: self.rest.len(),
            });
        }
        let (taken, rest) = self.rest.split_at(len);
        self.rest = rest;
        Ok(taken)
    }

    /// Takes a fixed-size array.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    /// Takes one byte.
    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    /// Takes a big-endian 32-bit integer.
    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// Takes a varint.
    pub(crate) fn varint(&mut self) -> Result<VarInt, DecodeError> {
        VarInt::decode(&mut self.rest)
    }

    /// Takes a varint that counts bytes, checked against what is left.
    pub(crate) fn length(&mut self) -> Result<usize, DecodeError> {
        let len = self.varint()?.get();
        let available = self.rest.len();
        if len > available as u64 {
            return Err(DecodeError::Truncated {
                needed: usize::try_from(len).unwrap_or(usize::MAX),
                available,
            });
        }
        // Invariant: the length is at most the bytes left, so it fits a usize.
        Ok(len as usize)
    }

    /// Takes a varint length, then that many bytes.
    pub(crate) fn length_prefixed(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.length()?;
        self.bytes(len)
    }

    /// Takes everything left.
    pub(crate) const fn rest(&mut self) -> &'a [u8] {
        let rest = self.rest;
        self.rest = &[];
        rest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_in_order() {
        // One byte, a 32-bit integer, a varint 37, then a 2-byte prefixed field.
        let input = [0xaa, 0x00, 0x00, 0x00, 0x05, 0x25, 0x02, 0xbe, 0xef, 0x99];
        let mut reader = Reader::new(&input);
        assert_eq!(reader.u8(), Ok(0xaa));
        assert_eq!(reader.u32(), Ok(5));
        assert_eq!(reader.varint(), Ok(VarInt::from(37_u8)));
        assert_eq!(reader.length_prefixed(), Ok(&[0xbe, 0xef][..]));
        assert_eq!(reader.remaining(), 1);
        assert_eq!(reader.rest(), &[0x99]);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn length_beyond_input_is_refused() {
        // A prefix of 5 with only 2 bytes behind it.
        let mut reader = Reader::new(&[0x05, 0x01, 0x02]);
        assert_eq!(
            reader.length_prefixed(),
            Err(DecodeError::Truncated {
                needed: 5,
                available: 2
            })
        );
    }
}
