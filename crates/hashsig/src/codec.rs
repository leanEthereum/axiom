//! The byte layout of keys and signatures: SSZ containers of little-endian words.
//!
//! # Overview
//!
//! A field element is its canonical value as four little-endian bytes.
//! A variable field of a container is a four-byte offset in the fixed part, its bytes after it.
//! Decoding is strict: offsets must be exact, lengths whole, and elements canonical.
//! So every value has exactly one encoding, and a signature cannot be mangled into another.

use crate::{error::DecodeError, field::KoalaBear, words::Words};

/// Bytes of one encoded field element.
pub(crate) const ELEMENT_BYTES: usize = 4;

/// Bytes of an SSZ offset.
pub(crate) const OFFSET_BYTES: usize = 4;

/// Appends encodings to a byte buffer.
#[derive(Debug, Default)]
pub(crate) struct Writer {
    /// The bytes written so far.
    bytes: Vec<u8>,
}

impl Writer {
    /// A writer with room for a known length.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Appends a 32-bit word, little-endian.
    pub(crate) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a 64-bit word, little-endian.
    pub(crate) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends an SSZ offset.
    pub(crate) fn offset(&mut self, offset: usize) {
        // Invariant: encodings stay far below 4 GiB, the largest key being a few hundred MiB.
        self.u32(offset as u32);
    }

    /// Appends raw bytes.
    pub(crate) fn bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// Appends field elements as canonical words.
    pub(crate) fn elements(&mut self, elements: &[KoalaBear]) {
        for element in elements {
            self.u32(element.to_canonical());
        }
    }

    /// Appends a list of words, one after the other.
    pub(crate) fn words<const CAP: usize>(&mut self, list: &[Words<CAP>]) {
        for words in list {
            self.elements(words.elements());
        }
    }

    /// The bytes written.
    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// A cursor over bytes being decoded.
#[derive(Debug)]
pub(crate) struct Reader<'a> {
    /// The bytes not yet read.
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over a whole encoding.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// Bytes not yet read.
    pub(crate) const fn remaining(&self) -> usize {
        self.rest.len()
    }

    /// Takes the next bytes.
    pub(crate) const fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
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
        let bytes = self.take(N)?;
        let mut array = [0; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    /// Reads a 32-bit little-endian word.
    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        self.array().map(u32::from_le_bytes)
    }

    /// Reads a 64-bit little-endian word.
    pub(crate) fn u64(&mut self) -> Result<u64, DecodeError> {
        self.array().map(u64::from_le_bytes)
    }

    /// Reads an offset and checks it points where the variable part starts.
    pub(crate) fn offset(&mut self, expected: usize) -> Result<(), DecodeError> {
        let actual = self.u32()? as usize;
        if actual != expected {
            return Err(DecodeError::Offset { expected, actual });
        }
        Ok(())
    }

    /// Reads one canonical field element.
    pub(crate) fn element(&mut self) -> Result<KoalaBear, DecodeError> {
        let value = self.u32()?;
        KoalaBear::from_canonical(value).ok_or(DecodeError::NonCanonical { value })
    }

    /// Reads words of a known length.
    pub(crate) fn words<const CAP: usize>(
        &mut self,
        len: usize,
    ) -> Result<Words<CAP>, DecodeError> {
        let mut elements = [KoalaBear::ZERO; CAP];
        for element in &mut elements[..len] {
            *element = self.element()?;
        }
        Ok(Words::from_slice(&elements[..len]))
    }

    /// Reads a list of words that runs to the end, refusing a partial last item.
    pub(crate) fn words_to_end<const CAP: usize>(
        &mut self,
        len: usize,
    ) -> Result<Vec<Words<CAP>>, DecodeError> {
        let item = len * ELEMENT_BYTES;
        if !self.rest.len().is_multiple_of(item) {
            return Err(DecodeError::PartialItem {
                len: self.rest.len(),
                item,
            });
        }
        let count = self.rest.len() / item;
        (0..count).map(|_| self.words(len)).collect()
    }

    /// Checks every byte was read.
    pub(crate) const fn finish(self) -> Result<(), DecodeError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Trailing {
                bytes: self.rest.len(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_round_trip_and_refuse_non_canonical_words() {
        // Fixture state: the elements 0, 1 and p - 1, then the word p.
        let p = KoalaBear::ORDER;
        let mut writer = Writer::default();
        writer.elements(&[KoalaBear::new(0), KoalaBear::new(1), KoalaBear::new(p - 1)]);
        writer.u32(p);
        let bytes = writer.finish();
        assert_eq!(&bytes[4..8], &[1, 0, 0, 0]);

        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.element(), Ok(KoalaBear::new(0)));
        assert_eq!(reader.element(), Ok(KoalaBear::new(1)));
        assert_eq!(reader.element(), Ok(KoalaBear::new(p - 1)));
        assert_eq!(
            reader.element(),
            Err(DecodeError::NonCanonical { value: p })
        );
    }

    #[test]
    fn short_input_and_trailing_bytes_are_refused() {
        // Three bytes cannot hold a word; one unread byte fails the finish.
        assert_eq!(
            Reader::new(&[1, 2, 3]).u32(),
            Err(DecodeError::Truncated {
                needed: 4,
                available: 3
            })
        );
        let mut reader = Reader::new(&[0; 5]);
        reader.u32().unwrap();
        assert_eq!(reader.finish(), Err(DecodeError::Trailing { bytes: 1 }));
    }

    #[test]
    fn a_list_must_hold_whole_items() {
        // Fixture state: 10 bytes against 2-element items of 8 bytes.
        let mut reader = Reader::new(&[0; 10]);
        assert_eq!(
            reader.words_to_end::<8>(2),
            Err(DecodeError::PartialItem { len: 10, item: 8 })
        );
    }

    #[test]
    fn offsets_must_be_exact() {
        let mut reader = Reader::new(&[12, 0, 0, 0]);
        assert_eq!(
            reader.offset(8),
            Err(DecodeError::Offset {
                expected: 8,
                actual: 12
            })
        );
    }
}
