//! A buffer that appends RLP items, nesting lists through closures.

use crate::header::Header;

/// Appends canonical RLP items to a growing buffer.
///
/// # Overview
///
/// Strings and integers append directly.
/// A list runs a closure that appends its items, then gains its header in front.
/// Closures keep every list balanced by construction.
///
/// # Examples
///
/// ```
/// use axiom_rlp::Encoder;
///
/// // The Yellow Paper example: [ [], [[]], [ [], [[]] ] ].
/// let mut encoder = Encoder::new();
/// let empty = |_: &mut Encoder| {};
/// let wrapped_empty = |list: &mut Encoder| {
///     list.list(empty);
/// };
/// encoder.list(|outer| {
///     outer.list(empty).list(wrapped_empty).list(|inner| {
///         inner.list(empty).list(wrapped_empty);
///     });
/// });
/// assert_eq!(
///     encoder.finish(),
///     [0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]
/// );
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Encoder {
    /// The encoding so far.
    out: Vec<u8>,
}

impl Encoder {
    /// An empty encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { out: Vec::new() }
    }

    /// Appends a byte string.
    pub fn bytes(&mut self, payload: &[u8]) -> &mut Self {
        // A lone byte below 0x80 is its own encoding.
        if let [byte] = payload
            && *byte < 0x80
        {
            self.out.push(*byte);
            return self;
        }
        // Otherwise a string header, then the payload.
        Header::string(payload.len()).encode_to(&mut self.out);
        self.out.extend_from_slice(payload);
        self
    }

    /// Appends an unsigned integer as minimal big-endian bytes.
    ///
    /// Zero is the empty string, `0x80`.
    pub fn uint(&mut self, value: u64) -> &mut Self {
        // Strip the leading zero bytes, which canonical integers never carry.
        let bytes = value.to_be_bytes();
        let skip = value.leading_zeros() as usize / 8;
        self.bytes(&bytes[skip..])
    }

    /// Appends a list whose items the closure appends.
    pub fn list(&mut self, items: impl FnOnce(&mut Self)) -> &mut Self {
        // Phase 1: append the items where the list starts.
        let start = self.out.len();
        items(self);
        // Phase 2: the payload length is now known, so the header goes in front.
        let header = Header::list(self.out.len() - start);
        let mut prefix = Vec::with_capacity(header.encoded_len());
        header.encode_to(&mut prefix);
        self.out.splice(start..start, prefix);
        self
    }

    /// Appends an item that is already encoded.
    ///
    /// The caller vouches that the bytes are one canonical item.
    pub fn raw(&mut self, item: &[u8]) -> &mut Self {
        // No header: the bytes carry their own.
        self.out.extend_from_slice(item);
        self
    }

    /// Bytes encoded so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.out.len()
    }

    /// Whether nothing is encoded yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// The finished encoding.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::Decoder;

    fn encode_uint(value: u64) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.uint(value);
        encoder.finish()
    }

    #[test]
    fn integers_are_minimal_big_endian() {
        // 0 is the empty string, 0x80.
        assert_eq!(encode_uint(0), [0x80]);
        // 127 stands alone as 0x7f.
        assert_eq!(encode_uint(127), [0x7f]);
        // 128 needs a header: 0x81 0x80.
        assert_eq!(encode_uint(128), [0x81, 0x80]);
        // 1000 is 0x03e8 behind 0x82.
        assert_eq!(encode_uint(1000), [0x82, 0x03, 0xe8]);
        // The largest 64-bit value takes eight bytes behind 0x88.
        let mut expected = vec![0x88];
        expected.extend_from_slice(&[0xff; 8]);
        assert_eq!(encode_uint(u64::MAX), expected);
    }

    #[test]
    fn lists_gain_long_headers_past_fifty_five_bytes() {
        // Four 13-byte strings encode to 14 bytes each, a 56-byte payload.
        let mut encoder = Encoder::new();
        encoder.list(|list| {
            for _ in 0..4 {
                list.bytes(&[0xaa; 13]);
            }
        });
        let encoded = encoder.finish();
        // 0xf8 0x38 says one length byte follows, holding 56.
        assert_eq!(encoded[..2], [0xf8, 56]);
        assert_eq!(encoded.len(), 2 + 56);
    }

    #[test]
    fn raw_items_pass_through() {
        // A pre-encoded string sits beside a fresh one.
        let mut encoder = Encoder::new();
        encoder.list(|list| {
            list.raw(&[0x83, b'd', b'o', b'g']).bytes(b"god");
        });
        assert_eq!(encoder.len(), 9);
        assert_eq!(
            encoder.finish(),
            [0xc8, 0x83, b'd', b'o', b'g', 0x83, b'g', b'o', b'd']
        );
    }

    proptest! {
        #[test]
        fn integers_round_trip(value in any::<u64>()) {
            // The minimal big-endian form decodes back to the value.
            let mut encoder = Encoder::new();
            encoder.uint(value);
            let encoded = encoder.finish();
            let mut decoder = Decoder::new(&encoded);
            prop_assert_eq!(decoder.uint(), Ok(value));
            prop_assert!(decoder.finish().is_ok());
        }
    }
}
