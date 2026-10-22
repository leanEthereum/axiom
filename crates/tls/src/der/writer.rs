//! Writing DER values in their one canonical encoding.

use super::Tag;

/// An append-only buffer of DER values.
#[derive(Debug, Default)]
pub struct DerWriter {
    /// The values written so far.
    out: Vec<u8>,
}

impl DerWriter {
    /// An empty writer.
    #[must_use]
    pub const fn new() -> Self {
        Self { out: Vec::new() }
    }

    /// The encoded values.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    /// Appends a value with the tag and content.
    pub fn element(&mut self, tag: Tag, content: &[u8]) {
        self.out.push(tag.0);
        self.length(content.len());
        self.out.extend_from_slice(content);
    }

    /// Appends a value that is already encoded, such as a signed part kept verbatim.
    pub fn encoded(&mut self, value: &[u8]) {
        self.out.extend_from_slice(value);
    }

    /// Appends a constructed value whose content the closure writes.
    pub fn nested(&mut self, tag: Tag, content: impl FnOnce(&mut Self)) {
        // The length precedes the content, so the content is written aside first.
        let mut inner = Self::new();
        content(&mut inner);
        self.element(tag, &inner.out);
    }

    /// Appends a SEQUENCE whose values the closure writes.
    pub fn sequence(&mut self, content: impl FnOnce(&mut Self)) {
        self.nested(Tag::SEQUENCE, content);
    }

    /// Appends a non-negative INTEGER from big-endian magnitude bytes.
    pub fn unsigned_integer(&mut self, magnitude: &[u8]) {
        // Strip leading zeros, keeping one byte for zero itself.
        let first = magnitude
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(magnitude.len());
        let digits = &magnitude[first..];
        let mut content = Vec::with_capacity(digits.len() + 1);

        // A set top bit would read as negative, so a zero byte goes in front.
        if digits.first().is_none_or(|&byte| byte & 0x80 != 0) {
            content.push(0);
        }
        content.extend_from_slice(digits);
        self.element(Tag::INTEGER, &content);
    }

    /// Appends a BOOLEAN.
    pub fn boolean(&mut self, value: bool) {
        self.element(Tag::BOOLEAN, &[if value { 0xff } else { 0x00 }]);
    }

    /// Appends a BIT STRING of whole bytes.
    pub fn bit_string(&mut self, bytes: &[u8]) {
        // Zero unused bits, then the bytes.
        let mut content = Vec::with_capacity(bytes.len() + 1);
        content.push(0);
        content.extend_from_slice(bytes);
        self.element(Tag::BIT_STRING, &content);
    }

    /// Appends a length in its shortest definite form.
    fn length(&mut self, length: usize) {
        if length < 0x80 {
            self.out.push(length as u8);
            return;
        }
        // Long form: 0x80 + k, then k big-endian bytes without a leading zero.
        let bytes = length.to_be_bytes();
        let first = bytes.iter().position(|&byte| byte != 0).unwrap_or(0);
        let significant = &bytes[first..];
        self.out.push(0x80 | significant.len() as u8);
        self.out.extend_from_slice(significant);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_encodings() {
        // INTEGER 0, 127, 128, and 0x00 0x00 0x01 stripped to 1.
        let mut writer = DerWriter::new();
        writer.unsigned_integer(&[]);
        writer.unsigned_integer(&[0x7f]);
        writer.unsigned_integer(&[0x80]);
        writer.unsigned_integer(&[0, 0, 1]);
        assert_eq!(
            writer.into_bytes(),
            [
                0x02, 0x01, 0x00, 0x02, 0x01, 0x7f, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01
            ]
        );

        // A 300-byte octet string takes the two-byte long form 0x82 0x01 0x2c.
        let mut writer = DerWriter::new();
        writer.element(Tag::OCTET_STRING, &[0; 300]);
        assert_eq!(writer.into_bytes()[..4], [0x04, 0x82, 0x01, 0x2c]);

        // SEQUENCE { BOOLEAN true, BIT STRING 0xaa }.
        let mut writer = DerWriter::new();
        writer.sequence(|inner| {
            inner.boolean(true);
            inner.bit_string(&[0xaa]);
        });
        assert_eq!(
            writer.into_bytes(),
            [0x30, 0x07, 0x01, 0x01, 0xff, 0x03, 0x02, 0x00, 0xaa]
        );
    }
}
