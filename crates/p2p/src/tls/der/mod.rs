//! A strict reader and writer for the ASN.1 Distinguished Encoding Rules.
//!
//! # Overview
//!
//! Every DER value is a tag, a length, and that many content bytes.
//!
//! ```text
//! [ tag: 1 byte ][ length: 1 to 5 bytes ][ content ]
//!
//! length < 128 : one byte holding the length
//! length >= 128: 0x80 + k, then the length in k big-endian bytes, without leading zeros
//! ```
//!
//! X.509 certificates and ECDSA signatures are DER, so these rules guard every certificate check.
//! See ITU-T X.690, sections 8 and 10.
//!
//! # Strictness
//!
//! A value has exactly one DER encoding, and only that encoding is accepted.
//!
//! - Lengths are definite and minimal.
//! - Integers are minimal two's complement.
//! - Booleans are 0x00 or 0xff.
//! - Bit strings here carry whole bytes, with zero unused bits.
//! - Tags use the one-byte form; the high tag number form never occurs in a certificate.
//! - A container ends exactly where its length says.
//!
//! Every input is public: certificates and signatures travel in the clear.

mod error;
mod reader;
mod time;
mod writer;

pub use error::DerError;
pub(crate) use reader::DerReader;
pub(crate) use time::Timestamp;
pub(crate) use writer::DerWriter;

/// An ASN.1 tag in the one-byte form: class, constructed bit, and number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Tag(pub(crate) u8);

impl Tag {
    /// BOOLEAN, universal 1.
    pub(crate) const BOOLEAN: Self = Self(0x01);
    /// INTEGER, universal 2.
    pub(crate) const INTEGER: Self = Self(0x02);
    /// BIT STRING, universal 3.
    pub(crate) const BIT_STRING: Self = Self(0x03);
    /// OCTET STRING, universal 4.
    pub(crate) const OCTET_STRING: Self = Self(0x04);
    /// OBJECT IDENTIFIER, universal 6.
    pub(crate) const OBJECT_IDENTIFIER: Self = Self(0x06);
    /// UTF8String, universal 12.
    pub(crate) const UTF8_STRING: Self = Self(0x0c);
    /// UTCTime, universal 23.
    pub(crate) const UTC_TIME: Self = Self(0x17);
    /// GeneralizedTime, universal 24.
    pub(crate) const GENERALIZED_TIME: Self = Self(0x18);
    /// SEQUENCE, universal 16, constructed.
    pub(crate) const SEQUENCE: Self = Self(0x30);
    /// SET, universal 17, constructed.
    pub(crate) const SET: Self = Self(0x31);

    /// The context-specific constructed tag [n], as an EXPLICIT field carries it.
    pub(crate) const fn explicit(number: u8) -> Self {
        // Class bits 10, constructed bit 1, then the number.
        Self(0xa0 | number)
    }

    /// The context-specific primitive tag [n], as an IMPLICIT primitive field carries it.
    pub(crate) const fn implicit(number: u8) -> Self {
        // Class bits 10, constructed bit 0, then the number.
        Self(0x80 | number)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// A tree of DER values, built by the writer and read back by the reader.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Value {
        /// A non-negative integer magnitude, without leading zeros.
        Integer(Vec<u8>),
        /// An octet string.
        Octets(Vec<u8>),
        /// A boolean.
        Boolean(bool),
        /// A sequence of values.
        Sequence(Vec<Self>),
    }

    impl Value {
        /// Writes the value.
        fn write(&self, writer: &mut DerWriter) {
            match self {
                Self::Integer(magnitude) => writer.unsigned_integer(magnitude),
                Self::Octets(bytes) => writer.element(Tag::OCTET_STRING, bytes),
                Self::Boolean(value) => writer.boolean(*value),
                Self::Sequence(values) => writer.sequence(|inner| {
                    for value in values {
                        value.write(inner);
                    }
                }),
            }
        }

        /// Reads the next value of the reader.
        fn read(reader: &mut DerReader<'_>) -> Result<Self, DerError> {
            match reader.peek_tag() {
                Some(Tag::INTEGER) => Ok(Self::Integer(reader.unsigned_integer()?.to_vec())),
                Some(Tag::OCTET_STRING) => Ok(Self::Octets(reader.octet_string()?.to_vec())),
                Some(Tag::BOOLEAN) => Ok(Self::Boolean(reader.boolean()?)),
                _ => {
                    let mut inner = reader.sequence()?;
                    let mut values = Vec::new();
                    while !inner.is_empty() {
                        values.push(Self::read(&mut inner)?);
                    }
                    Ok(Self::Sequence(values))
                }
            }
        }
    }

    /// Any value tree, three levels deep at most.
    fn arb_value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..40).prop_map(|bytes| {
                // Strip leading zeros: the reader returns the minimal magnitude, one byte for zero.
                let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
                let magnitude = &bytes[first..];
                Value::Integer(if magnitude.is_empty() {
                    vec![0]
                } else {
                    magnitude.to_vec()
                })
            }),
            proptest::collection::vec(any::<u8>(), 0..300).prop_map(Value::Octets),
            any::<bool>().prop_map(Value::Boolean),
        ];
        leaf.prop_recursive(3, 32, 6, |inner| {
            proptest::collection::vec(inner, 0..6).prop_map(Value::Sequence)
        })
    }

    proptest! {
        #[test]
        fn written_values_read_back(value in arb_value()) {
            // Law: the reader inverts the writer, and consumes every byte.
            let mut writer = DerWriter::new();
            value.write(&mut writer);
            let bytes = writer.into_bytes();
            let mut reader = DerReader::new(&bytes);
            let read = Value::read(&mut reader);
            prop_assert_eq!(read, Ok(value));
            prop_assert_eq!(reader.finish(), Ok(()));
        }

        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            // Any input either parses or fails cleanly.
            let mut reader = DerReader::new(&bytes);
            while !reader.is_empty() {
                if Value::read(&mut reader).is_err() {
                    break;
                }
            }
        }

        #[test]
        fn encodings_are_unique(value in arb_value(), flip in any::<prop::sample::Index>()) {
            // A one-byte change either fails to read or reads a different value.
            let mut writer = DerWriter::new();
            value.write(&mut writer);
            let mut bytes = writer.into_bytes();
            let position = flip.index(bytes.len());
            bytes[position] ^= 0x01;
            let mut reader = DerReader::new(&bytes);
            if let Ok(read) = Value::read(&mut reader)
                && reader.finish().is_ok()
            {
                prop_assert_ne!(read, value);
            }
        }
    }
}
