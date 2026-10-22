//! Appending the fields of one message.

use super::{ProtoMessage, WireType};
use crate::varint::Varint;

/// Appends the fields of one message to a buffer, in the order written.
#[derive(Debug)]
pub struct FieldWriter<'a> {
    /// The buffer the fields go to.
    out: &'a mut Vec<u8>,
}

impl<'a> FieldWriter<'a> {
    /// A writer appending to a buffer.
    pub const fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }

    /// Appends a varint field.
    pub fn varint(&mut self, number: u32, value: u64) {
        self.key(number, WireType::Varint);
        Varint::Protobuf.write(value, self.out);
    }

    /// Appends a length-delimited field holding raw bytes or a string.
    pub fn bytes(&mut self, number: u32, bytes: &[u8]) {
        self.key(number, WireType::LengthDelimited);
        Varint::Protobuf.write(bytes.len() as u64, self.out);
        self.out.extend_from_slice(bytes);
    }

    /// Appends a nested message as a length-delimited field.
    pub fn message<M: ProtoMessage>(&mut self, number: u32, message: &M) {
        self.key(number, WireType::LengthDelimited);
        message.encode_length_prefixed(self.out);
    }

    /// Appends a field key.
    fn key(&mut self, number: u32, wire_type: WireType) {
        Varint::Protobuf.write((u64::from(number) << 3) | wire_type.tag(), self.out);
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::protobuf::{Field, FieldReader, FieldValue, ProtobufError};

    /// A message of one bytes field, to exercise nesting.
    #[derive(Debug, PartialEq, Eq)]
    struct Blob(Vec<u8>);

    impl ProtoMessage for Blob {
        fn encode_to(&self, out: &mut Vec<u8>) {
            FieldWriter::new(out).bytes(1, &self.0);
        }

        fn decode(bytes: &[u8]) -> Result<Self, ProtobufError> {
            let field = FieldReader::new(bytes)
                .next_field()?
                .ok_or(ProtobufError::MissingField(1))?;
            Ok(Self(field.bytes()?.to_vec()))
        }
    }

    #[test]
    fn field_layouts() {
        // Field 1, varint 150: the canonical example of the protobuf docs.
        //
        //     key   = (1 << 3) | 0 = 0x08
        //     150   = [0x96, 0x01]
        let mut out = Vec::new();
        FieldWriter::new(&mut out).varint(1, 150);
        assert_eq!(out, [0x08, 0x96, 0x01]);

        // Field 2, string "testing": key 0x12, length 7, then the bytes.
        let mut out = Vec::new();
        FieldWriter::new(&mut out).bytes(2, b"testing");
        assert_eq!(out, [0x12, 0x07, b't', b'e', b's', b't', b'i', b'n', b'g']);

        // Read both back in one message.
        let mut message = vec![0x08, 0x96, 0x01];
        message.extend_from_slice(&out);
        let mut reader = FieldReader::new(&message);
        let first = reader.next_field().unwrap().unwrap();
        assert_eq!(
            first,
            Field {
                number: 1,
                value: FieldValue::Varint(150)
            }
        );
        let second = reader.next_field().unwrap().unwrap();
        assert_eq!(second.string(), Ok("testing"));
        assert_eq!(reader.next_field(), Ok(None));
    }

    #[test]
    fn nested_message_with_a_two_byte_length() {
        // A 200-byte blob encodes to key 0x0a, length [0xc8, 0x01], then 200 bytes: 203 in all.
        let blob = Blob(vec![7; 200]);
        let mut out = vec![0xee];
        FieldWriter::new(&mut out).message(3, &blob);
        // Field 3, length-delimited: key 0x1a, then length 203 = [0xcb, 0x01].
        assert_eq!(&out[..6], &[0xee, 0x1a, 0xcb, 0x01, 0x0a, 0xc8]);
        assert_eq!(out.len(), 1 + 1 + 2 + 203);
        let field = FieldReader::new(&out[1..]).next_field().unwrap().unwrap();
        assert_eq!(Blob::decode(field.bytes().unwrap()), Ok(blob));
    }

    #[test]
    fn length_prefixed_message() {
        // A 3-byte blob encodes to [0x0a, 0x03, 1, 2, 3]: prefix 5, then the body.
        let mut out = vec![0xee];
        Blob(vec![1, 2, 3]).encode_length_prefixed(&mut out);
        assert_eq!(out, [0xee, 0x05, 0x0a, 0x03, 1, 2, 3]);
    }

    proptest! {
        #[test]
        fn fields_round_trip(number in 1u32..(1 << 29), value: u64, bytes in proptest::collection::vec(any::<u8>(), 0..32)) {
            // One varint field and one bytes field under the same number.
            let mut out = Vec::new();
            let mut writer = FieldWriter::new(&mut out);
            writer.varint(number, value);
            writer.bytes(number, &bytes);
            let mut reader = FieldReader::new(&out);
            prop_assert_eq!(reader.next_field().unwrap().unwrap().varint(), Ok(value));
            prop_assert_eq!(reader.next_field().unwrap().unwrap().bytes(), Ok(&bytes[..]));
            prop_assert_eq!(reader.next_field(), Ok(None));
        }

        #[test]
        fn nested_messages_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
            // A nested message reads back as the same message, whatever its length prefix size.
            let blob = Blob(bytes);
            let mut out = Vec::new();
            FieldWriter::new(&mut out).message(1, &blob);
            let field = FieldReader::new(&out).next_field().unwrap().unwrap();
            prop_assert_eq!(Blob::decode(field.bytes().unwrap()), Ok(blob));
        }
    }
}
