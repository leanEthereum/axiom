//! A minimal protobuf wire codec, enough for every libp2p message.
//!
//! # Overview
//!
//! A protobuf message is a flat run of fields.
//! Each field opens with a key: the field number and a wire type, packed in one varint.
//!
//! ```text
//! key = (field_number << 3) | wire_type
//!
//! wire type 0   varint             [ key ][ varint ]
//! wire type 1   64-bit fixed       [ key ][ 8 bytes LE ]
//! wire type 2   length-delimited   [ key ][ varint length ][ bytes ]
//! wire type 5   32-bit fixed       [ key ][ 4 bytes LE ]
//!
//! example: field 2, bytes "hi"
//!   key    = (2 << 3) | 2 = 0x12
//!   wire   = [0x12, 0x02, b'h', b'i']
//! ```
//!
//! Strings, bytes, and nested messages all use wire type 2.
//! Repeated fields repeat the key once per element.
//! Groups, wire types 3 and 4, are deprecated and rejected.
//!
//! Types are written by hand per message, with no code generation.
//! See `protocolbuffers.dev/docs/encoding`.

mod error;
mod frame;
mod reader;
mod writer;

pub use error::ProtobufError;
pub use frame::LengthPrefixedDecoder;
pub use reader::{Field, FieldReader, FieldValue};
pub use writer::FieldWriter;

use crate::varint;

/// A protobuf message with a hand-written wire encoding.
pub trait ProtoMessage: Sized {
    /// Appends the encoding of this message, without a length prefix.
    fn encode_to(&self, out: &mut Vec<u8>);

    /// Decodes a message spanning exactly the given bytes.
    ///
    /// Unknown fields are skipped, as protobuf requires for forward compatibility.
    fn decode(bytes: &[u8]) -> Result<Self, ProtobufError>;

    /// The encoding of this message in a fresh buffer.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_to(&mut out);
        out
    }

    /// Appends this message behind a varint length prefix, the framing libp2p streams use.
    fn encode_length_prefixed(&self, out: &mut Vec<u8>) {
        // The prefix needs the body's size, so the body goes first and the prefix follows.
        let start = out.len();
        self.encode_to(out);
        let body_len = out.len() - start;
        varint::encode(body_len as u64, out);
        // Rotate the prefix in front of the body, with no scratch buffer.
        //
        //     [ body ][ prefix ]  →  [ prefix ][ body ]
        let prefix_len = out.len() - start - body_len;
        out[start..].rotate_right(prefix_len);
    }
}

/// How a field's value is laid out after its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireType {
    /// A varint.
    Varint,
    /// Eight little-endian bytes.
    Fixed64,
    /// A varint length, then that many bytes.
    LengthDelimited,
    /// Four little-endian bytes.
    Fixed32,
}

impl WireType {
    /// The three-bit tag of this wire type.
    #[must_use]
    pub const fn tag(self) -> u64 {
        match self {
            Self::Varint => 0,
            Self::Fixed64 => 1,
            Self::LengthDelimited => 2,
            Self::Fixed32 => 5,
        }
    }
}
