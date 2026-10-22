//! Recursive Length Prefix, the serialization of Ethereum node records and discovery messages.
//!
//! # Overview
//!
//! RLP encodes two shapes: byte strings and lists of items.
//! Integers are byte strings in minimal big-endian form.
//! The rules are the Yellow Paper, appendix B.
//!
//! ```text
//! 0x00..0x7f   one byte, encoded as itself
//! 0x80..0xb7   string of 0 to 55 bytes, length in the prefix
//! 0xb8..0xbf   longer string, length in the next 1 to 8 bytes
//! 0xc0..0xf7   list with a payload of 0 to 55 bytes
//! 0xf8..0xff   longer list, length in the next 1 to 8 bytes
//! ```
//!
//! # Invariants
//!
//! Decoding is strict: every value has exactly one accepted encoding.
//! Non-minimal lengths, padded integers, and wrapped single bytes are refused.
//! Signatures over node records rely on that uniqueness.
//!
//! # Examples
//!
//! ```
//! use axiom_rlp::{Decoder, Encoder};
//!
//! let mut encoder = Encoder::new();
//! encoder.list(|list| {
//!     list.bytes(b"dog").uint(1024);
//! });
//! let encoded = encoder.finish();
//! assert_eq!(encoded, [0xc7, 0x83, b'd', b'o', b'g', 0x82, 0x04, 0x00]);
//!
//! let mut decoder = Decoder::new(&encoded);
//! let mut list = decoder.list().unwrap();
//! assert_eq!(list.bytes().unwrap(), b"dog");
//! assert_eq!(list.uint().unwrap(), 1024);
//! ```

mod decoder;
mod encoder;
mod error;
mod header;
mod item;

pub use decoder::Decoder;
pub use encoder::Encoder;
pub use error::RlpError;
pub use header::{Header, Kind};
pub use item::Item;
