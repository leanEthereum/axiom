//! JSON, as the engine API and the beacon node API speak it.
//!
//! # Overview
//!
//! The parser accepts exactly the grammar of RFC 8259 and nothing more.
//!
//! - No comments, no trailing commas, no single quotes, no leading byte order mark.
//! - Strings must be valid UTF-8 and must not encode a lone surrogate.
//! - An object must not repeat a member name.
//!
//! RFC 8259 leaves repeated names to the implementation.
//! Two readers that pick different duplicates would see two different messages.
//! Rejecting them closes that gap on an authenticated, consensus-critical channel.
//!
//! Hostile input is bounded twice.
//! A size limit caps the bytes read, and a depth limit caps the nesting.
//! The parser keeps its own stack, so deep input never overflows the thread's stack.
//!
//! Numbers keep the exact text they were written with.
//! A 256-bit wei amount or a 64-bit gas limit never passes through a float.
//!
//! Ethereum JSON-RPC carries integers and bytes as hex strings.
//! Two codec traits encode and decode them.
//!
//! ```text
//!     QUANTITY  minimal hex of an integer    0      -> "0x0"
//!                                            1024   -> "0x400"
//!     DATA      two hex digits per byte      []     -> "0x"
//!                                            [0, 1] -> "0x0001"
//! ```

mod data;
mod error;
mod frame;
mod hex;
mod number;
mod object;
mod parser;
mod quantity;
mod value;
mod writer;

pub use data::Data;
pub use error::{ErrorKind, ParseError};
pub use hex::HexError;
pub use number::{Number, NumberError};
pub use object::Object;
pub use parser::Limits;
pub use quantity::Quantity;
pub use value::Json;
