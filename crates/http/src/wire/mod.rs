//! The HTTP/1.1 wire format, free of any input or output.
//!
//! Everything here works on byte slices, so tests drive it directly.

mod body;
mod encode;
mod head;

pub use body::{BodyLength, ChunkedDecoder};
pub use head::{RequestHead, ResponseHead};
