//! Streams: ids, send and receive buffers, flow control, and the map of a connection's streams.

mod credit;
mod id;
mod recv;
mod send;
mod streams;

pub use id::{Side, StreamId};
pub(crate) use recv::RecvBuffer;
pub(crate) use send::{Chunk, SendBuffer};
pub use streams::StreamLimits;
pub(crate) use streams::{StreamRecord, Streams};
