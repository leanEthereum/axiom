//! The consensus req/resp domain: one stream per request, ssz_snappy encoded.
//!
//! # Overview
//!
//! 1. The requester opens a stream and negotiates the protocol id.
//! 2. The requester sends the request, then half-closes the stream.
//! 3. The responder reads until EOF and validates the request.
//! 4. The responder sends zero or more response chunks.
//! 5. The responder closes the stream.
//!
//! Single-value methods answer with one chunk; list methods with one chunk per item.
//! A non-zero result code ends the response.
//! See `specs/phase0/p2p-interface.md`, the req/resp domain, and its successors.

mod codec;
mod error;
mod limiter;
mod messages;
mod protocol;
mod status_version;

pub use codec::{
    MAX_ERROR_MESSAGE_LEN, RequestDecoder, ResponseChunk, ResponseCode, ResponseDecoder,
};
pub use error::ReqRespError;
pub use limiter::{Quota, RateLimited, RateLimiter};
pub use messages::{Attnets, GoodbyeReason, MetaData, Status, StatusV1, Syncnets};
pub use protocol::Protocol;
pub use status_version::StatusVersion;
