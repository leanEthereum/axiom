//! The consensus req/resp domain: one stream per request, ssz_snappy encoded.
//!
//! # Overview
//!
//! ```text
//! requester                                            responder
//!   ── open stream, negotiate protocol id ─────────────▶
//!   ── request, then half-close ───────────────────────▶   read until EOF, validate
//!   ◀──────────────────────────── chunk, chunk, ... ───    zero or more response chunks
//!   ◀─────────────────────────────────────── close ────
//! ```
//!
//! Single-value methods answer with one chunk; list methods with one chunk per item.
//! A non-zero result code ends the response.
//! See `specs/phase0/p2p-interface.md`, the req/resp domain, and its successors.

mod codec;
mod error;
mod limiter;
mod messages;
mod protocol;

pub use codec::{
    MAX_ERROR_MESSAGE_LEN, ResponseChunk, ResponseCode, ResponseDecoder, decode_request,
    encode_request, encode_response_chunk,
};
pub use error::ReqRespError;
pub use limiter::{Quota, RateLimited, RateLimiter};
pub use messages::{Attnets, GoodbyeReason, MetaData, Status, StatusV1, Syncnets};
pub use protocol::Protocol;
