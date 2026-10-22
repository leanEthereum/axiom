//! A small HTTP/1.1 client and server on tokio.
//!
//! # Overview
//!
//! The engine API, the beacon node API, and the metrics endpoint all speak HTTP/1.1.
//! This crate implements the part of RFC 9110 and RFC 9112 they need, and no more.
//!
//! The wire format is pure code over byte slices, tested without sockets.
//! The client and server wrap it with tokio sockets, timeouts, and limits.
//!
//! ```text
//!     wire     RequestHead, ResponseHead, ChunkedDecoder, encoders   pure
//!     client   connection pool, retries a stale pooled connection    async
//!     server   router, keep-alive, graceful shutdown                 async
//! ```
//!
//! An HTTP/1.1 exchange on one connection:
//!
//! ```text
//!     client                                      server
//!     POST / HTTP/1.1\r\n               ------>
//!     host: localhost:8551\r\n
//!     content-length: 2\r\n
//!     \r\n
//!     {}
//!                                       <------   HTTP/1.1 200 OK\r\n
//!                                                 content-length: 2\r\n
//!                                                 \r\n
//!                                                 {}
//!     the connection stays open for the next request
//! ```
//!
//! Every read is bounded: head size, field count, body size, and time.
//! Ambiguous framing, such as both a length and a transfer coding, is refused outright.
//!
//! # Examples
//!
//! ```
//! use axiom_http::{Limits, RequestHead};
//!
//! let bytes = b"GET /eth/v1/node/health HTTP/1.1\r\nhost: node\r\n\r\n";
//! let (head, used) = RequestHead::parse(bytes, &Limits::DEFAULT)
//!     .unwrap()
//!     .unwrap();
//! assert_eq!(head.target, "/eth/v1/node/health");
//! assert_eq!(used, bytes.len());
//! ```

mod client;
mod connection;
mod date;
mod endpoint;
mod error;
mod headers;
mod limits;
mod message;
mod method;
mod race;
mod router;
mod server;
mod status;
mod wire;

pub use client::{Client, ClientConfig};
pub use endpoint::Endpoint;
pub use error::{HttpError, ProtocolError};
pub use headers::Headers;
pub use limits::Limits;
pub use message::{Request, Response, Version};
pub use method::Method;
pub use router::Router;
pub use server::{Server, ServerConfig};
pub use status::StatusCode;
pub use wire::{BodyLength, ChunkedDecoder, RequestHead, ResponseHead};
