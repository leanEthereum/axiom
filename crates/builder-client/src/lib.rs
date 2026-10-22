//! The builder API: how a proposer buys an execution payload from relays.
//!
//! # Overview
//!
//! From the merge until Gloas, a proposer may sell its block's payload to an outside builder.
//! Builders reach proposers through relays, which hold each payload until the block is signed.
//!
//! A proposal through the builder API runs in four steps:
//!
//! 1. Ahead of time, the node hands each validator's signed registration to every relay.
//! 2. At the slot, the node asks every relay for a bid on the parent payload.
//! 3. The node verifies the bids, keeps the highest, and the proposer signs a blinded block.
//! 4. The relay reveals the payload, which the node checks before publishing the full block.
//!
//! A proposer must never sign two blocks for one slot.
//! So every check that can fail runs before signing, and the local payload is the fallback.
//! After signing a blinded block, the proposer is bound to it.
//!
//! Relays are reached over plain http, since this codebase has no TLS.
//! The usual deployment is a local sidecar that fans out to remote relays.
//!
//! # Spec mapping
//!
//! The builder specs live in `ethereum/builder-specs`.
//!
//! ```text
//!     endpoint or rule                     spec file                      here
//!     GET  /eth/v1/builder/status          apis/builder/status.yaml       relay status
//!     POST /eth/v1/builder/validators      apis/builder/validators.yaml   registrations
//!     GET  /eth/v1/builder/header/...      apis/builder/header.yaml       bid request
//!     POST /eth/v1/builder/blinded_blocks  apis/builder/blinded_blocks    reveal
//!     process_bid                          specs/bellatrix/validator.md   bid verification
//!     liveness failsafe                    specs/bellatrix/validator.md   circuit breaker
//! ```

mod bid;
mod circuit_breaker;
mod client;
mod concurrent;
mod error;
mod gas_limit;
pub mod mock;
mod relay_set;
mod reveal;
mod timeouts;
mod versioned;

pub use bid::{BidError, BidRequest, VerifiedBid};
pub use circuit_breaker::{BreakerTrip, ChainHealth, CircuitBreaker};
pub use client::RelayClient;
pub use error::{BuilderError, RelayFailure, RelayFailures};
pub use gas_limit::GasLimitTarget;
pub use relay_set::{Auction, RelaySet, WinningBid};
pub use reveal::{RevealError, RevealedBlobs, RevealedPayload, UnblindedBlock};
pub use timeouts::RelayTimeouts;
