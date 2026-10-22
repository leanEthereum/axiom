//! The signing seam: what is signed, whether it is safe, and the scheme that signs.
//!
//! # Overview
//!
//! A signature comes out of three independent steps.
//!
//! 1. The request names the message, and the context turns it into a signing root.
//! 2. Slashing protection records a block or a vote durably, or refuses it.
//! 3. The key signs the root under its scheme, locally or through a remote signer.
//!
//! Only the third step knows the scheme.
//! Domains, roots, and protection are the same for BLS and for any successor.
//!
//! # Plugging in a hash-based scheme
//!
//! A hash-based scheme implements the scheme trait with its own key and signature types.
//! It declares one-time keys with their leaf supply.
//!
//! A local key of that scheme then needs a leaf ledger.
//! Before each signature, the ledger spends the next leaf on stable storage.
//! A crash can waste a leaf but can never sign twice with one.
//!
//! A synchronized scheme ties leaves to slots instead of a counter.
//! It maps each message to its leaf before signing, and the ledger refuses any leaf already passed.
//!
//! Such a scheme does not aggregate, so its aggregation step answers nothing.
//! The duties that aggregate then publish individual signatures, or a proof of them.
//!
//! Its signature does not fit the 96 bytes of today's containers.
//! A fork introducing it brings new containers, and the duties dispatch on that fork once.

mod context;
mod guard;
mod ledger;
mod local;
mod remote;
mod request;
mod scheme;
mod signer;

pub use context::SigningContext;
pub use guard::{Cleared, SigningGuard};
pub use ledger::{LeafLedger, LedgerError};
pub use local::{LocalKey, LocalKeyError};
pub use remote::{RemoteError, RemoteSigner};
pub use request::{AggregateAndProofRef, DomainScope, Protected, SigningRequest};
pub use scheme::{Bls, KeyState, Leaf, SchemeError, SignatureScheme};
pub use signer::{SignError, ValidatorSigner};
