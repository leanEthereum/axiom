//! Signing: what is signed, whether it is safe to sign, and the key that signs it.
//!
//! # Overview
//!
//! A signature comes out of three steps.
//!
//! 1. The request names the message, and the context turns it into a signing root.
//! 2. Slashing protection records a block or a vote durably, or refuses it.
//! 3. The key signs the root, locally or through a remote signer.
//!
//! Only a message protection has cleared reaches the third step.

mod context;
mod guard;
mod local;
mod remote;
mod request;
mod signer;

pub use context::SigningContext;
pub use guard::{Cleared, SigningGuard};
pub use local::LocalKey;
pub use remote::{RemoteError, RemoteSigner};
pub use request::{AggregateAndProofRef, DomainScope, Protected, SigningRequest};
pub use signer::{SignError, ValidatorSigner};
