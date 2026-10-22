//! Signature collection and batch verification.

use std::fmt;

use axiom_bls::{PublicKey, Signature, SignatureSet};
use axiom_types::{BlsSignature, Root};

use crate::BlockError;

/// Whether a transition checks signatures.
///
/// Spec tests run some vectors with signatures disabled.
/// A node skips them only for blocks it built or already verified.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Verification {
    /// Every signature is checked.
    #[default]
    Verify,
    /// Signatures are ignored.
    Skip,
}

/// Signatures gathered during block processing, verified together at the end.
///
/// # Overview
///
/// A block carries dozens of independent signatures.
/// Checking them one by one costs two pairings each.
///
/// A random linear combination checks them all with one multi-pairing.
/// The combination is sound: a single bad signature fails it except with negligible probability.
#[derive(Default)]
pub struct SignatureBatch {
    /// Whether signatures are checked at all.
    verification: Verification,
    /// The gathered checks.
    sets: Vec<SignatureSet>,
}

impl SignatureBatch {
    /// An empty batch.
    #[must_use]
    pub const fn new(verification: Verification) -> Self {
        Self {
            verification,
            sets: Vec::new(),
        }
    }

    /// Whether signatures are checked, so callers can skip building keys they will not use.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.verification == Verification::Verify
    }

    /// Adds a signature by a key over a root.
    ///
    /// # Errors
    ///
    /// Fails when the signature bytes do not decode to a group element.
    pub fn push(
        &mut self,
        public_key: PublicKey,
        message: Root,
        signature: &BlsSignature,
    ) -> Result<(), BlockError> {
        if !self.is_enabled() {
            return Ok(());
        }
        let signature =
            Signature::from_bytes(&signature.0).map_err(|_| BlockError::MalformedSignature)?;
        self.sets.push(SignatureSet {
            signature,
            public_key,
            message: message.0,
        });
        Ok(())
    }

    /// Checks every gathered signature with one multi-pairing.
    ///
    /// # Errors
    ///
    /// Fails when any signature does not verify.
    pub fn verify(self) -> Result<(), BlockError> {
        if SignatureSet::verify_batch(&self.sets) {
            Ok(())
        } else {
            Err(BlockError::InvalidSignature)
        }
    }
}

impl fmt::Debug for SignatureBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureBatch")
            .field("verification", &self.verification)
            .field("sets", &self.sets.len())
            .finish()
    }
}
