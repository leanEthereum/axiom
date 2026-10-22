//! A set of signers over one message, with their aggregate signature.

use axiom_bls::Signature;
use axiom_types::BlsSignature;

use crate::{Bits, PoolError};

/// Signers at their positions in a committee, and one signature standing for all of them.
///
/// # Overview
///
/// Two aggregates over the same message combine when their signers are disjoint.
/// Their signatures then add up as points, and the result verifies against the union.
///
/// This type is the only place the pool combines signatures.
/// A scheme without that additive law replaces the merge here and nowhere else.
///
/// # Invariants
///
/// The signature verifies for the signers, which the pool's caller checked on entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aggregate {
    /// Positions of the signers.
    pub bits: Bits,
    /// The signers' aggregate signature, compressed.
    pub signature: BlsSignature,
}

impl Aggregate {
    /// Whether the other aggregate adds no signer.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        other.bits.is_subset_of(&self.bits)
    }

    /// Adds a disjoint aggregate's signers and signature.
    ///
    /// # Algorithm
    ///
    /// BLS signatures over one message aggregate by point addition in G2.
    /// With s_i = sk_i * H(m), the sum verifies for the sum of the keys.
    /// See the IETF BLS signature draft, section 2.8.
    ///
    /// # Errors
    ///
    /// Fails when the signers overlap, which would count one signer twice.
    /// Fails when a signature is not a valid point.
    pub fn merge(&mut self, other: &Self) -> Result<(), PoolError> {
        if !self.bits.is_disjoint(&other.bits) || self.bits.len() != other.bits.len() {
            return Err(PoolError::OverlappingSigners);
        }
        self.signature = Self::sum(&[self.signature, other.signature])?;
        self.bits.union_with(&other.bits);
        Ok(())
    }

    /// The aggregate of compressed signatures, compressed.
    ///
    /// No signature at all gives the point at infinity, the identity of the group.
    ///
    /// # Errors
    ///
    /// Fails when a signature is not a valid point.
    pub fn sum(signatures: &[BlsSignature]) -> Result<BlsSignature, PoolError> {
        if signatures.is_empty() {
            return Ok(BlsSignature(Signature::INFINITY_BYTES));
        }
        let points = signatures
            .iter()
            .map(|signature| Signature::from_bytes(&signature.0))
            .collect::<Result<Vec<_>, _>>()
            .map_err(PoolError::Signature)?;
        let sum = Signature::aggregate(&points).map_err(PoolError::Signature)?;
        Ok(BlsSignature(sum.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use axiom_bls::SecretKey;

    use super::*;

    /// A signature of a message by the secret key 1, 2, or 3.
    fn signed(secret: u8, message: &[u8]) -> BlsSignature {
        let mut bytes = [0; 32];
        bytes[31] = secret;
        BlsSignature(
            SecretKey::from_bytes(&bytes)
                .unwrap()
                .sign(message)
                .to_bytes(),
        )
    }

    #[test]
    fn disjoint_signers_merge_into_one_verifying_signature() {
        // Fixture state: a committee of 4; keys 1 and 2 sit at positions 0 and 3.
        let message = b"attestation data root";
        let mut left = Aggregate {
            bits: Bits::single(4, 0),
            signature: signed(1, message),
        };
        let right = Aggregate {
            bits: Bits::single(4, 3),
            signature: signed(2, message),
        };

        left.merge(&right).unwrap();

        // Positions 0 and 3, and a signature verifying for both keys.
        assert_eq!(left.bits.ones().collect::<Vec<_>>(), [0, 3]);
        let keys: Vec<_> = [1_u8, 2]
            .map(|secret| {
                let mut bytes = [0; 32];
                bytes[31] = secret;
                SecretKey::from_bytes(&bytes).unwrap().public_key()
            })
            .into_iter()
            .collect();
        let signature = Signature::from_bytes(&left.signature.0).unwrap();
        assert!(signature.fast_aggregate_verify(&keys.iter().collect::<Vec<_>>(), message));
    }

    #[test]
    fn overlapping_signers_are_refused_and_nothing_changes() {
        // Mutation: both aggregates claim position 1.
        let message = b"m";
        let mut left = Aggregate {
            bits: Bits::from_bools([false, true, true].into_iter()),
            signature: signed(1, message),
        };
        let before = left.clone();
        let right = Aggregate {
            bits: Bits::single(3, 1),
            signature: signed(3, message),
        };

        assert_eq!(left.merge(&right), Err(PoolError::OverlappingSigners));
        assert_eq!(left, before);
    }

    #[test]
    fn the_sum_of_nothing_is_the_point_at_infinity() {
        assert_eq!(
            Aggregate::sum(&[]),
            Ok(BlsSignature(Signature::INFINITY_BYTES))
        );
    }
}
