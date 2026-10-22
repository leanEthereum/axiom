//! One decoded blob opening, the unit of the EIP-4844 batch check.

use axiom_bls12_381::{G1Affine, Scalar};

use crate::{Bytes32, Bytes48, FIELD_ELEMENTS_PER_BLOB, transcript::Transcript};

/// Domain tag of the blob batch coefficient, RANDOM_CHALLENGE_KZG_BATCH_DOMAIN in the Deneb spec.
const RANDOM_CHALLENGE_KZG_BATCH_DOMAIN: &[u8; 16] = b"RCKZGBATCH___V1_";

/// The claim f(z) = y for a committed f, with its proof, as bytes and as points.
///
/// The batch challenge hashes the bytes as received, and the pairing check uses the points.
#[derive(Clone, Copy, Debug)]
pub(super) struct Opening<'a> {
    /// The commitment, as received.
    pub(super) commitment_bytes: &'a Bytes48,
    /// The proof, as received.
    pub(super) proof_bytes: &'a Bytes48,
    /// The decoded commitment.
    pub(super) commitment: G1Affine,
    /// The decoded proof.
    pub(super) proof: G1Affine,
    /// The evaluation point.
    pub(super) z: Scalar,
    /// The claimed evaluation.
    pub(super) y: Scalar,
}

impl Opening<'_> {
    /// The coefficient r of the random linear combination of openings, from verify_kzg_proof_batch.
    ///
    /// ```text
    ///     SHA-256( tag || 4096 as u64 || n as u64 || (commitment || z || y || proof) for each )  mod r
    /// ```
    pub(super) fn batch_challenge(openings: &[Self]) -> Scalar {
        let mut transcript = Transcript::new(RANDOM_CHALLENGE_KZG_BATCH_DOMAIN);
        transcript.append_u64(FIELD_ELEMENTS_PER_BLOB as u64);
        transcript.append_u64(openings.len() as u64);
        for opening in openings {
            transcript.append(opening.commitment_bytes.0);
            transcript.append(Bytes32::from_scalar(&opening.z).0);
            transcript.append(Bytes32::from_scalar(&opening.y).0);
            transcript.append(opening.proof_bytes.0);
        }
        transcript.challenge()
    }
}
