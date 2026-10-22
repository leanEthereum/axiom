//! Secret keys: scalars that sign messages.

use std::{fmt, hint::black_box};

use axiom_bls12_381::{G1Projective, G2Affine, G2Projective, SCALAR_BYTES, Scalar};

use crate::{BlsError, DST, PublicKey, Signature};

/// A secret key: a nonzero scalar below the group order r.
///
/// The scalar is overwritten with zero when the key is dropped.
/// The key cannot be cloned, and its debug output hides the scalar.
pub struct SecretKey {
    /// The secret scalar, never zero.
    scalar: Scalar,
}

impl SecretKey {
    /// Decodes a key from its 32-byte big-endian encoding.
    ///
    /// # Errors
    ///
    /// Rejects zero and any integer not below r, as KeyGen never produces them.
    pub fn from_bytes(bytes: &[u8; SCALAR_BYTES]) -> Result<Self, BlsError> {
        // The integer must be canonical, below r.
        let scalar = Scalar::from_bytes_be(bytes).ok_or(BlsError::InvalidSecretKey)?;
        // Zero would make every signature the identity.
        if scalar.is_zero() {
            return Err(BlsError::InvalidSecretKey);
        }
        Ok(Self { scalar })
    }

    /// Derives the public key sk * G1, the SkToPk function of draft-irtf-cfrg-bls-signature-05 section 2.4.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        // Invariant: sk is nonzero and below r, and G1 has prime order r.
        // So sk * G1 is a non-identity member of G1, a valid public key.
        PublicKey::from_point_unchecked((G1Projective::GENERATOR * self.scalar).into())
    }

    /// Signs a message, the CoreSign function of draft-irtf-cfrg-bls-signature-05 section 2.6.
    ///
    /// The signature is sk * H(message), with H the hash to G2 under the proof-of-possession tag.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        let hashed = G2Projective::hash_to_curve(message, DST);
        // Constant-time multiplication: the secret scalar never steers a branch or a memory access.
        Signature::from_point(G2Affine::from(hashed * self.scalar))
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Overwrite the scalar, then pass it through an optimization barrier.
        // The barrier counts as a read, so the compiler cannot discard the write as dead.
        self.scalar = Scalar::ZERO;
        black_box(&self.scalar);
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_rejected() {
        // Zero is canonical but signs every message with the identity.
        assert_eq!(
            SecretKey::from_bytes(&[0; 32]).err(),
            Some(BlsError::InvalidSecretKey)
        );
    }

    #[test]
    fn group_order_is_rejected_and_its_predecessor_accepted() {
        // Fixture state: r in big-endian bytes.
        let mut bytes = [
            0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1,
            0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x01,
        ];
        assert_eq!(
            SecretKey::from_bytes(&bytes).err(),
            Some(BlsError::InvalidSecretKey)
        );

        // Mutation: r - 1 is the largest valid key.
        bytes[31] = 0x00;
        assert!(SecretKey::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn debug_output_hides_the_scalar() {
        let key = SecretKey::from_bytes(&[1; 32]).unwrap();
        assert_eq!(format!("{key:?}"), "SecretKey(<redacted>)");
    }
}
