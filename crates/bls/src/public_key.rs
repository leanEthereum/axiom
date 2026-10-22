//! Public keys: validated points of G1.

use std::fmt;

use axiom_bls12_381::{G1_COMPRESSED_BYTES, G1Affine, G1Projective};

use crate::BlsError;

/// A public key that passed KeyValidate: a point of G1 other than the point at infinity.
///
/// Every constructor enforces both properties, so holders never re-check them.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    /// The key as a curve point, in G1 and never infinite.
    point: G1Affine,
}

impl PublicKey {
    /// Decodes a compressed key and runs KeyValidate, draft-irtf-cfrg-bls-signature-05 section 2.5.
    ///
    /// # Errors
    ///
    /// Rejects encodings that are malformed, off the curve, outside G1, or the point at infinity.
    pub fn from_bytes(bytes: &[u8; G1_COMPRESSED_BYTES]) -> Result<Self, BlsError> {
        // Decoding checks flags, canonical coordinates, the curve, and the subgroup.
        let point = G1Affine::from_compressed(bytes).map_err(BlsError::InvalidPublicKey)?;
        // KeyValidate additionally rejects the identity.
        if point.is_identity() {
            return Err(BlsError::InfinityPublicKey);
        }
        Ok(Self { point })
    }

    /// Encodes the key in the 48-byte compressed form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; G1_COMPRESSED_BYTES] {
        self.point.to_compressed()
    }

    /// Sums keys, as eth_aggregate_pubkeys of the Altair specification.
    ///
    /// The specification would return an infinite sum, but no valid key is infinite.
    /// Reaching it requires knowing secret keys that cancel, which proofs of possession tie to their owners.
    ///
    /// # Errors
    ///
    /// Rejects an empty list, and a sum equal to the point at infinity.
    pub fn aggregate(keys: &[Self]) -> Result<Self, BlsError> {
        Self::aggregate_refs(keys)
    }

    /// Sums borrowed keys, with the same rules as the slice version.
    ///
    /// # Errors
    ///
    /// Rejects an empty input, and a sum equal to the point at infinity.
    pub fn aggregate_refs<'a>(keys: impl IntoIterator<Item = &'a Self>) -> Result<Self, BlsError> {
        let mut keys = keys.into_iter();
        let first = keys.next().ok_or(BlsError::EmptyAggregate)?;
        // Mixed additions into one projective accumulator, normalized once at the end.
        let sum = keys.fold(G1Projective::from(first.point), |acc, key| acc + key.point);
        Self::from_sum(&sum)
    }

    /// Returns self + (-other), the key of the signers in self but not in other.
    ///
    /// # Errors
    ///
    /// Rejects a difference equal to the point at infinity, as when both keys are equal.
    pub fn subtract(&self, other: &Self) -> Result<Self, BlsError> {
        Self::from_sum(&(G1Projective::from(self.point) + -other.point))
    }

    /// The key as a curve point.
    #[must_use]
    pub const fn as_point(&self) -> &G1Affine {
        &self.point
    }

    /// Wraps a point the caller knows to be a non-identity member of G1.
    pub(crate) const fn from_point_unchecked(point: G1Affine) -> Self {
        Self { point }
    }

    /// Wraps a sum of valid keys, rejecting the point at infinity.
    fn from_sum(sum: &G1Projective) -> Result<Self, BlsError> {
        // Invariant: G1 is closed under addition, so only the identity check remains.
        if sum.is_identity() {
            return Err(BlsError::InfinityAggregate);
        }
        Ok(Self {
            point: G1Affine::from(sum),
        })
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The compressed encoding identifies the key compactly.
        f.write_str("PublicKey(0x")?;
        for byte in self.to_bytes() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretKey;

    /// A key from a small secret.
    fn key(secret: u8) -> PublicKey {
        let mut bytes = [0; 32];
        bytes[31] = secret;
        SecretKey::from_bytes(&bytes).unwrap().public_key()
    }

    #[test]
    fn infinity_fails_key_validation() {
        // 0xc0 followed by zeros is the valid encoding of infinity, but not a valid key.
        let mut bytes = [0; 48];
        bytes[0] = 0xc0;
        assert_eq!(
            PublicKey::from_bytes(&bytes),
            Err(BlsError::InfinityPublicKey)
        );
    }

    #[test]
    fn aggregation_of_nothing_fails() {
        assert_eq!(PublicKey::aggregate(&[]), Err(BlsError::EmptyAggregate));
    }

    #[test]
    fn aggregation_adds_the_secrets() {
        // pk(2) + pk(3) = (2 + 3) G1 = pk(5).
        assert_eq!(PublicKey::aggregate(&[key(2), key(3)]), Ok(key(5)));
        assert_eq!(PublicKey::aggregate_refs([&key(2), &key(3)]), Ok(key(5)));
    }

    #[test]
    fn subtraction_removes_a_signer() {
        // pk(5) - pk(3) = pk(2), and a key minus itself is infinity.
        assert_eq!(key(5).subtract(&key(3)), Ok(key(2)));
        assert_eq!(key(5).subtract(&key(5)), Err(BlsError::InfinityAggregate));
    }

    #[test]
    fn bytes_round_trip() {
        let original = key(7);
        assert_eq!(PublicKey::from_bytes(&original.to_bytes()), Ok(original));
    }
}
