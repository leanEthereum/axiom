//! Signatures: points of G2, and the verification algorithms over them.

use std::fmt;

use axiom_bls12_381::{G1Affine, G2_COMPRESSED_BYTES, G2Affine, G2Projective, Gt};

use crate::{BlsError, DST, PublicKey};

/// A signature: a point of G2, possibly the point at infinity.
///
/// Decoding checks subgroup membership, so every value already passed signature_subgroup_check.
/// The point at infinity is a valid encoding: it is the aggregate of no signatures in Ethereum's sense.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    /// The signature as a curve point, always in G2.
    point: G2Affine,
}

impl Signature {
    /// The encoding of the point at infinity: the compression and infinity flags, then zeros.
    pub const INFINITY_BYTES: [u8; G2_COMPRESSED_BYTES] = {
        let mut bytes = [0; G2_COMPRESSED_BYTES];
        bytes[0] = 0xc0;
        bytes
    };

    /// Decodes a compressed signature and checks that it lies in G2.
    ///
    /// # Errors
    ///
    /// Rejects encodings that are malformed, off the curve, or outside G2.
    pub fn from_bytes(bytes: &[u8; G2_COMPRESSED_BYTES]) -> Result<Self, BlsError> {
        G2Affine::from_compressed(bytes)
            .map(Self::from_point)
            .map_err(BlsError::InvalidSignature)
    }

    /// Encodes the signature in the 96-byte compressed form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; G2_COMPRESSED_BYTES] {
        self.point.to_compressed()
    }

    /// Whether this is the point at infinity.
    #[must_use]
    pub const fn is_infinity(&self) -> bool {
        self.point.is_identity()
    }

    /// The signature as a curve point.
    #[must_use]
    pub const fn as_point(&self) -> &G2Affine {
        &self.point
    }

    /// Sums signatures, the Aggregate function of draft-irtf-cfrg-bls-signature-05 section 2.8.
    ///
    /// # Errors
    ///
    /// Rejects an empty list.
    pub fn aggregate(signatures: &[Self]) -> Result<Self, BlsError> {
        // The draft defines no aggregate of nothing.
        if signatures.is_empty() {
            return Err(BlsError::EmptyAggregate);
        }
        // Mixed additions into a projective accumulator, one normalization at the end.
        let sum = signatures
            .iter()
            .fold(G2Projective::IDENTITY, |acc, signature| {
                acc + signature.point
            });
        Ok(Self::from_point(G2Affine::from(sum)))
    }

    /// Checks the signature on one message, the Verify function of the proof-of-possession scheme.
    ///
    /// # Algorithm
    ///
    /// CoreVerify, draft-irtf-cfrg-bls-signature-05 section 2.7, as one product of two pairings:
    ///
    /// ```text
    ///     e(pk, H(m)) = e(G1, sig)   <=>   e(pk, H(m)) * e(-G1, sig) = 1
    /// ```
    #[must_use]
    pub fn verify(&self, key: &PublicKey, message: &[u8]) -> bool {
        // Both inputs were validated at construction, so only the pairing equation remains.
        let hashed = G2Affine::from(G2Projective::hash_to_curve(message, DST));
        Gt::multi_pairing(&[
            (*key.as_point(), hashed),
            (-G1Affine::GENERATOR, self.point),
        ])
        .is_identity()
    }

    /// Checks the signature on one message signed by every key, draft-irtf-cfrg-bls-signature-05 section 3.3.4.
    ///
    /// Proof of possession makes summing the keys safe against rogue-key attacks.
    /// An empty key list fails, and so does a sum of keys equal to infinity.
    #[must_use]
    pub fn fast_aggregate_verify(&self, keys: &[&PublicKey], message: &[u8]) -> bool {
        match PublicKey::aggregate_refs(keys.iter().copied()) {
            // CoreVerify includes KeyValidate, which the aggregate either passed or failed above.
            Ok(aggregate) => self.verify(&aggregate, message),
            Err(_) => false,
        }
    }

    /// Like the fast aggregate check, but accepts the infinity signature over no keys.
    ///
    /// This is eth_fast_aggregate_verify of the Altair specification.
    /// It lets a sync committee aggregate with no participants verify.
    #[must_use]
    pub fn eth_fast_aggregate_verify(&self, keys: &[&PublicKey], message: &[u8]) -> bool {
        // Altair: an empty participant set signs with the infinity signature.
        if keys.is_empty() && self.is_infinity() {
            return true;
        }
        // Every other case follows the draft's rules.
        self.fast_aggregate_verify(keys, message)
    }

    /// Checks an aggregate signature over one message per key, the AggregateVerify function.
    ///
    /// # Algorithm
    ///
    /// CoreAggregateVerify, draft-irtf-cfrg-bls-signature-05 section 2.9, as one product of n + 1 pairings:
    ///
    /// ```text
    ///     prod_i e(pk_i, H(m_i)) * e(-G1, sig) = 1
    /// ```
    ///
    /// The proof-of-possession scheme, section 3.3, does not require distinct messages.
    /// Only the basic scheme of section 3.1 needs that rule, to stop rogue-key attacks that proofs of possession already stop.
    #[must_use]
    pub fn aggregate_verify(&self, keys: &[&PublicKey], messages: &[&[u8]]) -> bool {
        // The draft rejects empty inputs and mismatched lengths outright.
        if keys.is_empty() || keys.len() != messages.len() {
            return false;
        }
        let mut terms: Vec<(G1Affine, G2Affine)> = keys
            .iter()
            .zip(messages)
            .map(|(key, message)| {
                let hashed = G2Projective::hash_to_curve(message, DST);
                (*key.as_point(), G2Affine::from(hashed))
            })
            .collect();
        terms.push((-G1Affine::GENERATOR, self.point));
        Gt::multi_pairing(&terms).is_identity()
    }

    /// Wraps a point the caller knows to lie in G2.
    pub(crate) const fn from_point(point: G2Affine) -> Self {
        Self { point }
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The compressed encoding identifies the signature compactly.
        f.write_str("Signature(0x")?;
        for byte in self.to_bytes() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::SecretKey;

    /// A secret key from 32 random bytes, retried by the strategy until valid.
    fn arb_secret_key() -> impl Strategy<Value = SecretKey> {
        any::<[u8; 32]>().prop_filter_map("bytes must be a valid key", |mut bytes| {
            // Clear the top bit so most draws land below r.
            bytes[0] &= 0x3f;
            SecretKey::from_bytes(&bytes).ok()
        })
    }

    #[test]
    fn infinity_bytes_decode_to_infinity() {
        let signature = Signature::from_bytes(&Signature::INFINITY_BYTES).unwrap();
        assert!(signature.is_infinity());
        assert_eq!(signature.to_bytes(), Signature::INFINITY_BYTES);
    }

    #[test]
    fn aggregation_of_nothing_fails() {
        assert_eq!(Signature::aggregate(&[]), Err(BlsError::EmptyAggregate));
    }

    #[test]
    fn empty_inputs_fail_every_aggregate_check() {
        let signature = Signature::from_bytes(&Signature::INFINITY_BYTES).unwrap();
        // The plain checks reject no keys whatever the signature.
        assert!(!signature.fast_aggregate_verify(&[], b"message"));
        assert!(!signature.aggregate_verify(&[], &[]));
        // The Ethereum variant accepts exactly this case: no keys, infinity signature.
        assert!(signature.eth_fast_aggregate_verify(&[], b"message"));
    }

    #[test]
    fn mismatched_lengths_fail_aggregate_verify() {
        // Fixture state: one key, two messages.
        let key = SecretKey::from_bytes(&[3; 32]).unwrap();
        let signature = key.sign(b"a");
        assert!(!signature.aggregate_verify(&[&key.public_key()], &[b"a", b"b"]));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn signatures_verify_only_their_own_message_and_key(
            first in arb_secret_key(),
            second in arb_secret_key(),
            message in any::<[u8; 32]>(),
        ) {
            let signature = first.sign(&message);
            prop_assert!(signature.verify(&first.public_key(), &message));

            // Mutation: another message under the same key.
            let mut other = message;
            other[0] ^= 1;
            prop_assert!(!signature.verify(&first.public_key(), &other));

            // Mutation: the right message under another key.
            prop_assert!(!signature.verify(&second.public_key(), &message));

            // Round trip through the wire format.
            prop_assert_eq!(Signature::from_bytes(&signature.to_bytes()), Ok(signature));
        }

        #[test]
        fn aggregates_verify_like_their_parts(
            first in arb_secret_key(),
            second in arb_secret_key(),
            message in any::<[u8; 32]>(),
        ) {
            // Fast aggregation: two keys sign the same message.
            let signatures = [first.sign(&message), second.sign(&message)];
            let aggregate = Signature::aggregate(&signatures).unwrap();
            let keys = [first.public_key(), second.public_key()];
            prop_assert!(aggregate.fast_aggregate_verify(&[&keys[0], &keys[1]], &message));
            prop_assert!(!aggregate.fast_aggregate_verify(&[&keys[0]], &message));

            // General aggregation: each key signs its own message.
            let mut other = message;
            other[31] ^= 0xff;
            let aggregate =
                Signature::aggregate(&[first.sign(&message), second.sign(&other)]).unwrap();
            prop_assert!(aggregate.aggregate_verify(&[&keys[0], &keys[1]], &[&message, &other]));
            // Swapping the messages breaks the pairing equation.
            prop_assert!(!aggregate.aggregate_verify(&[&keys[0], &keys[1]], &[&other, &message]));
        }
    }
}
