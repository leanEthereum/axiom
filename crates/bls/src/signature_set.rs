//! Independent signature checks, verified one by one or together in a single multi-pairing.

use axiom_bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use sha2::{Digest, Sha256};

use crate::{DST, PublicKey, Signature};

/// Domain tag of the batch coefficient derivation, so its hashes never collide with other uses of SHA-256.
const BATCH_DOMAIN: &[u8] = b"AXIOM_BLS_BATCH_VERIFY_V1";

/// Number of random bits in each batch coefficient.
///
/// A forged batch passes with probability at most 2^-128 per hash evaluation the forger spends.
const COEFFICIENT_BYTES: usize = 16;

/// One signature check: a signature over a 32-byte message by an already aggregated key.
///
/// Consensus objects always sign a 32-byte signing root, hence the fixed message size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureSet {
    /// The signature to check.
    pub signature: Signature,
    /// The key that must have produced it, aggregated over all signers.
    pub public_key: PublicKey,
    /// The signed message, a signing root.
    pub message: [u8; 32],
}

impl SignatureSet {
    /// Checks this set on its own.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.signature.verify(&self.public_key, &self.message)
    }

    /// Checks many sets at once, accepting only if every set is valid except with negligible probability.
    ///
    /// An empty batch is valid.
    ///
    /// # Algorithm
    ///
    /// Random linear combination with coefficients r_i, then one multi-pairing of n + 1 pairs:
    ///
    /// ```text
    ///     prod_i e(r_i pk_i, H(m_i)) * e(-G1, sum_i r_i sig_i) = 1
    /// ```
    ///
    /// The consensus layer has no randomness source, so the coefficients come from SHA-256.
    /// The hash covers every signature, key, and message of the batch, in order.
    ///
    /// # Invariants
    ///
    /// Acceptance implies every set is valid, except with probability at most q / 2^128.
    ///
    /// Write each signature as sig_i = sk_i H(m_i) + D_i, where D_i in G2 is its error.
    /// Bilinearity collapses the product to e(G1, sum_i r_i D_i).
    /// G2 is cyclic of prime order r, so with D_i = d_i g the check passes iff sum_i r_i d_i = 0 mod r.
    ///
    /// Suppose some d_j is nonzero.
    /// For any fixed values of the other coefficients, exactly one residue of r_j passes.
    /// Each r_j is a 128-bit hash output, so one attempt passes with probability at most 2^-128.
    ///
    /// The forger fixes the batch before learning the coefficients, as in Fiat-Shamir.
    /// Grinding over q batches therefore succeeds with probability at most q / 2^128.
    /// That is why the coefficients carry 128 bits rather than the 64 that suffice with a private random source.
    #[must_use]
    pub fn verify_batch(sets: &[Self]) -> bool {
        match sets {
            [] => true,
            // A single set gains nothing from a linear combination.
            [set] => set.verify(),
            _ => Self::verify_combined(sets),
        }
    }

    /// Runs the random linear combination check on two or more sets.
    fn verify_combined(sets: &[Self]) -> bool {
        let coefficients = Self::coefficients(sets);

        // G1 side: scale each key by its coefficient.
        // Short scalars make variable time cheap.
        let scaled_keys: Vec<G1Projective> = sets
            .iter()
            .zip(&coefficients)
            .map(|(set, coefficient)| {
                G1Projective::from(set.public_key.as_point()).mul_vartime(coefficient)
            })
            .collect();

        // G2 side: one multi-scalar multiplication combines all signatures.
        let signatures: Vec<G2Affine> = sets.iter().map(|set| *set.signature.as_point()).collect();
        let combined = G2Affine::from(G2Projective::multi_exp(&signatures, &coefficients));

        // Hash every message, then normalize every point with one inversion per group.
        let hashes: Vec<G2Projective> = sets
            .iter()
            .map(|set| G2Projective::hash_to_curve(&set.message, DST))
            .collect();
        let scaled_keys = G1Projective::batch_normalize(&scaled_keys);
        let hashes = G2Projective::batch_normalize(&hashes);

        // n + 1 pairs share one Miller loop and one final exponentiation.
        let mut terms: Vec<(G1Affine, G2Affine)> = scaled_keys.into_iter().zip(hashes).collect();
        terms.push((-G1Affine::GENERATOR, combined));
        Gt::multi_pairing(&terms).is_identity()
    }

    /// Derives one nonzero 128-bit coefficient per set from a hash of the whole batch.
    fn coefficients(sets: &[Self]) -> Vec<Scalar> {
        // Phase 1: a seed that commits to every input, length first so batches cannot be re-split.
        let mut hasher = Sha256::new();
        hasher.update(BATCH_DOMAIN);
        hasher.update(u64::try_from(sets.len()).unwrap_or(u64::MAX).to_be_bytes());
        for set in sets {
            hasher.update(set.signature.to_bytes());
            hasher.update(set.public_key.to_bytes());
            hasher.update(set.message);
        }
        let seed = hasher.finalize();

        // Phase 2: r_i = the first 16 bytes of SHA-256(seed || i), as a big-endian integer.
        (0_u64..)
            .zip(sets)
            .map(|(index, _)| {
                let digest = Sha256::new()
                    .chain_update(seed)
                    .chain_update(index.to_be_bytes())
                    .finalize();
                let mut bytes = [0_u8; 32];
                bytes[32 - COEFFICIENT_BYTES..].copy_from_slice(&digest[..COEFFICIENT_BYTES]);
                // 2^128 < r, so the integer is canonical.
                // Zero would drop the set, so it becomes one.
                let coefficient = Scalar::from_bytes_be_reduced(&bytes);
                if coefficient.is_zero() {
                    Scalar::ONE
                } else {
                    coefficient
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::mem;

    use proptest::prelude::*;

    use super::*;
    use crate::SecretKey;

    /// A valid set: key number seed signs a message derived from the same seed.
    fn valid_set(seed: u8) -> SignatureSet {
        // Clearing the top two bits keeps the integer below r = 0x73ed...
        let mut secret = [seed; 32];
        secret[0] &= 0x3f;
        let key = SecretKey::from_bytes(&secret).unwrap();
        let message = [seed.wrapping_mul(7); 32];
        SignatureSet {
            signature: key.sign(&message),
            public_key: key.public_key(),
            message,
        }
    }

    #[test]
    fn empty_batch_is_valid() {
        assert!(SignatureSet::verify_batch(&[]));
    }

    #[test]
    fn coefficients_are_deterministic_and_distinct() {
        // Fixture state: three valid sets.
        let sets = [valid_set(1), valid_set(2), valid_set(3)];
        let first = SignatureSet::coefficients(&sets);
        // The same batch always yields the same coefficients.
        assert_eq!(first, SignatureSet::coefficients(&sets));
        // Distinct indices give distinct coefficients.
        assert_ne!(first[0], first[1]);
        assert_ne!(first[1], first[2]);

        // Mutation: reordering the batch changes the seed, hence every coefficient.
        let reordered = [valid_set(2), valid_set(1), valid_set(3)];
        assert_ne!(SignatureSet::coefficients(&reordered)[2], first[2]);
    }

    #[test]
    fn swapped_signatures_fail_together() {
        // Fixture state: two valid sets.
        let mut sets = [valid_set(4), valid_set(5)];
        assert!(SignatureSet::verify_batch(&sets));

        // Mutation: exchange the signatures.
        // Each set alone is now invalid.
        //
        //     set 0: sig_5 over m_4 under pk_4
        //     set 1: sig_4 over m_5 under pk_5
        // The plain sum of signatures is unchanged, so only the coefficients catch this.
        let [first, second] = &mut sets;
        mem::swap(&mut first.signature, &mut second.signature);
        assert!(!SignatureSet::verify_batch(&sets));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn batch_agrees_with_individual_checks(
            seeds in proptest::collection::vec(1_u8..=255, 1..5),
            tamper in proptest::option::of(0_usize..5),
        ) {
            let mut sets: Vec<SignatureSet> = seeds.iter().map(|seed| valid_set(*seed)).collect();

            // Mutation: optionally move one message off its signature.
            if let Some(index) = tamper.filter(|index| *index < sets.len()) {
                sets[index].message[0] ^= 1;
            }

            let individually = sets.iter().all(SignatureSet::verify);
            prop_assert_eq!(SignatureSet::verify_batch(&sets), individually);
        }
    }
}
