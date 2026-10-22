//! EIP-4844: blob commitments, and openings at one point, alone or in batches.
//!
//! See `specs/deneb/polynomial-commitments.md` of the consensus specs.

use axiom_bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};

use super::opening::Opening;
use crate::{
    Blob, Bytes32, Bytes48, FIELD_ELEMENTS_PER_BLOB, KzgError, basis::Basis, fft::Domain,
    parallel::Threads, powers::Powers,
};

/// The EIP-4844 prover and verifier: commitments to blobs and their openings at single points.
#[derive(Clone, Debug)]
pub(super) struct BlobScheme {
    /// The Lagrange basis in bit-reversal order, matching the order of blob evaluations.
    lagrange_brp: Basis,
    /// The secret in G2, [s]_2, which every opening check pairs against.
    s_g2: G2Affine,
    /// The 4096-th roots of unity in bit-reversal order, matching the order of blob evaluations.
    roots_brp: Vec<Scalar>,
    /// The inverse of the blob size, 1 / 4096.
    size_inverse: Scalar,
}

impl BlobScheme {
    /// Builds the scheme from its setup points and the blob domain.
    pub(super) fn new(lagrange_brp: Basis, s_g2: G2Affine, domain: &Domain) -> Self {
        // The spec stores blob evaluations at the bit-reversed roots, so the roots follow suit.
        let mut roots_brp = domain.roots().to_vec();
        domain.bit_reversal().permute(&mut roots_brp);
        Self {
            lagrange_brp,
            s_g2,
            roots_brp,
            size_inverse: domain.size_inverse(),
        }
    }

    /// Commits to a blob, blob_to_kzg_commitment in the Deneb spec.
    ///
    /// ```text
    ///     [f(s)] = sum_i f(omega_i) [L_i(s)]
    /// ```
    pub(super) fn commit(&self, blob: &Blob) -> Bytes48 {
        Bytes48::from_point(&self.lagrange_brp.commit(blob.evaluations()))
    }

    /// Opens the blob at z, compute_kzg_proof in the Deneb spec.
    pub(super) fn compute_kzg_proof(
        &self,
        blob: &Blob,
        z: &Bytes32,
    ) -> Result<(Bytes48, Bytes32), KzgError> {
        let z = z.to_scalar()?;
        let (proof, y) = self.open(blob, &z);
        Ok((Bytes48::from_point(&proof), Bytes32::from_scalar(&y)))
    }

    /// Opens the blob at its Fiat-Shamir challenge, compute_blob_kzg_proof in the Deneb spec.
    pub(super) fn compute_blob_kzg_proof(
        &self,
        blob: &Blob,
        commitment: &Bytes48,
    ) -> Result<Bytes48, KzgError> {
        commitment.to_commitment()?;
        let z = blob.challenge(commitment);
        let (proof, _) = self.open(blob, &z);
        Ok(Bytes48::from_point(&proof))
    }

    /// Checks one opening given as bytes, verify_kzg_proof in the Deneb spec.
    pub(super) fn verify_kzg_proof(
        &self,
        commitment: &Bytes48,
        z: &Bytes32,
        y: &Bytes32,
        proof: &Bytes48,
    ) -> Result<bool, KzgError> {
        let commitment = commitment.to_commitment()?;
        let z = z.to_scalar()?;
        let y = y.to_scalar()?;
        let proof = proof.to_proof()?;
        Ok(self.check_opening(&commitment, &z, &y, &proof))
    }

    /// Checks one blob proof, verify_blob_kzg_proof in the Deneb spec.
    pub(super) fn verify_blob_kzg_proof(
        &self,
        blob: &Blob,
        commitment: &Bytes48,
        proof: &Bytes48,
    ) -> Result<bool, KzgError> {
        let opening = self.blob_opening(blob, commitment, proof)?;
        Ok(self.check_opening(&opening.commitment, &opening.z, &opening.y, &opening.proof))
    }

    /// Checks many blob proofs at once, verify_blob_kzg_proof_batch in the Deneb spec.
    pub(super) fn verify_blob_kzg_proof_batch(
        &self,
        blobs: &[Blob],
        commitments: &[Bytes48],
        proofs: &[Bytes48],
    ) -> Result<bool, KzgError> {
        KzgError::check_paired(blobs.len(), &[commitments.len(), proofs.len()])?;

        // Each blob needs a challenge hash and a barycentric evaluation, independent of the others.
        let triples: Vec<(&Blob, &Bytes48, &Bytes48)> = blobs
            .iter()
            .zip(commitments)
            .zip(proofs)
            .map(|((blob, commitment), proof)| (blob, commitment, proof))
            .collect();
        let openings: Result<Vec<Opening<'_>>, KzgError> = Threads::available()
            .map(&triples, |(blob, commitment, proof)| {
                self.blob_opening(blob, commitment, proof)
            });
        Ok(self.check_openings(&openings?))
    }

    /// Decodes a blob opening and computes its challenge and evaluation.
    fn blob_opening<'a>(
        &self,
        blob: &Blob,
        commitment: &'a Bytes48,
        proof: &'a Bytes48,
    ) -> Result<Opening<'a>, KzgError> {
        // The spec validates the commitment, derives z and y, then validates the proof.
        let commitment_point = commitment.to_commitment()?;
        let z = blob.challenge(commitment);
        let y = self.evaluate(blob, &z);
        let proof_point = proof.to_proof()?;
        Ok(Opening {
            commitment_bytes: commitment,
            proof_bytes: proof,
            commitment: commitment_point,
            proof: proof_point,
            z,
            y,
        })
    }

    /// Evaluates the blob's polynomial at any point.
    ///
    /// See evaluate_polynomial_in_evaluation_form in the Deneb spec.
    ///
    /// # Algorithm
    ///
    /// Off the domain, the barycentric formula over the n = 4096 roots omega_i:
    ///
    /// ```text
    ///     f(z) = (z^n - 1) / n * sum_i f_i omega_i / (z - omega_i)
    /// ```
    ///
    /// On the domain, the stored evaluation, since the formula would divide by zero.
    fn evaluate(&self, blob: &Blob, z: &Scalar) -> Scalar {
        let evaluations = blob.evaluations();
        let roots = &self.roots_brp;

        // z = omega_i: the answer is stored.
        if let Some(index) = roots.iter().position(|root| root == z) {
            return evaluations[index];
        }

        // Every z - omega_i is nonzero now, so one batch inversion serves all 4096 terms.
        let mut inverses: Vec<Scalar> = roots.iter().map(|root| z - root).collect();
        Scalar::batch_invert(&mut inverses);
        let sum = evaluations
            .iter()
            .zip(roots)
            .zip(&inverses)
            .fold(Scalar::ZERO, |acc, ((value, root), inverse)| {
                acc + value * root * inverse
            });

        // The prefactor (z^n - 1) / n, with z^n by 12 squarings.
        let z_to_n =
            (0..FIELD_ELEMENTS_PER_BLOB.trailing_zeros()).fold(*z, |power, _| power.square());
        sum * (z_to_n - Scalar::ONE) * self.size_inverse
    }

    /// Computes the opening proof at z and the evaluation y, compute_kzg_proof_impl in the Deneb spec.
    ///
    /// # Algorithm
    ///
    /// The quotient q(X) = (f(X) - y) / (X - z), in evaluation form, then committed:
    ///
    /// ```text
    ///     q(omega_i) = (f_i - y) / (omega_i - z)                          omega_i != z
    ///     q(omega_m) = sum_{i != m} (f_i - y) omega_i / (z (z - omega_i))     omega_m = z
    /// ```
    ///
    /// The second line is the derivative rule at a root, from Feist, "PCS multiproofs using random evaluation".
    fn open(&self, blob: &Blob, z: &Scalar) -> (G1Projective, Scalar) {
        let evaluations = blob.evaluations();
        let roots = &self.roots_brp;
        let y = self.evaluate(blob, z);

        // Phase 1: invert every omega_i - z at once.
        // A zero entry marks z on the domain, and batch inversion leaves it zero.
        let mut inverses: Vec<Scalar> = roots.iter().map(|root| root - z).collect();
        let on_domain = inverses.iter().position(Scalar::is_zero);
        Scalar::batch_invert(&mut inverses);

        // Phase 2: the quotient off the root, (f_i - y) / (omega_i - z).
        // At the root itself the inverse is zero, so the entry is zero until phase 3.
        let mut quotient: Vec<Scalar> = evaluations
            .iter()
            .zip(&inverses)
            .map(|(value, inverse)| (value - &y) * inverse)
            .collect();

        // Phase 3: at omega_m = z, sum the derivative terms.
        //
        //     1 / (z - omega_i) = -1 / (omega_i - z)
        //     q(omega_m) = -(1 / z) sum_{i != m} (f_i - y) omega_i / (omega_i - z)
        if let Some(m) = on_domain {
            let sum = quotient
                .iter()
                .zip(roots)
                .enumerate()
                .filter(|(i, _)| *i != m)
                .fold(Scalar::ZERO, |acc, (_, (term, root))| acc + term * root);
            // z is a root of unity here, so it is nonzero and invertible.
            let z_inverse = z.invert().unwrap_or(Scalar::ZERO);
            quotient[m] = -(sum * z_inverse);
        }

        (self.lagrange_brp.commit(&quotient), y)
    }

    /// The pairing check of one opening, verify_kzg_proof_impl in the Deneb spec.
    ///
    /// ```text
    ///     e(C - [y], -[1]_2) * e(pi, [s]_2 - [z]_2) = 1
    ///     <=>  C - [y] = [q(s) (s - z)]
    /// ```
    fn check_opening(
        &self,
        commitment: &G1Affine,
        z: &Scalar,
        y: &Scalar,
        proof: &G1Affine,
    ) -> bool {
        let s_minus_z = G2Projective::from(self.s_g2) - G2Projective::GENERATOR.mul_vartime(z);
        let c_minus_y = G1Projective::from(commitment) - G1Projective::GENERATOR.mul_vartime(y);
        Gt::multi_pairing(&[
            (G1Affine::from(c_minus_y), -G2Affine::GENERATOR),
            (*proof, G2Affine::from(s_minus_z)),
        ])
        .is_identity()
    }

    /// The batched pairing check of many openings, verify_kzg_proof_batch in the Deneb spec.
    ///
    /// # Algorithm
    ///
    /// Each opening satisfies pi_i (s - z_i) = C_i - [y_i].
    /// A random combination with powers of r folds them into one equation:
    ///
    /// ```text
    ///     e( sum r^i pi_i, [s]_2 ) = e( sum r^i (C_i - [y_i]) + sum r^i z_i pi_i, [1]_2 )
    /// ```
    ///
    /// A false opening survives only if r is a root of a nonzero polynomial of degree n - 1.
    /// The challenge hashes every input, so that happens with probability at most n / r.
    fn check_openings(&self, openings: &[Opening<'_>]) -> bool {
        if openings.is_empty() {
            return true;
        }

        // Phase 1: the coefficients r^0, r^1, ..., r^{n-1}.
        let r = Opening::batch_challenge(openings);
        let r_powers: Vec<Scalar> = Powers::new(r).take(openings.len()).collect();

        // Phase 2: the three combinations, as MSMs.
        let proofs: Vec<G1Affine> = openings.iter().map(|opening| opening.proof).collect();
        let commitments: Vec<G1Affine> =
            openings.iter().map(|opening| opening.commitment).collect();
        let z_weights: Vec<Scalar> = openings
            .iter()
            .zip(&r_powers)
            .map(|(opening, power)| opening.z * power)
            .collect();
        let y_sum = openings
            .iter()
            .zip(&r_powers)
            .fold(Scalar::ZERO, |acc, (opening, power)| {
                acc + opening.y * power
            });

        let proof_lincomb = G1Projective::multi_exp(&proofs, &r_powers);
        let proof_z_lincomb = G1Projective::multi_exp(&proofs, &z_weights);
        // One MSM and one scalar multiplication replace n subtractions.
        //
        //     sum r^i (C_i - [y_i]) = sum r^i C_i - [sum r^i y_i]
        let c_minus_y_lincomb = G1Projective::multi_exp(&commitments, &r_powers)
            - G1Projective::GENERATOR.mul_vartime(&y_sum);

        // Phase 3: one product of two pairings.
        Gt::multi_pairing(&[
            (G1Affine::from(proof_lincomb), -self.s_g2),
            (
                G1Affine::from(c_minus_y_lincomb + proof_z_lincomb),
                G2Affine::GENERATOR,
            ),
        ])
        .is_identity()
    }
}

#[cfg(test)]
mod tests {
    use proptest::{collection::vec, prelude::*};

    use super::*;
    use crate::{
        Kzg,
        blob::tests::{arb_blob, blob_from_seed},
        setup::TrustedSetup,
    };

    #[test]
    fn evaluation_on_and_off_the_domain_agree_with_the_coefficients() {
        // Fixture state: the blob of f(X) = X, so its evaluation at any z is z itself.
        // Element i stores f(omega_{rev(i)}) = omega_{rev(i)}.
        let scheme = &Kzg::mainnet().blobs;
        let bytes: Vec<u8> = scheme
            .roots_brp
            .iter()
            .flat_map(Scalar::to_bytes_be)
            .collect();
        let blob = Blob::from_bytes(&bytes).unwrap();

        // Off the domain: z = 5 goes through the barycentric formula.
        assert_eq!(
            scheme.evaluate(&blob, &Scalar::from_u64(5)),
            Scalar::from_u64(5)
        );
        // On the domain: z = omega_7 reads the stored value.
        let root = Domain::new(12).roots()[7];
        assert_eq!(scheme.evaluate(&blob, &root), root);
    }

    #[test]
    fn opening_on_the_domain_uses_the_derivative_rule() {
        // Fixture state: f(X) = X^2, whose quotient at z is (X^2 - z^2) / (X - z) = X + z.
        let scheme = &Kzg::mainnet().blobs;
        let bytes: Vec<u8> = scheme
            .roots_brp
            .iter()
            .flat_map(|root| root.square().to_bytes_be())
            .collect();
        let blob = Blob::from_bytes(&bytes).unwrap();

        // z = omega_3 is on the domain, so the quotient entry at omega_3 needs the special case.
        let z = Domain::new(12).roots()[3];
        let (proof, y) = scheme.open(&blob, &z);
        assert_eq!(y, z.square());

        // The quotient X + z commits to [s] + z [1].
        let s = TrustedSetup::mainnet().g1_monomial.points()[1];
        let expected = G1Projective::from(s) + G1Projective::GENERATOR.mul_vartime(&z);
        assert_eq!(proof, expected);
    }

    /// A field element below 2^254, as 32 big-endian bytes.
    fn arb_field_element() -> impl Strategy<Value = Bytes32> {
        any::<[u8; 32]>().prop_map(|mut bytes| {
            bytes[0] &= 0x3f;
            Bytes32(bytes)
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn opening_round_trips(blob in arb_blob(), z in arb_field_element()) {
            let kzg = Kzg::mainnet();
            let commitment = kzg.blob_to_kzg_commitment(&blob);

            // Completeness: an honest opening at any z verifies.
            let (proof, y) = kzg.compute_kzg_proof(&blob, &z).unwrap();
            prop_assert_eq!(kzg.verify_kzg_proof(&commitment, &z, &y, &proof), Ok(true));

            // Mutation: the claimed value moves from y to y + 1 (the low byte of a value below 2^254 + 1).
            //
            //     pi (s - z) = C - [y]  holds,  so  C - [y + 1] has no matching proof.
            let mut wrong = y;
            let (sum, carry) = wrong.0[31].overflowing_add(1);
            wrong.0[31] = sum;
            prop_assume!(!carry);
            prop_assert_eq!(kzg.verify_kzg_proof(&commitment, &z, &wrong, &proof), Ok(false));
        }

        #[test]
        fn blob_proof_round_trips(blob in arb_blob(), other in arb_blob()) {
            prop_assume!(blob != other);
            let kzg = Kzg::mainnet();
            let commitment = kzg.blob_to_kzg_commitment(&blob);
            let proof = kzg.compute_blob_kzg_proof(&blob, &commitment).unwrap();

            // Completeness: the blob verifies against its own commitment and proof.
            prop_assert_eq!(kzg.verify_blob_kzg_proof(&blob, &commitment, &proof), Ok(true));
            // Soundness spot check: a different blob under the same commitment fails.
            prop_assert_eq!(kzg.verify_blob_kzg_proof(&other, &commitment, &proof), Ok(false));
        }

        #[test]
        fn blob_batch_equals_individual_checks(
            seeds in vec(any::<u64>(), 1..4),
            corrupt in vec(any::<bool>(), 4),
        ) {
            let kzg = Kzg::mainnet();
            let blobs: Vec<Blob> = seeds.into_iter().map(blob_from_seed).collect();
            let commitments: Vec<Bytes48> = blobs.iter().map(|blob| kzg.blob_to_kzg_commitment(blob)).collect();
            let mut proofs: Vec<Bytes48> = blobs
                .iter()
                .zip(&commitments)
                .map(|(blob, commitment)| kzg.compute_blob_kzg_proof(blob, commitment).unwrap())
                .collect();

            // Mutation: a flagged entry takes the proof of the generator, valid as a point, wrong as a proof.
            let generator = Bytes48(G1Affine::GENERATOR.to_compressed());
            for (proof, flag) in proofs.iter_mut().zip(&corrupt) {
                if *flag {
                    *proof = generator;
                }
            }

            // The batch accepts exactly when every single check accepts.
            let individual = blobs
                .iter()
                .zip(&commitments)
                .zip(&proofs)
                .all(|((blob, commitment), proof)| kzg.verify_blob_kzg_proof(blob, commitment, proof) == Ok(true));
            prop_assert_eq!(kzg.verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs), Ok(individual));
        }
    }
}
