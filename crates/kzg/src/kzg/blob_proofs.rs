//! EIP-4844: blob commitments, and openings at one point, alone or in batches.
//!
//! See `specs/deneb/polynomial-commitments.md` of the consensus specs.

use axiom_bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};

use super::Kzg;
use crate::{
    Blob, Bytes32, Bytes48, FIELD_ELEMENTS_PER_BLOB, KzgError, parallel,
    transcript::{OpeningClaim, batch_challenge, blob_challenge},
};

/// One opening with its points decoded, ready for the pairing check.
#[derive(Clone, Copy, Debug)]
struct Opening<'a> {
    /// The claim, with the bytes the transcript hashes.
    claim: OpeningClaim<'a>,
    /// The decoded commitment.
    commitment: G1Affine,
    /// The decoded proof.
    proof: G1Affine,
}

impl Kzg {
    /// Commits to a blob: [f(s)] for the polynomial its evaluations define.
    ///
    /// The Lagrange basis turns the commitment into one MSM over the evaluations.
    ///
    /// ```text
    ///     [f(s)] = sum_i f(omega_i) [L_i(s)]
    /// ```
    ///
    /// See blob_to_kzg_commitment in the Deneb spec.
    #[must_use]
    pub fn blob_to_kzg_commitment(&self, blob: &Blob) -> Bytes48 {
        Bytes48::from_point(&self.commit_evaluations(blob.evaluations()))
    }

    /// Opens the blob's polynomial at z.
    ///
    /// See compute_kzg_proof in the Deneb spec.
    ///
    /// # Returns
    ///
    /// The proof and the evaluation y = f(z).
    ///
    /// # Errors
    ///
    /// Fails when z is not a canonical field element.
    pub fn compute_kzg_proof(
        &self,
        blob: &Blob,
        z: &Bytes32,
    ) -> Result<(Bytes48, Bytes32), KzgError> {
        let z = z.to_scalar()?;
        let (proof, y) = self.open(blob, &z);
        Ok((Bytes48::from_point(&proof), Bytes32::from_scalar(&y)))
    }

    /// Opens the blob at the Fiat-Shamir challenge derived from the blob and its commitment.
    ///
    /// The commitment is only validated, never checked against the blob.
    ///
    /// See compute_blob_kzg_proof in the Deneb spec.
    ///
    /// # Errors
    ///
    /// Fails when the commitment is not a point of G1.
    pub fn compute_blob_kzg_proof(
        &self,
        blob: &Blob,
        commitment: &Bytes48,
    ) -> Result<Bytes48, KzgError> {
        commitment.to_commitment()?;
        let z = blob_challenge(blob, commitment);
        let (proof, _) = self.open(blob, &z);
        Ok(Bytes48::from_point(&proof))
    }

    /// Checks a proof that the committed polynomial takes the value y at z.
    ///
    /// See verify_kzg_proof in the Deneb spec.
    ///
    /// # Errors
    ///
    /// Fails when a point or a field element is malformed.
    /// A well-formed but wrong proof returns false.
    pub fn verify_kzg_proof(
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

    /// Checks a blob proof: the opening at the challenge matches the blob's own evaluation there.
    ///
    /// See verify_blob_kzg_proof in the Deneb spec.
    ///
    /// # Errors
    ///
    /// Fails when the commitment or the proof is not a point of G1.
    pub fn verify_blob_kzg_proof(
        &self,
        blob: &Blob,
        commitment: &Bytes48,
        proof: &Bytes48,
    ) -> Result<bool, KzgError> {
        let opening = self.blob_opening(blob, commitment, proof)?;
        Ok(self.check_opening(
            &opening.commitment,
            &opening.claim.z,
            &opening.claim.y,
            &opening.proof,
        ))
    }

    /// Checks many blob proofs with one pairing check, true for an empty batch.
    ///
    /// See verify_blob_kzg_proof_batch in the Deneb spec.
    ///
    /// # Errors
    ///
    /// Fails when the lists differ in length or any point is malformed.
    pub fn verify_blob_kzg_proof_batch(
        &self,
        blobs: &[Blob],
        commitments: &[Bytes48],
        proofs: &[Bytes48],
    ) -> Result<bool, KzgError> {
        check_lengths(blobs.len(), &[commitments.len(), proofs.len()])?;

        // Each blob needs a challenge hash and a barycentric evaluation, independent of the others.
        let triples: Vec<(&Blob, &Bytes48, &Bytes48)> = blobs
            .iter()
            .zip(commitments)
            .zip(proofs)
            .map(|((blob, commitment), proof)| (blob, commitment, proof))
            .collect();
        let openings = parallel::map(&triples, |(blob, commitment, proof)| {
            self.blob_opening(blob, commitment, proof)
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
        Ok(self.check_openings(&openings))
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
        let z = blob_challenge(blob, commitment);
        let y = self.evaluate(blob, &z);
        let proof_point = proof.to_proof()?;
        Ok(Opening {
            claim: OpeningClaim {
                commitment,
                z,
                y,
                proof,
            },
            commitment: commitment_point,
            proof: proof_point,
        })
    }

    /// Commits to evaluations in bit-reversal order with the matching Lagrange basis.
    fn commit_evaluations(&self, evaluations: &[Scalar]) -> G1Projective {
        parallel::multi_exp(&self.setup.g1_lagrange_brp, evaluations)
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
        let roots = &self.blob_roots_brp;

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
        sum * (z_to_n - Scalar::ONE) * self.blob_domain.size_inverse()
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
        let roots = &self.blob_roots_brp;
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

        (self.commit_evaluations(&quotient), y)
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
        let s_minus_z =
            G2Projective::from(self.setup.g2_monomial[1]) - G2Projective::GENERATOR.mul_vartime(z);
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
        let claims: Vec<OpeningClaim<'_>> = openings.iter().map(|opening| opening.claim).collect();
        let r = batch_challenge(&claims);
        let r_powers = powers(&r, openings.len());

        // Phase 2: the three combinations, as MSMs.
        let proofs: Vec<G1Affine> = openings.iter().map(|opening| opening.proof).collect();
        let commitments: Vec<G1Affine> =
            openings.iter().map(|opening| opening.commitment).collect();
        let z_weights: Vec<Scalar> = claims
            .iter()
            .zip(&r_powers)
            .map(|(claim, power)| claim.z * power)
            .collect();
        let y_sum = claims
            .iter()
            .zip(&r_powers)
            .fold(Scalar::ZERO, |acc, (claim, power)| acc + claim.y * power);

        let proof_lincomb = G1Projective::multi_exp(&proofs, &r_powers);
        let proof_z_lincomb = G1Projective::multi_exp(&proofs, &z_weights);
        // One MSM and one scalar multiplication replace n subtractions.
        //
        //     sum r^i (C_i - [y_i]) = sum r^i C_i - [sum r^i y_i]
        let c_minus_y_lincomb = G1Projective::multi_exp(&commitments, &r_powers)
            - G1Projective::GENERATOR.mul_vartime(&y_sum);

        // Phase 3: one product of two pairings.
        Gt::multi_pairing(&[
            (G1Affine::from(proof_lincomb), -self.setup.g2_monomial[1]),
            (
                G1Affine::from(c_minus_y_lincomb + proof_z_lincomb),
                G2Affine::GENERATOR,
            ),
        ])
        .is_identity()
    }
}

/// The powers x^0, ..., x^{n-1}, compute_powers in the Deneb spec.
pub(super) fn powers(x: &Scalar, count: usize) -> Vec<Scalar> {
    let mut power = Scalar::ONE;
    (0..count)
        .map(|_| {
            let current = power;
            power *= x;
            current
        })
        .collect()
}

/// Checks that paired lists all have the length of the first.
pub(super) fn check_lengths(expected: usize, others: &[usize]) -> Result<(), KzgError> {
    match others.iter().find(|actual| **actual != expected) {
        Some(&actual) => Err(KzgError::LengthMismatch { expected, actual }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluation_on_and_off_the_domain_agree_with_the_coefficients() {
        // Fixture state: the blob of f(X) = X, so its evaluation at any z is z itself.
        // Element i stores f(omega_{rev(i)}) = omega_{rev(i)}.
        let kzg = Kzg::mainnet();
        let bytes: Vec<u8> = kzg
            .blob_roots_brp
            .iter()
            .flat_map(Scalar::to_bytes_be)
            .collect();
        let blob = Blob::from_bytes(&bytes).unwrap();

        // Off the domain: z = 5 goes through the barycentric formula.
        assert_eq!(
            kzg.evaluate(&blob, &Scalar::from_u64(5)),
            Scalar::from_u64(5)
        );
        // On the domain: z = omega_7 reads the stored value.
        let root = kzg.blob_domain.roots()[7];
        assert_eq!(kzg.evaluate(&blob, &root), root);
    }

    #[test]
    fn opening_on_the_domain_uses_the_derivative_rule() {
        // Fixture state: f(X) = X^2, whose quotient at z is (X^2 - z^2) / (X - z) = X + z.
        let kzg = Kzg::mainnet();
        let bytes: Vec<u8> = kzg
            .blob_roots_brp
            .iter()
            .flat_map(|root| root.square().to_bytes_be())
            .collect();
        let blob = Blob::from_bytes(&bytes).unwrap();

        // z = omega_3 is on the domain, so the quotient entry at omega_3 needs the special case.
        let z = kzg.blob_domain.roots()[3];
        let (proof, y) = kzg.open(&blob, &z);
        assert_eq!(y, z.square());

        // The quotient X + z commits to [s] + z [1].
        let expected =
            G1Projective::from(kzg.setup.g1_monomial[1]) + G1Projective::GENERATOR.mul_vartime(&z);
        assert_eq!(proof, expected);
    }

    #[test]
    fn lengths_must_match_the_first_list() {
        // The second list of three, the first of two, is the reported mismatch.
        assert_eq!(
            check_lengths(2, &[2, 3]),
            Err(KzgError::LengthMismatch {
                expected: 2,
                actual: 3
            })
        );
        assert_eq!(check_lengths(2, &[2, 2]), Ok(()));
    }
}
