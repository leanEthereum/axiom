//! Fiat-Shamir challenges: hashes of everything a prover sent, reduced to field elements.
//!
//! Each transcript starts with a 16-byte domain tag, so challenges of different protocols never collide.
//! The verifier derives the challenge itself, so a prover cannot choose it after the fact.

use axiom_bls12_381::Scalar;
use sha2::{Digest, Sha256};

use crate::{
    Blob, Bytes32, Bytes48, CellIndex, FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL,
    bytes::encode_field_elements,
};

/// Domain tag of the blob evaluation challenge, FIAT_SHAMIR_PROTOCOL_DOMAIN in the Deneb spec.
const FIAT_SHAMIR_PROTOCOL_DOMAIN: &[u8; 16] = b"FSBLOBVERIFY_V1_";

/// Domain tag of the blob batch coefficient, RANDOM_CHALLENGE_KZG_BATCH_DOMAIN in the Deneb spec.
const RANDOM_CHALLENGE_KZG_BATCH_DOMAIN: &[u8; 16] = b"RCKZGBATCH___V1_";

/// Domain tag of the cell batch coefficient, RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN in the Fulu spec.
const RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN: &[u8; 16] = b"RCKZGCBATCH__V1_";

/// One opening of a batch: the claim f(z) = y for the committed f, with its proof.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpeningClaim<'a> {
    /// The commitment, as received.
    pub(crate) commitment: &'a Bytes48,
    /// The evaluation point.
    pub(crate) z: Scalar,
    /// The claimed evaluation.
    pub(crate) y: Scalar,
    /// The proof, as received.
    pub(crate) proof: &'a Bytes48,
}

/// Hashes the transcript and reduces the digest modulo r, as hash_to_bls_field does.
///
/// The output is not uniform: some residues have three preimages, others two.
/// Soundness only needs each value to be unlikely, and none has probability above 2^-254.
fn finish(hasher: Sha256) -> Scalar {
    Scalar::from_bytes_be_reduced(&hasher.finalize().into())
}

/// The evaluation point of a blob opening, compute_challenge in the Deneb spec.
///
/// ```text
///     SHA-256( tag || 4096 as u128 || blob || commitment )  mod r
/// ```
pub(crate) fn blob_challenge(blob: &Blob, commitment: &Bytes48) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(FIAT_SHAMIR_PROTOCOL_DOMAIN);
    // The polynomial degree bound, as a 16-byte big-endian integer.
    hasher.update((FIELD_ELEMENTS_PER_BLOB as u128).to_be_bytes());
    hasher.update(blob.to_bytes());
    hasher.update(commitment.0);
    finish(hasher)
}

/// The coefficient r of the random linear combination of openings, from verify_kzg_proof_batch.
///
/// ```text
///     SHA-256( tag || 4096 as u64 || n as u64 || (commitment || z || y || proof) for each )  mod r
/// ```
pub(crate) fn batch_challenge(claims: &[OpeningClaim<'_>]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(RANDOM_CHALLENGE_KZG_BATCH_DOMAIN);
    hasher.update((FIELD_ELEMENTS_PER_BLOB as u64).to_be_bytes());
    hasher.update((claims.len() as u64).to_be_bytes());
    for claim in claims {
        hasher.update(claim.commitment.0);
        hasher.update(Bytes32::from_scalar(&claim.z).0);
        hasher.update(Bytes32::from_scalar(&claim.y).0);
        hasher.update(claim.proof.0);
    }
    finish(hasher)
}

/// The coefficient r of the cell batch, compute_verify_cell_kzg_proof_batch_challenge in the Fulu spec.
///
/// ```text
///     SHA-256( tag || 4096 || 64 || #commitments || #cells          (u64 each)
///              || commitments
///              || (commitment index || cell index || cell || proof) for each cell )  mod r
/// ```
///
/// The commitments are the deduplicated ones, and each cell names its commitment by position.
pub(crate) fn cell_batch_challenge(
    commitments: &[&Bytes48],
    commitment_indices: &[usize],
    cell_indices: &[CellIndex],
    cells: &[&[Scalar]],
    proofs: &[Bytes48],
) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN);
    hasher.update((FIELD_ELEMENTS_PER_BLOB as u64).to_be_bytes());
    hasher.update((FIELD_ELEMENTS_PER_CELL as u64).to_be_bytes());
    hasher.update((commitments.len() as u64).to_be_bytes());
    hasher.update((cell_indices.len() as u64).to_be_bytes());
    for commitment in commitments {
        hasher.update(commitment.0);
    }
    let rows = commitment_indices
        .iter()
        .zip(cell_indices)
        .zip(cells)
        .zip(proofs);
    for (((commitment_index, cell_index), cell), proof) in rows {
        hasher.update((*commitment_index as u64).to_be_bytes());
        hasher.update(cell_index.get().to_be_bytes());
        // Cells hold canonical elements, so re-encoding gives back the bytes received.
        hasher.update(encode_field_elements(cell));
        hasher.update(proof.0);
    }
    finish(hasher)
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        path::{Path, PathBuf},
    };

    use axiom_yaml::Yaml;

    use super::*;
    use crate::bytes::decode_field_elements;

    /// The c-kzg-4844 vectors of one handler, or none when the vectors are absent.
    ///
    /// The lookup mirrors the conformance suite: AXIOM_VECTORS, this checkout, then the main checkout.
    fn cases(handler: &str) -> Vec<Yaml> {
        let roots = [
            env::var_os("AXIOM_VECTORS").map(PathBuf::from),
            Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors")),
            Some(PathBuf::from(
                "/home/utilisateur/Documents/axiom/testing/vectors",
            )),
        ];
        let Some(directory) = roots
            .into_iter()
            .flatten()
            .map(|root| root.join("kzg/tests").join(handler).join("kzg-mainnet"))
            .find(|directory| directory.is_dir())
        else {
            return Vec::new();
        };
        fs::read_dir(directory)
            .unwrap()
            .map(|entry| {
                let text = fs::read_to_string(entry.unwrap().path().join("data.yaml")).unwrap();
                Yaml::parse(&text).unwrap()
            })
            .collect()
    }

    /// Reads a list of 48-byte strings.
    fn points(items: &[Yaml]) -> Vec<Bytes48> {
        items
            .iter()
            .map(|item| Bytes48(item.as_hex_array().unwrap()))
            .collect()
    }

    #[test]
    fn blob_challenge_matches_vectors() {
        // Each case hashes a blob and a commitment into the evaluation point.
        for case in cases("compute_challenge") {
            let input = case.get("input").unwrap();
            let blob_bytes = input.get("blob").and_then(Yaml::as_hex_bytes).unwrap();
            let blob = Blob::from_bytes(&blob_bytes).unwrap();
            let commitment = Bytes48(input.get("commitment").unwrap().as_hex_array().unwrap());
            let expected = case.get("output").unwrap().as_hex_array().unwrap();
            assert_eq!(blob_challenge(&blob, &commitment).to_bytes_be(), expected);
        }
    }

    #[test]
    fn cell_batch_challenge_matches_vectors() {
        // Each case lists deduplicated commitments, then one row per cell.
        for case in cases("compute_verify_cell_kzg_proof_batch_challenge") {
            let input = case.get("input").unwrap();
            let sequence = |key: &str| input.get(key).and_then(Yaml::as_sequence).unwrap();
            let commitments = points(sequence("commitments"));
            let commitment_refs: Vec<&Bytes48> = commitments.iter().collect();
            let commitment_indices: Vec<usize> = sequence("commitment_indices")
                .iter()
                .map(|item| usize::try_from(item.as_u64().unwrap()).unwrap())
                .collect();
            let cell_indices: Vec<CellIndex> = sequence("cell_indices")
                .iter()
                .map(|item| CellIndex::new(item.as_u64().unwrap()).unwrap())
                .collect();

            // Each coset is a list of 64 field elements, joined then decoded.
            let cells: Vec<Vec<Scalar>> = sequence("cosets_evals")
                .iter()
                .map(|evaluations| {
                    let bytes: Vec<u8> = evaluations
                        .as_sequence()
                        .unwrap()
                        .iter()
                        .flat_map(|item| item.as_hex_bytes().unwrap())
                        .collect();
                    decode_field_elements(&bytes).unwrap()
                })
                .collect();
            let cell_refs: Vec<&[Scalar]> = cells.iter().map(Vec::as_slice).collect();
            let proofs = points(sequence("proofs"));

            let challenge = cell_batch_challenge(
                &commitment_refs,
                &commitment_indices,
                &cell_indices,
                &cell_refs,
                &proofs,
            );
            let expected = case.get("output").unwrap().as_hex_array().unwrap();
            assert_eq!(challenge.to_bytes_be(), expected);
        }
    }
}
