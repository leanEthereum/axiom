//! Laws of the public API over random blobs: completeness, soundness spot checks, and agreement.
//!
//! Each case commits to a whole blob, so the case counts stay small.

use axiom_bls12_381::G1Affine;
use axiom_kzg::{
    BYTES_PER_BLOB, BYTES_PER_FIELD_ELEMENT, Blob, Bytes32, Bytes48, CELLS_PER_EXT_BLOB, Cell,
    CellIndex, Kzg,
};
use proptest::{
    collection::vec,
    prelude::*,
    sample::{Index, subsequence},
};

/// A blob from a seed: every element takes 32 pseudorandom bytes with the top two bits cleared.
///
/// Clearing them keeps each integer below 2^254 < r, so every element is canonical.
fn blob_from_seed(seed: u64) -> Blob {
    // Xorshift64 is enough to fill a blob with varied, reproducible bytes.
    let mut state = seed | 1;
    let mut bytes = vec![0_u8; BYTES_PER_BLOB];
    for chunk in bytes.as_chunks_mut::<8>().0 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *chunk = state.to_be_bytes();
    }
    for element in bytes.as_chunks_mut::<BYTES_PER_FIELD_ELEMENT>().0 {
        element[0] &= 0x3f;
    }
    Blob::from_bytes(&bytes).expect("every element is below 2^254")
}

/// Random blobs, drawn through their seeds.
fn arb_blob() -> impl Strategy<Value = Blob> {
    any::<u64>().prop_map(blob_from_seed)
}

/// A field element below 2^254, as 32 big-endian bytes.
fn arb_field_element() -> impl Strategy<Value = Bytes32> {
    any::<[u8; 32]>().prop_map(|mut bytes| {
        bytes[0] &= 0x3f;
        Bytes32(bytes)
    })
}

/// Every cell index.
fn all_indices() -> Vec<CellIndex> {
    (0..CELLS_PER_EXT_BLOB as u64)
        .map(|index| CellIndex::new(index).expect("index below 128"))
        .collect()
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn cells_extend_the_blob_and_verify(blob in arb_blob(), picked in subsequence(all_indices(), 1..12)) {
        let kzg = Kzg::mainnet();
        let commitment = kzg.blob_to_kzg_commitment(&blob);
        let (cells, proofs) = kzg.compute_cells_and_kzg_proofs(&blob);

        // The cells alone agree with the cells computed alongside proofs.
        prop_assert_eq!(&kzg.compute_cells(&blob), &cells);

        // Systematic code: the first 64 cells, concatenated, are the blob itself.
        let prefix: Vec<u8> = cells[..CELLS_PER_EXT_BLOB / 2].iter().flat_map(Cell::to_bytes).collect();
        prop_assert_eq!(prefix, blob.to_bytes());

        // Completeness: any subset of cells verifies in one batch.
        let chosen: Vec<Cell> = picked.iter().map(|index| cells[index.get() as usize].clone()).collect();
        let chosen_proofs: Vec<Bytes48> = picked.iter().map(|index| proofs[index.get() as usize]).collect();
        let commitments = vec![commitment; picked.len()];
        prop_assert_eq!(kzg.verify_cell_kzg_proof_batch(&commitments, &picked, &chosen, &chosen_proofs), Ok(true));

        // Mutation: the first chosen cell claims to sit at the next position.
        //
        //     cell k evaluated on coset k+1 is not the blob there, so the batch fails.
        let mut shifted = picked.clone();
        shifted[0] = CellIndex::new((picked[0].get() + 1) % CELLS_PER_EXT_BLOB as u64).unwrap();
        prop_assert_eq!(kzg.verify_cell_kzg_proof_batch(&commitments, &shifted, &chosen, &chosen_proofs), Ok(false));
    }

    #[test]
    fn cell_batch_equals_individual_checks(
        seeds in vec(any::<u64>(), 1..3),
        rows in vec((0..CELLS_PER_EXT_BLOB as u64, any::<Index>(), any::<bool>()), 1..6),
    ) {
        let kzg = Kzg::mainnet();
        let blobs: Vec<Blob> = seeds.into_iter().map(blob_from_seed).collect();
        let commitments: Vec<Bytes48> = blobs.iter().map(|blob| kzg.blob_to_kzg_commitment(blob)).collect();
        let extended: Vec<_> = blobs.iter().map(|blob| kzg.compute_cells_and_kzg_proofs(blob)).collect();

        // Fixture state: each row picks a blob and a cell, and maybe swaps in a wrong proof.
        // Rows may repeat a commitment, which exercises deduplication.
        let mut row_commitments = Vec::new();
        let mut indices = Vec::new();
        let mut cells = Vec::new();
        let mut proofs = Vec::new();
        for (cell, blob, corrupt) in rows {
            let blob = blob.index(blobs.len());
            let position = cell as usize;
            row_commitments.push(commitments[blob]);
            indices.push(CellIndex::new(cell).unwrap());
            cells.push(extended[blob].0[position].clone());
            let proof = if corrupt { extended[blob].1[(position + 1) % CELLS_PER_EXT_BLOB] } else { extended[blob].1[position] };
            proofs.push(proof);
        }

        // The batch accepts exactly when every single-cell batch accepts.
        let individual = (0..indices.len()).all(|row| {
            kzg.verify_cell_kzg_proof_batch(
                &row_commitments[row..=row],
                &indices[row..=row],
                &cells[row..=row],
                &proofs[row..=row],
            ) == Ok(true)
        });
        prop_assert_eq!(kzg.verify_cell_kzg_proof_batch(&row_commitments, &indices, &cells, &proofs), Ok(individual));
    }

    #[test]
    fn recovery_from_any_half(blob in arb_blob(), kept in subsequence(all_indices(), 64..=128)) {
        let kzg = Kzg::mainnet();
        let (cells, proofs) = kzg.compute_cells_and_kzg_proofs(&blob);

        // Fixture state: a random ascending subset of at least 64 of the 128 cells.
        let available: Vec<Cell> = kept.iter().map(|index| cells[index.get() as usize].clone()).collect();

        // Recovery returns every cell and every proof of the original.
        let (recovered_cells, recovered_proofs) = kzg.recover_cells_and_kzg_proofs(&kept, &available).unwrap();
        prop_assert_eq!(recovered_cells, cells);
        prop_assert_eq!(recovered_proofs, proofs);
    }
}
