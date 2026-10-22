//! Timings of the public KZG operations, from EIP-4844 openings to EIP-7594 recovery.
#![allow(
    clippy::print_stdout,
    reason = "a benchmark reports its one-off costs on stdout"
)]

use std::{hint::black_box, time::Instant};

use axiom_kzg::{BYTES_PER_BLOB, Blob, Bytes48, CELLS_PER_EXT_BLOB, Cell, CellIndex, Kzg};
use criterion::Criterion;

/// A blob of 4096 pseudorandom elements below 2^248.
fn blob() -> Blob {
    // Xorshift64 fills the blob with varied, reproducible bytes.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut bytes = vec![0_u8; BYTES_PER_BLOB];
    for chunk in bytes.as_chunks_mut::<8>().0 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *chunk = state.to_be_bytes();
    }
    // A zero top byte keeps every element below the field modulus.
    for element in bytes.as_chunks_mut::<32>().0 {
        element[0] = 0;
    }
    Blob::from_bytes(&bytes).expect("canonical blob")
}

fn main() {
    // Ten samples suffice: the slowest operation takes a few hundred milliseconds.
    let mut criterion = Criterion::default().sample_size(10).configure_from_args();

    // Phase 1: one-off costs, the setup decoding and the FK20 tables.
    //
    // Both are cached after the first call, so one wall-clock reading is all there is to take.
    let start = Instant::now();
    let kzg = Kzg::mainnet();
    println!(
        "setup decoding (first mainnet call): {:.2?}",
        start.elapsed()
    );
    let blob = blob();
    let start = Instant::now();
    let (cells, proofs) = kzg.compute_cells_and_kzg_proofs(&blob);
    println!("FK20 tables + first cell proofs: {:.2?}", start.elapsed());

    // Phase 2: EIP-4844, one blob, then a block's worth of six.
    let commitment = kzg.blob_to_kzg_commitment(&blob);
    let proof = kzg
        .compute_blob_kzg_proof(&blob, &commitment)
        .expect("valid commitment");
    let blobs = vec![blob.clone(); 6];
    let commitments = vec![commitment; 6];
    let blob_proofs = vec![proof; 6];

    // Each group sits in its own scope, so its borrow of the runner ends with it.
    {
        let mut group = criterion.benchmark_group("eip4844");
        group.bench_function("blob_to_kzg_commitment", |b| {
            b.iter(|| kzg.blob_to_kzg_commitment(black_box(&blob)));
        });
        group.bench_function("compute_blob_kzg_proof", |b| {
            b.iter(|| kzg.compute_blob_kzg_proof(black_box(&blob), &commitment));
        });
        group.bench_function("verify_blob_kzg_proof", |b| {
            b.iter(|| kzg.verify_blob_kzg_proof(black_box(&blob), &commitment, &proof));
        });
        group.bench_function("verify_blob_kzg_proof_batch, 6 blobs", |b| {
            b.iter(|| {
                kzg.verify_blob_kzg_proof_batch(black_box(&blobs), &commitments, &blob_proofs)
            });
        });
        group.finish();
    }

    // Phase 3: EIP-7594, all 128 cells of the extended blob.
    let indices: Vec<CellIndex> = (0..CELLS_PER_EXT_BLOB as u64)
        .map(|index| CellIndex::new(index).expect("index below 128"))
        .collect();
    let all_commitments = vec![commitment; CELLS_PER_EXT_BLOB];
    let all_cells: Vec<Cell> = cells.to_vec();
    let all_proofs: Vec<Bytes48> = proofs.to_vec();

    // Recovery from the odd half of the cells, the worst case for no cell of the original blob.
    let kept: Vec<CellIndex> = indices
        .iter()
        .copied()
        .filter(|index| index.get() % 2 == 1)
        .collect();
    let kept_cells: Vec<Cell> = kept
        .iter()
        .map(|index| cells[index.get() as usize].clone())
        .collect();

    {
        let mut group = criterion.benchmark_group("eip7594");
        group.bench_function("compute_cells", |b| {
            b.iter(|| kzg.compute_cells(black_box(&blob)));
        });
        group.bench_function("compute_cells_and_kzg_proofs", |b| {
            b.iter(|| kzg.compute_cells_and_kzg_proofs(black_box(&blob)));
        });
        group.bench_function("verify_cell_kzg_proof_batch, 128 cells", |b| {
            b.iter(|| {
                kzg.verify_cell_kzg_proof_batch(
                    &all_commitments,
                    &indices,
                    black_box(&all_cells),
                    &all_proofs,
                )
            });
        });
        group.bench_function("recover_cells_and_kzg_proofs, 64 of 128", |b| {
            b.iter(|| kzg.recover_cells_and_kzg_proofs(&kept, black_box(&kept_cells)));
        });
        group.finish();
    }

    criterion.final_summary();
}
