//! Rough timings of the public operations, run on demand.
//!
//! Run with `cargo test -p axiom-kzg --release --test timing -- --ignored --nocapture`.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use axiom_kzg::{BYTES_PER_BLOB, Blob, Bytes48, CELLS_PER_EXT_BLOB, Cell, CellIndex, Kzg};

/// Collects one report line per measured operation.
#[derive(Debug, Default)]
struct Timer {
    /// Formatted name and mean time of each operation, in measurement order.
    lines: Vec<String>,
}

impl Timer {
    /// Runs the closure repeatedly for about a second and records the mean time per call.
    fn measure<T>(&mut self, name: &str, mut operation: impl FnMut() -> T) {
        // Warm up caches, lazy tables, and branch predictors once.
        black_box(operation());

        let budget = Duration::from_secs(1);
        let start = Instant::now();
        let mut iterations = 0_u32;
        while start.elapsed() < budget || iterations < 3 {
            black_box(operation());
            iterations += 1;
        }
        let per_call = start.elapsed() / iterations;
        self.lines.push(format!("{name:<44} {per_call:>12.2?}"));
    }

    /// Times a single call, for one-off costs such as building tables.
    fn once<T>(&mut self, name: &str, operation: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let output = black_box(operation());
        self.lines
            .push(format!("{name:<44} {:>12.2?}", start.elapsed()));
        output
    }
}

#[test]
#[ignore = "timing harness, run on demand"]
fn print_timings() {
    let mut timer = Timer::default();

    // Phase 1: one-off costs, the setup decoding and the FK20 tables.
    let kzg = timer.once("setup decoding (first mainnet call)", Kzg::mainnet);

    // Fixture state: a blob of 4096 pseudorandom elements below 2^248.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut bytes = vec![0_u8; BYTES_PER_BLOB];
    for chunk in bytes.as_chunks_mut::<8>().0 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *chunk = state.to_be_bytes();
    }
    for element in bytes.as_chunks_mut::<32>().0 {
        element[0] = 0;
    }
    let blob = Blob::from_bytes(&bytes).expect("canonical blob");
    let (cells, proofs) = timer.once("FK20 tables + first cell proofs", || {
        kzg.compute_cells_and_kzg_proofs(&blob)
    });

    // Phase 2: EIP-4844.
    let commitment = kzg.blob_to_kzg_commitment(&blob);
    let proof = kzg
        .compute_blob_kzg_proof(&blob, &commitment)
        .expect("valid commitment");
    timer.measure("blob_to_kzg_commitment", || {
        kzg.blob_to_kzg_commitment(&blob)
    });
    timer.measure("compute_blob_kzg_proof", || {
        kzg.compute_blob_kzg_proof(&blob, &commitment)
    });
    timer.measure("verify_blob_kzg_proof", || {
        kzg.verify_blob_kzg_proof(&blob, &commitment, &proof)
    });
    let blobs = vec![blob.clone(); 6];
    let commitments = vec![commitment; 6];
    let blob_proofs = vec![proof; 6];
    timer.measure("verify_blob_kzg_proof_batch, 6 blobs", || {
        kzg.verify_blob_kzg_proof_batch(&blobs, &commitments, &blob_proofs)
    });

    // Phase 3: EIP-7594.
    timer.measure("compute_cells", || kzg.compute_cells(&blob));
    timer.measure("compute_cells_and_kzg_proofs", || {
        kzg.compute_cells_and_kzg_proofs(&blob)
    });
    let indices: Vec<CellIndex> = (0..CELLS_PER_EXT_BLOB as u64)
        .map(|index| CellIndex::new(index).expect("index below 128"))
        .collect();
    let all_commitments = vec![commitment; CELLS_PER_EXT_BLOB];
    let all_cells: Vec<Cell> = cells.to_vec();
    let all_proofs: Vec<Bytes48> = proofs.to_vec();
    timer.measure("verify_cell_kzg_proof_batch, 128 cells", || {
        kzg.verify_cell_kzg_proof_batch(&all_commitments, &indices, &all_cells, &all_proofs)
    });

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
    timer.measure("recover_cells_and_kzg_proofs, 64 of 128", || {
        kzg.recover_cells_and_kzg_proofs(&kept, &kept_cells)
    });

    println!("{}", timer.lines.join("\n"));
}
