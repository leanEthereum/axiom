//! Rough timings of the hot operations, run on demand.
//!
//! Run with `cargo test -p axiom-bls12-381 --release --test timing -- --ignored --nocapture`.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use axiom_bls12_381::{
    Fp, Fp2, Fp12, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar,
};

/// Runs the closure repeatedly for about half a second and prints the mean time per call.
fn time<T>(name: &str, mut operation: impl FnMut() -> T) {
    // Warm up caches and branch predictors once.
    black_box(operation());

    // Read the clock once per batch so its own cost does not pollute nanosecond timings.
    const BATCH: u32 = 64;
    let budget = Duration::from_millis(500);
    let start = Instant::now();
    let mut iterations = 0_u32;
    while start.elapsed() < budget {
        for _ in 0..BATCH {
            black_box(operation());
        }
        iterations += BATCH;
    }
    let per_call = start.elapsed() / iterations;
    println!("{name:<32} {per_call:>12.2?}");
}

#[test]
#[ignore = "timing harness, run on demand"]
fn print_timings() {
    // Fixture state: fixed, non-trivial operands so every run measures the same work.
    let a = Fp::from_u64(0x1234_5678_9abc_def0).invert().unwrap();
    let b = Fp::from_u64(0x0fed_cba9_8765_4321).invert().unwrap();
    let a2 = Fp2::new(a, b);
    let b2 = Fp2::new(b, a);
    let scalar = -Scalar::from_u64(0x0123_4567_89ab_cdef).invert().unwrap();
    let g1 = G1Affine::from(G1Projective::GENERATOR * scalar);
    let g2 = G2Affine::from(G2Projective::GENERATOR * scalar);
    let f = Gt::pairing(&g1, &g2);
    let f12: Fp12 = *f.as_fp12();

    time("fp mul", || black_box(a) * black_box(b));
    time("fp square", || black_box(a).square());
    time("fp invert", || black_box(a).invert());
    time("fp2 mul", || black_box(a2) * black_box(b2));
    time("fp12 mul", || black_box(f12) * black_box(f12));
    time("fp12 cyclotomic square", || black_box(f12).cyclotomic_square());
    time("g1 add", || G1Projective::from(g1) + black_box(g1));
    time("g1 scalar mul (const time)", || G1Projective::GENERATOR * black_box(scalar));
    time("g2 scalar mul (const time)", || G2Projective::GENERATOR * black_box(scalar));
    time("g1 subgroup check", || black_box(g1).is_torsion_free());
    time("g2 subgroup check", || black_box(g2).is_torsion_free());
    time("g1 decompress (checked)", || G1Affine::from_compressed(&black_box(g1.to_compressed())));
    time("g2 decompress (checked)", || G2Affine::from_compressed(&black_box(g2.to_compressed())));
    time("pairing", || Gt::pairing(black_box(&g1), black_box(&g2)));
    time("multi pairing, 2 pairs", || {
        Gt::multi_pairing(black_box(&[(g1, g2), (-g1, g2)]))
    });
    time("hash to g2", || {
        G2Projective::hash_to_curve(black_box(b"timing message"), b"BLS_SIG_DST")
    });

    // MSM over a blob-sized input of 4096 points.
    let points: Vec<G1Affine> = {
        let mut point = G1Projective::GENERATOR;
        let mut projective = Vec::with_capacity(4096);
        for _ in 0..4096 {
            projective.push(point);
            point = point.double() + G1Projective::GENERATOR;
        }
        G1Projective::batch_normalize(&projective)
    };
    let scalars: Vec<Scalar> = (0..4096_u64)
        .map(|i| Scalar::from_u64(i + 1).invert().unwrap())
        .collect();
    time("g1 msm, 4096 points", || {
        G1Projective::multi_exp(black_box(&points), black_box(&scalars))
    });
}
