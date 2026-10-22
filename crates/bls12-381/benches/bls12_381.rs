//! Timings of the hot field, group, pairing, hashing, and multi-scalar operations.
//!
//! Run with `cargo bench -p axiom-bls12-381`.
#![expect(
    clippy::unwrap_used,
    reason = "the fixtures invert fixed nonzero values, which always succeeds"
)]
#![expect(
    clippy::significant_drop_tightening,
    reason = "each benchmark group finishes before the next one opens"
)]

use std::hint::black_box;

use axiom_bls12_381::{Fp, Fp2, Fp12, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use criterion::Criterion;

fn main() {
    let mut c = Criterion::default().configure_from_args();
    operations(&mut c);
    multi_exp(&mut c);
    c.final_summary();
}

/// Times field arithmetic, group arithmetic and decoding, pairings, and hashing to G2.
fn operations(c: &mut Criterion) {
    // Fixture state: fixed, non-trivial operands so every run measures the same work.
    let a = Fp::from_u64(0x1234_5678_9abc_def0).invert().unwrap();
    let b = Fp::from_u64(0x0fed_cba9_8765_4321).invert().unwrap();
    let a2 = Fp2::new(a, b);
    let b2 = Fp2::new(b, a);
    let scalar = -Scalar::from_u64(0x0123_4567_89ab_cdef).invert().unwrap();
    let g1 = G1Affine::from(G1Projective::GENERATOR * scalar);
    let g2 = G2Affine::from(G2Projective::GENERATOR * scalar);
    let f12: Fp12 = *Gt::pairing(&g1, &g2).as_fp12();
    let g1_compressed = g1.to_compressed();
    let g2_compressed = g2.to_compressed();

    // Field arithmetic.
    let mut group = c.benchmark_group("field");
    group.bench_function("fp mul", |bench| bench.iter(|| black_box(a) * black_box(b)));
    group.bench_function("fp square", |bench| bench.iter(|| black_box(a).square()));
    group.bench_function("fp invert", |bench| bench.iter(|| black_box(a).invert()));
    group.bench_function("fp2 mul", |bench| {
        bench.iter(|| black_box(a2) * black_box(b2));
    });
    group.bench_function("fp2 square", |bench| bench.iter(|| black_box(a2).square()));
    group.bench_function("fp12 mul", |bench| {
        bench.iter(|| black_box(f12) * black_box(f12));
    });
    group.bench_function("fp12 cyclotomic square", |bench| {
        bench.iter(|| black_box(f12).cyclotomic_square());
    });
    group.finish();

    // Group arithmetic and decoding.
    let mut group = c.benchmark_group("group");
    group.bench_function("g1 mixed add", |bench| {
        bench.iter(|| G1Projective::from(g1) + black_box(g1));
    });
    group.bench_function("g1 scalar mul (const time)", |bench| {
        bench.iter(|| G1Projective::GENERATOR * black_box(scalar));
    });
    group.bench_function("g2 scalar mul (const time)", |bench| {
        bench.iter(|| G2Projective::GENERATOR * black_box(scalar));
    });
    group.bench_function("g1 subgroup check", |bench| {
        bench.iter(|| black_box(g1).is_torsion_free());
    });
    group.bench_function("g2 subgroup check", |bench| {
        bench.iter(|| black_box(g2).is_torsion_free());
    });
    group.bench_function("g1 decompress (checked)", |bench| {
        bench.iter(|| G1Affine::from_compressed(black_box(&g1_compressed)));
    });
    group.bench_function("g2 decompress (checked)", |bench| {
        bench.iter(|| G2Affine::from_compressed(black_box(&g2_compressed)));
    });
    group.finish();

    // Pairing and hashing.
    let mut group = c.benchmark_group("pairing");
    group.bench_function("pairing", |bench| {
        bench.iter(|| Gt::pairing(black_box(&g1), black_box(&g2)));
    });
    group.bench_function("multi pairing, 2 pairs", |bench| {
        bench.iter(|| Gt::multi_pairing(black_box(&[(g1, g2), (-g1, g2)])));
    });
    group.bench_function("hash to g2", |bench| {
        bench.iter(|| G2Projective::hash_to_curve(black_box(b"timing message"), b"BLS_SIG_DST"));
    });
    group.finish();
}

/// Times a multi-scalar multiplication over a blob-sized input of 4096 points.
fn multi_exp(c: &mut Criterion) {
    // Fixture state: 4096 distinct points and 4096 full-width scalars.
    let mut projective = Vec::with_capacity(4096);
    let mut point = G1Projective::GENERATOR;
    for _ in 0..4096 {
        projective.push(point);
        point = point.double() + G1Projective::GENERATOR;
    }
    let points = G1Projective::batch_normalize(&projective);
    let scalars: Vec<Scalar> = (0..4096_u64)
        .map(|i| Scalar::from_u64(i + 1).invert().unwrap())
        .collect();

    // A single call takes tens of milliseconds, so ten samples suffice.
    let mut group = c.benchmark_group("msm");
    group.sample_size(10);
    group.bench_function("g1 msm, 4096 points", |bench| {
        bench.iter(|| G1Projective::multi_exp(black_box(&points), black_box(&scalars)));
    });
    group.finish();
}
