//! Timings of the hash-based signature operations: key preparation per epoch, signing, and verification.

use std::hint::black_box;

use axiom_hashsig::{
    ChunkSize, HypercubeLifetime, Instantiation, LeafEpoch, SeedStream, Target, TargetSumLifetime,
};
use criterion::{Criterion, Throughput};

fn main() {
    let mut criterion = Criterion::default().configure_from_args();

    // The 2^32 hypercube instantiation, and the 2^18 base-p ones with 2-bit and 4-bit chunks.
    let instantiations = [
        (
            "lifetime 2^32, hypercube",
            Instantiation::Hypercube(HypercubeLifetime::Epochs32),
        ),
        (
            "lifetime 2^18, w = 2",
            Instantiation::TargetSum {
                lifetime: TargetSumLifetime::Epochs18,
                chunk: ChunkSize::Two,
                target: Target::Expected,
            },
        ),
        (
            "lifetime 2^18, w = 4",
            Instantiation::TargetSum {
                lifetime: TargetSumLifetime::Epochs18,
                chunk: ChunkSize::Four,
                target: Target::Expected,
            },
        ),
    ];

    for (name, instantiation) in instantiations {
        // Fixture state: a key over three bottom trees from epoch 0, so the window can slide once.
        let scheme = instantiation.scheme();
        let trees = 3 * scheme.leaves_per_bottom_tree();
        let (public, secret) = scheme
            .generate(&mut SeedStream::new(name.as_bytes()), 0..trees)
            .expect("three bottom trees fit every lifetime");
        let message = [0x42_u8; 32];
        let epoch = LeafEpoch(3);
        let signature = secret.sign(epoch, &message).expect("epoch 3 is prepared");
        let bytes = signature.to_bytes();

        // Each group sits in its own scope, so its borrow of the runner ends with it.
        {
            let mut group = criterion.benchmark_group(name);
            group.sample_size(10);

            // One bottom tree builds the leaves of 2^(h/2) epochs, so time per element is per epoch.
            group.throughput(Throughput::Elements(scheme.leaves_per_bottom_tree()));
            group.bench_function("key preparation, one bottom tree", |b| {
                b.iter(|| {
                    // The fresh key's preparation builds bottom tree 2.
                    let preparation = black_box(&secret)
                        .preparation()
                        .expect("a third tree to slide onto");
                    preparation.build()
                });
            });
            group.finish();
        }
        {
            let mut group = criterion.benchmark_group(name);
            group.bench_function("sign", |b| {
                b.iter(|| secret.sign(epoch, black_box(&message)));
            });
            group.bench_function("verify", |b| {
                b.iter(|| scheme.verify(&public, epoch, black_box(&message), &signature));
            });
            group.bench_function("signature decode", |b| {
                b.iter(|| scheme.decode_signature(black_box(&bytes)));
            });
            group.finish();
        }
    }

    criterion.final_summary();
}
