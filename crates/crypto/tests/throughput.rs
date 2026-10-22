//! Latency of the public-key operations and throughput of the symmetric ciphers.
//!
//! Run with `cargo test -p axiom-crypto --release --test throughput -- --ignored --nocapture`.
#![allow(
    clippy::print_stdout,
    reason = "a benchmark reports its figures on stdout"
)]
#![allow(
    clippy::cast_precision_loss,
    reason = "timing figures need far fewer than 52 bits of precision"
)]

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use axiom_crypto::{
    aes::{Aes128Ctr, Aes128Gcm},
    chacha20poly1305::ChaCha20Poly1305,
    keccak::Keccak256,
    secp256k1::SecretKey,
    x25519,
};

/// Payload sizes for the symmetric ciphers: a discv5 message and a large gossip frame.
const SIZES: [usize; 2] = [1 << 10, 1 << 16];

/// Best time of one call over several rounds, in nanoseconds.
fn nanoseconds_per_call(calls: u32, mut run: impl FnMut()) -> f64 {
    // Warm up caches, the branch predictor, and any lazily built table.
    run();
    let mut best = Duration::MAX;
    for _ in 0..7 {
        let start = Instant::now();
        for _ in 0..calls {
            run();
        }
        best = best.min(start.elapsed());
    }
    best.as_nanos() as f64 / f64::from(calls)
}

/// Throughput in MB/s, from the time of one call over a buffer.
fn megabytes_per_second(bytes: usize, nanoseconds: f64) -> f64 {
    // Bytes per nanosecond times 1000 is megabytes per second.
    bytes as f64 / nanoseconds * 1e3
}

#[test]
#[ignore = "benchmark; run with --ignored --nocapture"]
fn public_key_operations() {
    // Fixture state: two keys and one 32-byte hash.
    let alice = SecretKey::from_bytes(&[0x5a; 32]).unwrap();
    let bob = SecretKey::from_bytes(&[0xa5; 32]).unwrap();
    let alice_public = alice.public_key();
    let bob_public = bob.public_key();
    let hash = [0x42; 32];
    let signature = alice.sign_recoverable(&hash);

    let figures = [
        (
            "secp256k1 public key",
            nanoseconds_per_call(2000, || {
                black_box(black_box(&alice).public_key());
            }),
        ),
        (
            "secp256k1 sign",
            nanoseconds_per_call(2000, || {
                black_box(black_box(&alice).sign_recoverable(black_box(&hash)));
            }),
        ),
        (
            "secp256k1 verify",
            nanoseconds_per_call(2000, || {
                let _ = black_box(alice_public.verify(black_box(&hash), &signature.signature()));
            }),
        ),
        (
            "secp256k1 recover",
            nanoseconds_per_call(2000, || {
                let _ = black_box(signature.recover(black_box(&hash)));
            }),
        ),
        (
            "secp256k1 ecdh",
            nanoseconds_per_call(2000, || {
                black_box(
                    black_box(&alice)
                        .diffie_hellman(&bob_public)
                        .to_compressed(),
                );
            }),
        ),
    ];

    let x_alice = x25519::SecretKey::from_bytes([0x5a; 32]);
    let x_bob = x25519::SecretKey::from_bytes([0xa5; 32]).public_key();
    let x25519_ns = nanoseconds_per_call(5000, || {
        let _ = black_box(black_box(&x_alice).diffie_hellman(&x_bob));
    });

    for (name, ns) in figures
        .into_iter()
        .chain([("x25519 diffie-hellman", x25519_ns)])
    {
        println!("{name:<24} {ns:>10.0} ns/op");
    }
}

#[test]
#[ignore = "benchmark; run with --ignored --nocapture"]
fn symmetric_throughput() {
    let chacha = ChaCha20Poly1305::new(&[7; 32]);
    let gcm = Aes128Gcm::new(&[7; 16]);
    for size in SIZES {
        let mut buffer = vec![0x33_u8; size];
        let calls = (1 << 24) / u32::try_from(size).unwrap();

        // Each closure seals in place, so no allocation enters the measurement.
        let chacha_ns = nanoseconds_per_call(calls, || {
            black_box(chacha.seal_in_place_detached(&[1; 12], b"aad", black_box(&mut buffer)));
        });
        let gcm_ns = nanoseconds_per_call(calls, || {
            black_box(gcm.seal_in_place_detached(&[1; 12], b"aad", black_box(&mut buffer)));
        });
        let ctr_ns = nanoseconds_per_call(calls, || {
            Aes128Ctr::new(&[7; 16], &[1; 16]).apply_keystream(black_box(&mut buffer));
        });
        let keccak_ns = nanoseconds_per_call(calls, || {
            black_box(Keccak256::digest(black_box(&buffer)));
        });

        for (name, ns) in [
            ("chacha20-poly1305 seal", chacha_ns),
            ("aes-128-gcm seal", gcm_ns),
            ("aes-128-ctr", ctr_ns),
            ("keccak-256", keccak_ns),
        ] {
            println!(
                "{name:<24} {size:>6} B {:>10.0} MB/s",
                megabytes_per_second(size, ns)
            );
        }
    }
}
