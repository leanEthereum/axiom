//! Latency of the public-key operations and throughput of the symmetric ciphers.
//!
//! Run with `cargo bench -p axiom-crypto`.
#![expect(
    clippy::unwrap_used,
    reason = "the fixtures decode fixed secret keys below the group order"
)]

use std::hint::black_box;

use axiom_crypto::{
    aes::{Aes128Ctr, Aes128Gcm},
    chacha20poly1305::{ChaCha20, ChaCha20Poly1305},
    keccak::Keccak256,
    secp256k1::SecretKey,
    x25519,
};
use criterion::{Criterion, Throughput};

/// Payload sizes for the symmetric ciphers: a discv5 message and a large gossip frame.
const SIZES: [usize; 2] = [1 << 10, 1 << 16];

fn main() {
    let mut c = Criterion::default().configure_from_args();
    public_key_operations(&mut c);
    symmetric_throughput(&mut c);
    c.final_summary();
}

/// Times key derivation, signing, verification, recovery, and both Diffie-Hellman exchanges.
fn public_key_operations(c: &mut Criterion) {
    // Fixture state: two keys and one 32-byte hash.
    let alice = SecretKey::from_bytes(&[0x5a; 32]).unwrap();
    let bob = SecretKey::from_bytes(&[0xa5; 32]).unwrap();
    let alice_public = alice.public_key();
    let bob_public = bob.public_key();
    let hash = [0x42; 32];
    let signature = alice.sign_recoverable(&hash);
    let x_alice = x25519::SecretKey::from_bytes([0x5a; 32]);
    let x_bob = x25519::SecretKey::from_bytes([0xa5; 32]).public_key();

    let mut group = c.benchmark_group("public key");
    group.bench_function("secp256k1 public key", |b| {
        b.iter(|| black_box(&alice).public_key());
    });
    group.bench_function("secp256k1 sign", |b| {
        b.iter(|| black_box(&alice).sign_recoverable(black_box(&hash)));
    });
    group.bench_function("secp256k1 verify", |b| {
        b.iter(|| alice_public.verify(black_box(&hash), &signature.signature()));
    });
    group.bench_function("secp256k1 recover", |b| {
        b.iter(|| signature.recover(black_box(&hash)));
    });
    group.bench_function("secp256k1 ecdh", |b| {
        b.iter(|| {
            black_box(&alice)
                .diffie_hellman(&bob_public)
                .to_compressed()
        });
    });
    group.bench_function("x25519 diffie-hellman", |b| {
        b.iter(|| black_box(&x_alice).diffie_hellman(&x_bob));
    });
    group.finish();
}

/// Measures the bytes per second of each cipher and of Keccak over two payload sizes.
fn symmetric_throughput(c: &mut Criterion) {
    let chacha = ChaCha20Poly1305::new(&[7; 32]);
    let gcm = Aes128Gcm::new(&[7; 16]);
    let mut group = c.benchmark_group("symmetric");
    for size in SIZES {
        let mut buffer = vec![0x33_u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        // Each closure works in place, so no allocation enters the measurement.
        group.bench_function(format!("chacha20-poly1305 seal {size} B"), |b| {
            b.iter(|| chacha.seal_in_place_detached(&[1; 12], b"aad", black_box(&mut buffer)));
        });
        group.bench_function(format!("chacha20 keystream {size} B"), |b| {
            b.iter(|| ChaCha20::new(&[7; 32], &[1; 12], 1).apply_keystream(black_box(&mut buffer)));
        });
        group.bench_function(format!("aes-128-gcm seal {size} B"), |b| {
            b.iter(|| gcm.seal_in_place_detached(&[1; 12], b"aad", black_box(&mut buffer)));
        });
        group.bench_function(format!("aes-128-ctr {size} B"), |b| {
            b.iter(|| Aes128Ctr::new(&[7; 16], &[1; 16]).apply_keystream(black_box(&mut buffer)));
        });
        group.bench_function(format!("keccak-256 {size} B"), |b| {
            b.iter(|| Keccak256::digest(black_box(&buffer)));
        });
    }
    group.finish();
}
