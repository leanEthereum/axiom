//! Timings of the signature operations, from key decoding to batch verification.

use std::hint::black_box;

use axiom_bls::{PublicKey, SecretKey, Signature, SignatureSet};
use criterion::{Criterion, Throughput};

/// A valid key from a small index, with a top byte below the group order.
fn secret_key(index: u32) -> SecretKey {
    let mut bytes = [0x11; 32];
    bytes[28..].copy_from_slice(&index.to_be_bytes());
    SecretKey::from_bytes(&bytes).expect("0x11 leading bytes stay below the group order")
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();

    // Fixture state: one signer for the single-signature operations.
    let key = secret_key(1);
    let public_key = key.public_key();
    let message = [0x42_u8; 32];
    let signature = key.sign(&message);
    let public_key_bytes = public_key.to_bytes();
    let signature_bytes = signature.to_bytes();

    // Each group sits in its own scope, so its borrow of the runner ends with it.
    {
        let mut group = criterion.benchmark_group("single");
        group.bench_function("public key decode (KeyValidate)", |b| {
            b.iter(|| PublicKey::from_bytes(black_box(&public_key_bytes)));
        });
        group.bench_function("signature decode (subgroup check)", |b| {
            b.iter(|| Signature::from_bytes(black_box(&signature_bytes)));
        });
        group.bench_function("sign", |b| b.iter(|| key.sign(black_box(&message))));
        group.bench_function("verify", |b| {
            b.iter(|| signature.verify(&public_key, black_box(&message)));
        });
        group.finish();
    }

    // Fixture state: a 512-member sync committee signing one root.
    let committee: Vec<SecretKey> = (0..512).map(secret_key).collect();
    let committee_keys: Vec<PublicKey> = committee.iter().map(SecretKey::public_key).collect();
    let committee_refs: Vec<&PublicKey> = committee_keys.iter().collect();
    let committee_signatures: Vec<Signature> =
        committee.iter().map(|key| key.sign(&message)).collect();
    let aggregate = Signature::aggregate(&committee_signatures).expect("512 signatures");

    {
        let mut group = criterion.benchmark_group("aggregate");
        group.bench_function("fast aggregate verify, 512 keys", |b| {
            b.iter(|| aggregate.fast_aggregate_verify(black_box(&committee_refs), &message));
        });
        group.finish();
    }

    // Fixture state: 64 independent sets, as in a block's attestations.
    let sets: Vec<SignatureSet> = (0..64)
        .map(|index| {
            let key = &committee[index];
            let message = [u8::try_from(index).expect("index below 64"); 32];
            SignatureSet {
                signature: key.sign(&message),
                public_key: committee_keys[index].clone(),
                message,
            }
        })
        .collect();

    // Throughput in sets turns a time per call into a time per set.
    {
        let mut group = criterion.benchmark_group("64 sets");
        group.throughput(Throughput::Elements(64));
        group.bench_function("verify one by one", |b| {
            b.iter(|| black_box(&sets).iter().all(SignatureSet::verify));
        });
        group.bench_function("batch verify", |b| {
            b.iter(|| SignatureSet::verify_batch(black_box(&sets)));
        });
        group.finish();
    }

    criterion.final_summary();
}
