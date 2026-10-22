//! Rough timings of the signature operations, run on demand.
//!
//! Run with `cargo test -p axiom-bls --release --test timing -- --ignored --nocapture`.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use axiom_bls::{PublicKey, SecretKey, Signature, SignatureSet};

/// Collects one report line per measured operation.
#[derive(Debug, Default)]
struct Timer {
    /// Formatted name and mean time of each operation, in measurement order.
    lines: Vec<String>,
}

impl Timer {
    /// Runs the closure repeatedly for about half a second and records the mean time per call.
    ///
    /// The divisor turns a time per call into a time per item, for batched operations.
    fn measure<T>(&mut self, name: &str, divisor: u32, mut operation: impl FnMut() -> T) {
        // Warm up caches and branch predictors once.
        black_box(operation());

        let budget = Duration::from_millis(500);
        let start = Instant::now();
        let mut iterations = 0_u32;
        while start.elapsed() < budget {
            black_box(operation());
            iterations += 1;
        }
        let per_item = start.elapsed() / iterations / divisor;
        self.lines.push(format!("{name:<40} {per_item:>12.2?}"));
    }
}

/// A valid key from a small index, with a top byte below the group order.
fn secret_key(index: u32) -> SecretKey {
    let mut bytes = [0x11; 32];
    bytes[28..].copy_from_slice(&index.to_be_bytes());
    SecretKey::from_bytes(&bytes).expect("0x11 leading bytes stay below the group order")
}

#[test]
#[ignore = "timing harness, run on demand"]
fn print_timings() {
    let mut timer = Timer::default();

    // Fixture state: one signer for the single-signature operations.
    let key = secret_key(1);
    let public_key = key.public_key();
    let message = [0x42_u8; 32];
    let signature = key.sign(&message);
    let public_key_bytes = public_key.to_bytes();
    let signature_bytes = signature.to_bytes();

    timer.measure("public key decode (KeyValidate)", 1, || {
        PublicKey::from_bytes(black_box(&public_key_bytes))
    });
    timer.measure("signature decode (subgroup check)", 1, || {
        Signature::from_bytes(black_box(&signature_bytes))
    });
    timer.measure("sign", 1, || key.sign(black_box(&message)));
    timer.measure("verify", 1, || {
        signature.verify(&public_key, black_box(&message))
    });

    // Fixture state: a 512-member sync committee signing one root.
    let committee: Vec<SecretKey> = (0..512).map(secret_key).collect();
    let committee_keys: Vec<PublicKey> = committee.iter().map(SecretKey::public_key).collect();
    let committee_refs: Vec<&PublicKey> = committee_keys.iter().collect();
    let committee_signatures: Vec<Signature> =
        committee.iter().map(|key| key.sign(&message)).collect();
    let aggregate = Signature::aggregate(&committee_signatures).unwrap();
    timer.measure("fast aggregate verify, 512 keys", 1, || {
        aggregate.fast_aggregate_verify(black_box(&committee_refs), &message)
    });

    // Fixture state: 64 independent sets, as in a block's attestations.
    let sets: Vec<SignatureSet> = (0..64)
        .map(|index| {
            let key = &committee[index];
            let message = [u8::try_from(index).unwrap(); 32];
            SignatureSet {
                signature: key.sign(&message),
                public_key: committee_keys[index].clone(),
                message,
            }
        })
        .collect();
    timer.measure("verify 64 sets one by one, per set", 64, || {
        sets.iter().all(SignatureSet::verify)
    });
    timer.measure("batch verify 64 sets, per set", 64, || {
        SignatureSet::verify_batch(black_box(&sets))
    });

    for line in &timer.lines {
        println!("{line}");
    }
}
