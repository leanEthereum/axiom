//! Throughput and recovery benchmarks, ignored by default.
//!
//! Run with `cargo test -p axiom-store --release --test bench -- --ignored --nocapture --test-threads 1`.
#![allow(
    clippy::print_stdout,
    reason = "a benchmark reports its figures on stdout"
)]
#![allow(
    clippy::cast_precision_loss,
    reason = "throughput figures need far fewer than 52 bits of precision"
)]

mod support;

use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

use axiom_store::{Batch, Options, Store, SyncPolicy, Table};
use support::TempDir;

/// Prints one measurement as operations and mebibytes per second.
fn report(label: &str, ops: usize, bytes: usize, elapsed: Duration) {
    let seconds = elapsed.as_secs_f64();
    println!(
        "{label:<44} {ops:>7} ops  {:>10.0} ops/s  {:>8.1} MiB/s  {:>9.3} s",
        ops as f64 / seconds,
        bytes as f64 / seconds / f64::from(1 << 20),
        seconds,
    );
}

/// Deterministic pseudo-random value bytes, so compression or deduplication cannot help.
fn value(seed: u64, len: usize) -> Vec<u8> {
    // xorshift64: cheap, and different for every key.
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// Writes keys one per batch, then reads them all back, reporting both.
fn put_then_get(dir: &Path, label: &str, options: Options, count: usize, len: usize) {
    let store = Store::open(dir, options).expect("benchmark operation succeeds");
    let table = store.table("bench").expect("benchmark operation succeeds");
    let values: Vec<_> = (0..count as u64).map(|i| value(i, len)).collect();

    let start = Instant::now();
    for (i, value) in values.iter().enumerate() {
        store
            .put(table, &(i as u64).to_be_bytes(), value)
            .expect("benchmark operation succeeds");
    }
    store.sync().expect("benchmark operation succeeds");
    report(&format!("put {label}"), count, count * len, start.elapsed());

    // Reads in a scattered order: a stride coprime with the count visits every key once.
    let start = Instant::now();
    let mut index = 0;
    for _ in 0..count {
        index = (index + 7919) % count;
        let read = store
            .get(table, &(index as u64).to_be_bytes())
            .expect("benchmark operation succeeds")
            .expect("benchmark operation succeeds");
        assert_eq!(read.len(), len);
    }
    report(&format!("get {label}"), count, count * len, start.elapsed());
}

#[test]
#[ignore = "benchmark"]
fn throughput_1_kib() {
    let manual = Options {
        sync: SyncPolicy::Manual,
        ..Options::default()
    };
    let dir = TempDir::on_disk("bench-1k");
    put_then_get(dir.path(), "1 KiB, sync manual", manual, 100_000, 1 << 10);

    // One device flush per batch: the latency floor of the drive.
    let dir = TempDir::on_disk("bench-1k-sync");
    put_then_get(
        dir.path(),
        "1 KiB, sync every batch",
        Options::default(),
        2_000,
        1 << 10,
    );

    // Batching amortizes the flush: 1000 puts per commit.
    let dir = TempDir::on_disk("bench-1k-batch");
    let store = Store::open(dir.path(), Options::default()).unwrap();
    let table = store.table("bench").unwrap();
    let start = Instant::now();
    for chunk in 0..100u64 {
        let mut batch = Batch::new();
        for i in 0..1000 {
            let key = chunk * 1000 + i;
            batch
                .put(table, &key.to_be_bytes(), &value(key, 1 << 10))
                .unwrap();
        }
        store.write(&batch).unwrap();
    }
    report(
        "put 1 KiB, sync every batch of 1000",
        100_000,
        100_000 << 10,
        start.elapsed(),
    );
}

#[test]
#[ignore = "benchmark"]
fn throughput_1_mib() {
    let manual = Options {
        sync: SyncPolicy::Manual,
        ..Options::default()
    };
    let dir = TempDir::on_disk("bench-1m");
    put_then_get(dir.path(), "1 MiB, sync manual", manual, 1_000, 1 << 20);

    let dir = TempDir::on_disk("bench-1m-sync");
    put_then_get(
        dir.path(),
        "1 MiB, sync every batch",
        Options::default(),
        200,
        1 << 20,
    );
}

#[test]
#[ignore = "benchmark"]
fn recovery_time() {
    // Fixture state: 200_000 keys of 1 KiB and 200 values of 1 MiB, about 400 MiB in 64 MiB segments.
    let options = Options {
        sync: SyncPolicy::Manual,
        segment_size: 64 << 20,
        ..Options::default()
    };
    let dir = TempDir::on_disk("bench-recovery");
    {
        let store = Store::open(dir.path(), options).unwrap();
        let small = store.table("small").unwrap();
        let large = store.table("large").unwrap();
        for i in 0..200_000u64 {
            store
                .put(small, &i.to_be_bytes(), &value(i, 1 << 10))
                .unwrap();
        }
        for i in 0..200u64 {
            store
                .put(large, &i.to_be_bytes(), &value(i, 1 << 20))
                .unwrap();
        }
    }
    let segments = fs::read_dir(dir.path())
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|ext| ext == "seg")
        })
        .count();
    println!("recovery fixture: {segments} segments");

    // Hints present: only the active segment is scanned.
    let start = Instant::now();
    let store = Store::open(dir.path(), options).unwrap();
    report("open with hints", 200_200, 0, start.elapsed());
    let small: Table = store.table("small").unwrap();
    assert!(
        store
            .contains_key(small, &199_999u64.to_be_bytes())
            .unwrap()
    );
    drop(store);

    // Hints deleted: every byte is read and checksummed, then the hints are rewritten.
    for entry in fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "hint") {
            fs::remove_file(path).unwrap();
        }
    }
    let start = Instant::now();
    let store = Store::open(dir.path(), options).unwrap();
    let total = store.metrics().disk_bytes() as usize;
    report("open by full scan", 200_200, total, start.elapsed());
}
