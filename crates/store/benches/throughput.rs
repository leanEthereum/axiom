//! Put, get, and recovery throughput of the store on a real disk.
#![allow(
    clippy::print_stdout,
    reason = "a benchmark reports its fixture on stdout"
)]

use std::{
    fs,
    path::{Path, PathBuf},
    process,
};

use axiom_store::{Batch, Options, Store, SyncPolicy};
use criterion::{BatchSize, BenchmarkGroup, Criterion, Throughput, measurement::WallTime};

/// A fresh directory under the build directory, deleted on drop.
///
/// The system temporary directory is often a RAM filesystem, where a sync costs nothing.
struct TempDir(PathBuf);

impl TempDir {
    /// Creates a directory name unique to this process and label.
    fn new(label: &str) -> Self {
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("axiom-store-bench-{label}-{}", process::id()));
        // A leftover from a killed earlier run would otherwise leak into this one.
        fs::remove_dir_all(&path).ok();
        Self(path)
    }

    /// Returns the path.
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
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

/// Options that flush only on rotation, close, or an explicit sync.
fn manual() -> Options {
    Options {
        sync: SyncPolicy::Manual,
        ..Options::default()
    }
}

/// Registers one put per batch, then scattered gets, over a fixture of the given size.
fn put_then_get(
    group: &mut BenchmarkGroup<'_, WallTime>,
    label: &str,
    options: Options,
    count: usize,
    len: usize,
) {
    let dir = TempDir::new(&label.replace(' ', "-"));
    let store = Store::open(dir.path(), options).expect("benchmark operation succeeds");
    let table = store.table("bench").expect("benchmark operation succeeds");
    let values: Vec<_> = (0..count as u64).map(|i| value(i, len)).collect();

    // Keys cycle over the fixture, so the live data never outgrows it.
    let mut next = 0;
    group.bench_function(format!("put, {label}"), |b| {
        b.iter(|| {
            store
                .put(table, &(next as u64).to_be_bytes(), &values[next])
                .expect("benchmark operation succeeds");
            next = (next + 1) % count;
        });
    });

    // Every key exists before the reads, however few puts the measurement ran.
    for (i, value) in values.iter().enumerate() {
        store
            .put(table, &(i as u64).to_be_bytes(), value)
            .expect("benchmark operation succeeds");
    }
    store.sync().expect("benchmark operation succeeds");

    // Reads in a scattered order: a stride coprime with the count visits every key once per cycle.
    let mut index = 0;
    group.bench_function(format!("get, {label}"), |b| {
        b.iter(|| {
            index = (index + 7919) % count;
            let read = store
                .get(table, &(index as u64).to_be_bytes())
                .expect("benchmark operation succeeds")
                .expect("every key was written");
            assert_eq!(read.len(), len);
        });
    });
}

/// Small values: the flush dominates unless batching amortizes it.
fn one_kib(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("1 KiB");
    group.throughput(Throughput::Bytes(1 << 10));
    put_then_get(&mut group, "sync manual", manual(), 100_000, 1 << 10);

    // One device flush per batch: the latency floor of the drive.
    put_then_get(
        &mut group,
        "sync every batch",
        Options::default(),
        2_000,
        1 << 10,
    );

    // Batching amortizes the flush: 1000 puts per commit, 100 batches in turn.
    let dir = TempDir::new("batch");
    let store = Store::open(dir.path(), Options::default()).expect("benchmark operation succeeds");
    let table = store.table("bench").expect("benchmark operation succeeds");
    let batches: Vec<Batch> = (0..100_u64)
        .map(|chunk| {
            let mut batch = Batch::new();
            for i in 0..1000 {
                let key = chunk * 1000 + i;
                batch
                    .put(table, &key.to_be_bytes(), &value(key, 1 << 10))
                    .expect("benchmark operation succeeds");
            }
            batch
        })
        .collect();
    let mut next = 0;
    group.throughput(Throughput::Bytes(1000 << 10));
    group.bench_function("put, sync every batch of 1000", |b| {
        b.iter(|| {
            store
                .write(&batches[next])
                .expect("benchmark operation succeeds");
            next = (next + 1) % batches.len();
        });
    });
    group.finish();
}

/// Large values: the drive's sequential bandwidth.
fn one_mib(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("1 MiB");
    group.throughput(Throughput::Bytes(1 << 20));
    put_then_get(&mut group, "sync manual", manual(), 1_000, 1 << 20);
    put_then_get(
        &mut group,
        "sync every batch",
        Options::default(),
        200,
        1 << 20,
    );
    group.finish();
}

/// Opening a store of about 400 MiB, with and without its hint files.
fn recovery(criterion: &mut Criterion) {
    // Fixture state: 200_000 keys of 1 KiB and 200 values of 1 MiB, about 400 MiB in 64 MiB segments.
    let options = Options {
        sync: SyncPolicy::Manual,
        segment_size: 64 << 20,
        ..Options::default()
    };
    let dir = TempDir::new("recovery");
    {
        let store = Store::open(dir.path(), options).expect("benchmark operation succeeds");
        let small = store.table("small").expect("benchmark operation succeeds");
        let large = store.table("large").expect("benchmark operation succeeds");
        for i in 0..200_000_u64 {
            store
                .put(small, &i.to_be_bytes(), &value(i, 1 << 10))
                .expect("benchmark operation succeeds");
        }
        for i in 0..200_u64 {
            store
                .put(large, &i.to_be_bytes(), &value(i, 1 << 20))
                .expect("benchmark operation succeeds");
        }
    }
    let files = |extension: &str| -> Vec<PathBuf> {
        fs::read_dir(dir.path())
            .expect("store directory is listable")
            .map(|entry| entry.expect("directory entry is readable").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == extension))
            .collect()
    };
    println!("recovery fixture: {} segments", files("seg").len());

    // The last small key is visible after a reopen, and the disk size sets the scan throughput.
    let store = Store::open(dir.path(), options).expect("benchmark operation succeeds");
    let small = store.table("small").expect("benchmark operation succeeds");
    assert!(
        store
            .contains_key(small, &199_999_u64.to_be_bytes())
            .expect("benchmark operation succeeds")
    );
    let disk_bytes = store.metrics().disk_bytes();
    drop(store);

    let mut group = criterion.benchmark_group("recovery");

    // Hints present: only the active segment is scanned.
    group.throughput(Throughput::Elements(200_200));
    group.bench_function("open with hints", |b| {
        b.iter_with_large_drop(|| {
            Store::open(dir.path(), options).expect("benchmark operation succeeds")
        });
    });

    // Hints deleted before each open: every byte is read and checksummed, then the hints are rewritten.
    group.throughput(Throughput::Bytes(disk_bytes));
    group.bench_function("open by full scan", |b| {
        b.iter_batched(
            || {
                for path in files("hint") {
                    fs::remove_file(path).expect("hint file is removable");
                }
            },
            |()| Store::open(dir.path(), options).expect("benchmark operation succeeds"),
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn main() {
    // Ten samples bound the disk traffic of the slowest groups.
    let mut criterion = Criterion::default().sample_size(10).configure_from_args();
    one_kib(&mut criterion);
    one_mib(&mut criterion);
    recovery(&mut criterion);
    criterion.final_summary();
}
