//! Concurrent readers against a writer that rotates and compacts underneath them.

mod support;

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use axiom_store::{Batch, Iter, Options, Snapshot, Store, SyncPolicy};
use support::TempDir;

#[test]
fn handles_are_shareable_across_threads() {
    // The store, its snapshots and its iterators all cross thread boundaries.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Store>();
    assert_send_sync::<Snapshot>();
    assert_send_sync::<Iter>();
}

#[test]
fn readers_see_whole_batches_while_segments_are_compacted_away() {
    let dir = TempDir::new("concurrency");
    // Tiny segments with automatic compaction: segments are deleted every few writes.
    let options = Options {
        sync: SyncPolicy::Manual,
        segment_size: 1024,
        compaction_threshold: 30,
        auto_compact: true,
    };
    let store = Arc::new(Store::open(dir.path(), options).unwrap());
    let left = store.table("left").unwrap();
    let right = store.table("right").unwrap();
    let done = Arc::new(AtomicBool::new(false));

    // Invariant: batch i writes counter i into both tables.
    // It also adds key i to the left table.
    //
    //     batch i: left/counter = i, right/counter = i, left/i = i
    let writer = {
        let store = Arc::clone(&store);
        let done = Arc::clone(&done);
        thread::spawn(move || {
            for i in 0u64..3000 {
                let mut batch = Batch::new();
                batch.put(left, b"counter", &i.to_be_bytes()).unwrap();
                batch.put(right, b"counter", &i.to_be_bytes()).unwrap();
                batch.put(left, &i.to_be_bytes(), &[i as u8; 64]).unwrap();
                store.write(&batch).unwrap();
            }
            done.store(true, Ordering::Release);
        })
    };

    // All readers start before the writer is awaited, so they overlap its whole run.
    let mut readers = Vec::new();
    for _ in 0..4 {
        let store = Arc::clone(&store);
        let done = Arc::clone(&done);
        readers.push(thread::spawn(move || {
            let mut last_seen = 0;
            let mut checks = 0u64;
            while !done.load(Ordering::Acquire) {
                let snapshot = store.snapshot();
                let left_counter = snapshot.get(left, b"counter").unwrap();
                let right_counter = snapshot.get(right, b"counter").unwrap();
                // Atomicity: both halves of a batch, or neither.
                assert_eq!(left_counter, right_counter);
                let Some(counter) = left_counter else {
                    continue;
                };
                let counter = u64::from_be_bytes(counter.try_into().unwrap());

                // Monotonicity: a later snapshot never goes back in time.
                assert!(counter >= last_seen);
                last_seen = counter;

                // Consistency: the snapshot holds keys 0..=counter plus the counter key.
                assert_eq!(snapshot.len(left).unwrap() as u64, counter + 2);
                // A full scan reads every value, some from segments compaction already deleted.
                let mut values = 0u64;
                for entry in snapshot.prefix(left, &[0]).unwrap() {
                    let (key, value) = entry.unwrap();
                    let i = u64::from_be_bytes(key.try_into().unwrap());
                    assert_eq!(value, vec![i as u8; 64]);
                    values += 1;
                }
                assert_eq!(values, counter + 1);
                checks += 1;
            }
            checks
        }));
    }

    writer.join().unwrap();
    let checks: u64 = readers
        .into_iter()
        .map(|reader| reader.join().unwrap())
        .sum();
    assert!(checks > 0);
    assert!(store.metrics().compactions() > 0);
}

#[test]
fn concurrent_table_creation_agrees_on_one_handle() {
    // Eight threads race to create the same table: all must get the same identifier.
    let store = Arc::new(Store::in_memory());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || store.table("contended").unwrap()));
    }
    let tables: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert!(tables.windows(2).all(|pair| pair[0] == pair[1]));
    // Only one catalog entry was written.
    assert_eq!(store.metrics().batches(), 1);
}
