//! One test per operation of the public interface, on the disk backend unless stated.

mod support;

use std::{fs, ops::Bound};

use axiom_store::{Batch, Error, Options, Store, SyncPolicy};
use support::{TempDir, segment_files, small_segments};

#[test]
fn put_get_and_missing_keys() {
    let dir = TempDir::new("put-get");
    let store = Store::open(dir.path(), Options::default()).unwrap();
    let blocks = store.table("blocks").unwrap();

    // A key never written reads as absent, not as an error.
    assert_eq!(store.get(blocks, b"root").unwrap(), None);
    assert!(!store.contains_key(blocks, b"root").unwrap());

    store.put(blocks, b"root", b"block").unwrap();
    assert_eq!(store.get(blocks, b"root").unwrap(), Some(b"block".to_vec()));
    assert!(store.contains_key(blocks, b"root").unwrap());

    // The empty key and the empty value are ordinary values.
    store.put(blocks, b"", b"").unwrap();
    assert_eq!(store.get(blocks, b"").unwrap(), Some(Vec::new()));
}

#[test]
fn overwrite_returns_the_latest_value() {
    let dir = TempDir::new("overwrite");
    let store = Store::open(dir.path(), Options::default()).unwrap();
    let states = store.table("states").unwrap();

    // Three versions of one key: only the last is visible.
    store.put(states, b"head", b"v1").unwrap();
    store.put(states, b"head", b"v2").unwrap();
    store.put(states, b"head", b"v3").unwrap();
    assert_eq!(store.get(states, b"head").unwrap(), Some(b"v3".to_vec()));
    assert_eq!(store.snapshot().len(states).unwrap(), 1);
}

#[test]
fn delete_removes_and_tolerates_absent_keys() {
    let dir = TempDir::new("delete");
    let store = Store::open(dir.path(), Options::default()).unwrap();
    let blobs = store.table("blobs").unwrap();

    store.put(blobs, b"a", b"1").unwrap();
    store.delete(blobs, b"a").unwrap();
    assert_eq!(store.get(blobs, b"a").unwrap(), None);

    // Deleting a key that was never there succeeds and changes nothing.
    store.delete(blobs, b"never").unwrap();
    assert_eq!(store.snapshot().len(blobs).unwrap(), 0);

    // The deletion survives a reopen: the tombstone shadows the older put.
    drop(store);
    let store = Store::open(dir.path(), Options::default()).unwrap();
    assert_eq!(store.get(blobs, b"a").unwrap(), None);
}

#[test]
fn batches_apply_atomically_across_tables_in_order() {
    let dir = TempDir::new("batch");
    let store = Store::open(dir.path(), Options::default()).unwrap();
    let blocks = store.table("blocks").unwrap();
    let states = store.table("states").unwrap();
    store.put(states, b"old", b"state").unwrap();

    // One batch: two tables, an overwrite within the batch, and a delete.
    let mut batch = Batch::new();
    batch.put(blocks, b"r", b"first").unwrap();
    batch.put(states, b"r", b"state r").unwrap();
    batch.put(blocks, b"r", b"second").unwrap();
    batch.delete(states, b"old").unwrap();
    assert_eq!(batch.len(), 4);

    // A snapshot taken before the commit sees none of it.
    let before = store.snapshot();
    store.write(&batch).unwrap();
    assert_eq!(before.get(blocks, b"r").unwrap(), None);
    assert_eq!(before.get(states, b"old").unwrap(), Some(b"state".to_vec()));

    // After the commit, all of it, with the later put winning.
    assert_eq!(store.get(blocks, b"r").unwrap(), Some(b"second".to_vec()));
    assert_eq!(store.get(states, b"r").unwrap(), Some(b"state r".to_vec()));
    assert_eq!(store.get(states, b"old").unwrap(), None);

    // An empty batch is a no-op and writes no frame.
    let written = store.metrics().bytes_written();
    store.write(&Batch::new()).unwrap();
    assert_eq!(store.metrics().bytes_written(), written);
}

#[test]
fn table_handles_are_stable_across_reopen() {
    let dir = TempDir::new("tables");
    let (blocks, states) = {
        let store = Store::open(dir.path(), Options::default()).unwrap();
        let blocks = store.table("blocks").unwrap();
        let states = store.table("states").unwrap();
        // Asking again for an existing name returns the same handle.
        assert_eq!(store.table("blocks").unwrap(), blocks);
        assert_ne!(blocks, states);
        // Tables are separate namespaces: one key, two values.
        store.put(blocks, b"k", b"block").unwrap();
        store.put(states, b"k", b"state").unwrap();
        (blocks, states)
    };

    // Reopen and ask in the opposite order: the persisted catalog decides, not the order.
    let store = Store::open(dir.path(), Options::default()).unwrap();
    assert_eq!(store.table("states").unwrap(), states);
    assert_eq!(store.table("blocks").unwrap(), blocks);
    assert_eq!(store.get(blocks, b"k").unwrap(), Some(b"block".to_vec()));
    assert_eq!(store.get(states, b"k").unwrap(), Some(b"state".to_vec()));
}

#[test]
fn table_names_and_count_are_bounded() {
    let store = Store::in_memory();

    // Names must be 1 to 64 bytes.
    assert!(matches!(
        store.table(""),
        Err(Error::InvalidTableName { length: 0 })
    ));
    assert!(matches!(
        store.table(&"x".repeat(65)),
        Err(Error::InvalidTableName { length: 65 })
    ));
    store.table(&"x".repeat(64)).unwrap();

    // Identifier 0 is the catalog, so 255 user tables fit; the 64-byte one above is the first.
    for i in 1..255 {
        store.table(&format!("t{i}")).unwrap();
    }
    assert!(matches!(
        store.table("one too many"),
        Err(Error::TooManyTables)
    ));
    // Existing names still resolve when the table space is full.
    store.table("t1").unwrap();
}

#[test]
fn handles_of_another_store_are_rejected() {
    // Store A has two tables, store B has one.
    let a = Store::in_memory();
    a.table("first").unwrap();
    let second = a.table("second").unwrap();
    let b = Store::in_memory();
    b.table("only").unwrap();

    // A handle with identifier 2 means nothing to store B.
    assert!(matches!(b.get(second, b"k"), Err(Error::UnknownTable(t)) if t == second));
    assert!(matches!(b.put(second, b"k", b"v"), Err(Error::UnknownTable(t)) if t == second));
    assert!(matches!(
        b.snapshot().entries(second),
        Err(Error::UnknownTable(_))
    ));
}

#[test]
fn oversized_keys_are_rejected() {
    let store = Store::in_memory();
    let table = store.table("t").unwrap();
    let key = vec![0; 65_536];
    assert!(matches!(
        store.put(table, &key, b"v"),
        Err(Error::KeyTooLong(65_536))
    ));
    assert!(matches!(
        store.delete(table, &key),
        Err(Error::KeyTooLong(65_536))
    ));
}

#[test]
fn ranges_prefixes_and_reverse_iteration() {
    let dir = TempDir::new("ranges");
    let store = Store::open(dir.path(), small_segments()).unwrap();
    let by_slot = store.table("blocks_by_slot").unwrap();

    // Fixture state: slots 0 to 9, big-endian so byte order equals numeric order.
    for slot in 0u64..10 {
        store
            .put(by_slot, &slot.to_be_bytes(), &[slot as u8])
            .unwrap();
    }
    let snapshot = store.snapshot();
    let three = 3u64.to_be_bytes();
    let six = 6u64.to_be_bytes();

    // Half-open range [3, 6): slots 3, 4, 5, values included.
    let entries: Vec<_> = snapshot
        .range(by_slot, &three[..]..&six[..])
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let expected: Vec<_> = (3u64..6)
        .map(|s| (s.to_be_bytes().to_vec(), vec![s as u8]))
        .collect();
    assert_eq!(entries, expected);

    // From the back: the newest slot first, the way a head lookup walks.
    let newest: Vec<_> = snapshot
        .entries(by_slot)
        .unwrap()
        .rev()
        .take(2)
        .map(Result::unwrap)
        .collect();
    assert_eq!(newest[0].1, vec![9]);
    assert_eq!(newest[1].1, vec![8]);

    // Explicit bounds: (3, 6] holds 4, 5, 6.
    let keys: Vec<_> = snapshot
        .range::<[u8], _>(
            by_slot,
            (Bound::Excluded(&three[..]), Bound::Included(&six[..])),
        )
        .unwrap()
        .keys()
        .collect();
    assert_eq!(
        keys,
        vec![
            4u64.to_be_bytes().to_vec(),
            5u64.to_be_bytes().to_vec(),
            six.to_vec()
        ]
    );

    // An inverted range is empty, not a panic.
    assert_eq!(
        snapshot
            .range(by_slot, &six[..]..&three[..])
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn prefix_scans_handle_the_top_byte() {
    let store = Store::in_memory();
    let table = store.table("t").unwrap();
    // Fixture state: keys around the 0xff boundary.
    for key in [
        &[0x01, 0xfe][..],
        &[0x01, 0xff],
        &[0x01, 0xff, 0x00],
        &[0x02],
        &[0xff, 0xff],
        &[0xff, 0xff, 0x01],
    ] {
        store.put(table, key, b"").unwrap();
    }
    let snapshot = store.snapshot();
    let keys = |prefix: &[u8]| -> Vec<Vec<u8>> {
        snapshot.prefix(table, prefix).unwrap().keys().collect()
    };

    // Prefix [0x01, 0xff] ends before its successor [0x02].
    assert_eq!(
        keys(&[0x01, 0xff]),
        vec![vec![0x01, 0xff], vec![0x01, 0xff, 0x00]]
    );
    // Prefix [0xff, 0xff] has no successor: it runs to the end.
    assert_eq!(
        keys(&[0xff, 0xff]),
        vec![vec![0xff, 0xff], vec![0xff, 0xff, 0x01]]
    );
    // The empty prefix matches everything.
    assert_eq!(keys(&[]).len(), 6);
}

#[test]
fn snapshots_survive_compaction_of_their_segments() {
    let dir = TempDir::new("snapshot-compaction");
    let store = Store::open(dir.path(), small_segments()).unwrap();
    let states = store.table("states").unwrap();

    // Fixture state: segment 0 holds the 30-byte catalog frame.
    // A 229-byte frame does not fit after it, so the first value opens segment 1.
    //
    //     16 + 30 + 229 = 275 > 256 -> rotate
    store.put(states, b"s", &[1; 200]).unwrap();
    let snapshot = store.snapshot();

    // The overwrite rotates again, into segment 2, and segment 1 is now fully dead.
    store.put(states, b"s", &[2; 200]).unwrap();
    store.compact().unwrap();
    assert_eq!(store.metrics().compactions(), 1);
    assert!(!dir.path().join("00000001.seg").exists());

    // The file is unlinked, but the snapshot's open handle still reads the old value.
    assert_eq!(snapshot.get(states, b"s").unwrap(), Some(vec![1; 200]));
    assert_eq!(store.get(states, b"s").unwrap(), Some(vec![2; 200]));
}

#[test]
fn compaction_keeps_tombstones_that_shadow_older_segments() {
    let dir = TempDir::new("tombstone");
    let options = small_segments();
    let store = Store::open(dir.path(), options).unwrap();
    let t = store.table("t").unwrap();

    // Segment 0 holds the 30-byte catalog frame.
    //
    // Segment 1 (one 243-byte frame): "k" and a large live "l".
    //     after the delete below: 16 + 14 of 243 bytes are dead -> 12%, survives
    let mut batch = Batch::new();
    batch.put(t, b"k", b"v").unwrap();
    batch.put(t, b"l", &[7; 200]).unwrap();
    store.write(&batch).unwrap();

    // Segment 2: the tombstone of "k", alone.
    store.delete(t, b"k").unwrap();
    // Segment 3: a large value whose arrival seals segment 2.
    store.put(t, b"m", &[9; 230]).unwrap();

    // Segment 2 is 100% dead, so it is rewritten; segment 1 survives and still holds k=v.
    store.compact().unwrap();
    assert!(!dir.path().join("00000002.seg").exists());
    assert!(dir.path().join("00000001.seg").exists());

    // Replay sees k=v in segment 1, then the forwarded tombstone in segment 3: still deleted.
    drop(store);
    let store = Store::open(dir.path(), options).unwrap();
    assert_eq!(store.get(t, b"k").unwrap(), None);
    assert_eq!(store.get(t, b"l").unwrap(), Some(vec![7; 200]));
    assert_eq!(store.get(t, b"m").unwrap(), Some(vec![9; 230]));
}

#[test]
fn compaction_reclaims_overwritten_space() {
    let dir = TempDir::new("reclaim");
    let options = Options {
        segment_size: 4096,
        ..small_segments()
    };
    let store = Store::open(dir.path(), options).unwrap();
    let t = store.table("t").unwrap();

    // Fixture state: 10 keys of 100-byte values, each overwritten 20 times.
    //
    //     live: 10 * (12 + 1 + 100) = 1130 bytes plus the catalog entry
    //     written: about 200 * 129 = 25800 bytes across 7 segments
    for round in 0u8..20 {
        for key in 0u8..10 {
            store.put(t, &[key], &[round; 100]).unwrap();
        }
    }
    let before = store.metrics();
    assert!(before.segments() > 5);

    store.compact().unwrap();
    let after = store.metrics();

    // The active segment was mostly dead too, so it was sealed and rewritten as well.
    // All live entries now sit in one fresh active segment.
    assert_eq!(after.segments(), 1);
    assert!(after.disk_bytes() < before.disk_bytes() / 4);
    assert_eq!(after.live_bytes(), before.live_bytes());
    assert!(after.bytes_reclaimed() > 0);

    // Content is unchanged, before and after a reopen.
    for key in 0u8..10 {
        assert_eq!(store.get(t, &[key]).unwrap(), Some(vec![19; 100]));
    }
    drop(store);
    let store = Store::open(dir.path(), options).unwrap();
    for key in 0u8..10 {
        assert_eq!(store.get(t, &[key]).unwrap(), Some(vec![19; 100]));
    }
}

#[test]
fn automatic_compaction_runs_on_rotation() {
    let dir = TempDir::new("auto");
    let options = Options {
        auto_compact: true,
        ..small_segments()
    };
    let store = Store::open(dir.path(), options).unwrap();
    let t = store.table("t").unwrap();

    // One key rewritten 50 times: each rotation finds a fully dead sealed segment.
    for round in 0u8..50 {
        store.put(t, b"k", &[round; 100]).unwrap();
    }
    let metrics = store.metrics();
    assert!(metrics.compactions() > 0);
    // Without compaction there would be about 25 segments.
    assert!(metrics.segments() <= 3, "{} segments", metrics.segments());
    assert_eq!(store.get(t, b"k").unwrap(), Some(vec![49; 100]));
}

#[test]
fn a_second_handle_is_locked_out() {
    let dir = TempDir::new("lock");
    let store = Store::open(dir.path(), Options::default()).unwrap();

    // The lock is per open file description: the same process is refused too.
    let second = Store::open(dir.path(), Options::default());
    assert!(matches!(second, Err(Error::Locked(path)) if path == dir.path()));

    // Closing releases it.
    drop(store);
    Store::open(dir.path(), Options::default()).unwrap();
}

#[test]
fn large_values_round_trip_across_reopen() {
    let dir = TempDir::new("large");
    // 8 MiB with a pattern, so a misplaced read cannot pass by accident.
    let value: Vec<u8> = (0..8 << 20).map(|i: u32| (i % 251) as u8).collect();
    {
        let store = Store::open(dir.path(), Options::default()).unwrap();
        let states = store.table("states").unwrap();
        store.put(states, b"state", &value).unwrap();
        assert_eq!(
            store.get(states, b"state").unwrap().as_deref(),
            Some(&value[..])
        );
    }
    let store = Store::open(dir.path(), Options::default()).unwrap();
    let states = store.table("states").unwrap();
    assert_eq!(
        store.get(states, b"state").unwrap().as_deref(),
        Some(&value[..])
    );
}

#[test]
fn recovery_rebuilds_missing_hints() {
    let dir = TempDir::new("hints");
    let options = small_segments();
    {
        let store = Store::open(dir.path(), options).unwrap();
        let t = store.table("t").unwrap();
        // 30 puts of 60 bytes: about 8 segments, 7 of them sealed with hints.
        for i in 0u8..30 {
            store.put(t, &[i], &[i; 60]).unwrap();
        }
    }
    let hints = || {
        fs::read_dir(dir.path())
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "hint")
            })
            .count()
    };
    let sealed = segment_files(dir.path()).len() - 1;
    assert!(sealed >= 5);
    assert_eq!(hints(), sealed);

    // Mutation: delete every hint, as if each crash hit between seal and hint.
    for entry in fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "hint") {
            fs::remove_file(path).unwrap();
        }
    }

    // Recovery scans the sealed segments instead, and writes their hints back.
    let store = Store::open(dir.path(), options).unwrap();
    let t = store.table("t").unwrap();
    for i in 0u8..30 {
        assert_eq!(store.get(t, &[i]).unwrap(), Some(vec![i; 60]));
    }
    assert_eq!(hints(), sealed);
}

#[test]
fn recovery_cleans_leftovers_of_interrupted_operations() {
    let dir = TempDir::new("leftovers");
    {
        let store = Store::open(dir.path(), Options::default()).unwrap();
        let t = store.table("t").unwrap();
        store.put(t, b"k", b"v").unwrap();
    }
    // Mutation 1: a hint whose rename never happened.
    fs::write(dir.path().join("00000000.hint.tmp"), b"half a hint").unwrap();
    // Mutation 2: a hint whose segment compaction already deleted.
    fs::write(dir.path().join("0000000a.hint"), b"orphan").unwrap();
    // Mutation 3: a segment whose creation crashed inside its 16-byte header.
    fs::write(dir.path().join("00000001.seg"), b"AXIOM").unwrap();

    let store = Store::open(dir.path(), Options::default()).unwrap();
    let t = store.table("t").unwrap();
    assert_eq!(store.get(t, b"k").unwrap(), Some(b"v".to_vec()));
    assert!(!dir.path().join("00000000.hint.tmp").exists());
    assert!(!dir.path().join("0000000a.hint").exists());

    // Segment 1 got a fresh header and accepts writes.
    store.put(t, b"k2", b"v2").unwrap();
    drop(store);
    let store = Store::open(dir.path(), Options::default()).unwrap();
    assert_eq!(store.get(t, b"k2").unwrap(), Some(b"v2".to_vec()));
}

#[test]
fn corrupt_values_in_sealed_segments_fail_their_checksum() {
    let dir = TempDir::new("bitrot");
    let options = small_segments();
    {
        let store = Store::open(dir.path(), options).unwrap();
        let t = store.table("t").unwrap();
        // Segment 0: the catalog frame (30 bytes), then "k" with a 100-byte value.
        store.put(t, b"k", &[5; 100]).unwrap();
        // A 250-byte value seals segment 0.
        store.put(t, b"filler", &[6; 250]).unwrap();
    }

    // Mutation: flip one bit inside the value of "k".
    //
    //     | file header 16 | catalog frame 30 | frame header 16 | entry header 12 | "k" | value ...
    //                                                                   value starts at 16 + 30 + 16 + 12 + 1 = 75
    let path = dir.path().join("00000000.seg");
    let mut bytes = fs::read(&path).unwrap();
    bytes[75 + 40] ^= 0x01;
    fs::write(&path, bytes).unwrap();

    // The sealed segment opens from its hint, so the damage surfaces on read, not at open.
    let store = Store::open(dir.path(), options).unwrap();
    let t = store.table("t").unwrap();
    assert!(matches!(
        store.get(t, b"k"),
        Err(Error::Corruption {
            segment: 0,
            offset: 62,
            reason: "entry checksum mismatch",
        })
    ));
    // Other values are unaffected.
    assert_eq!(store.get(t, b"filler").unwrap(), Some(vec![6; 250]));
}

#[test]
fn metrics_count_bytes_batches_and_syncs() {
    let dir = TempDir::new("metrics");
    let store = Store::open(dir.path(), Options::default()).unwrap();
    let t = store.table("t").unwrap();
    store.put(t, b"k", b"v").unwrap();
    store.get(t, b"k").unwrap();

    // Two frames of 30 bytes each:
    //
    //     catalog: 16 + 12 + key [1, 't'] 2 + value 0 = 30
    //     put:     16 + 12 + key "k" 1 + value "v" 1  = 30
    //
    // Both entries are live: 14 + 14 = 28 bytes.
    let metrics = store.metrics();
    assert_eq!(metrics.batches(), 2);
    assert_eq!(metrics.bytes_written(), 60);
    assert_eq!(metrics.bytes_read(), 14);
    assert_eq!(metrics.syncs(), 2);
    assert_eq!(metrics.segments(), 1);
    assert_eq!(metrics.disk_bytes(), 60);
    assert_eq!(metrics.live_bytes(), 28);
    assert_eq!(metrics.compactions(), 0);
}

#[test]
fn manual_sync_policy_flushes_on_request() {
    let dir = TempDir::new("manual");
    let options = Options {
        sync: SyncPolicy::Manual,
        ..Options::default()
    };
    let store = Store::open(dir.path(), options).unwrap();
    let t = store.table("t").unwrap();
    store.put(t, b"k", b"v").unwrap();

    // No flush per batch; one per explicit sync.
    assert_eq!(store.metrics().syncs(), 0);
    store.sync().unwrap();
    assert_eq!(store.metrics().syncs(), 1);
}

#[test]
fn invalid_options_are_rejected() {
    let dir = TempDir::new("options");
    // A 63-byte segment is one byte short of the 64-byte minimum.
    let tiny = Options {
        segment_size: 63,
        ..Options::default()
    };
    let error = Store::open(dir.path(), tiny).unwrap_err();
    assert!(matches!(error, Error::SegmentSizeTooSmall { size: 63 }));
    assert_eq!(
        error.to_string(),
        "segment size of 63 bytes is below the minimum of 64 bytes"
    );

    // A threshold of 101 percent is past the whole segment.
    let over = Options {
        compaction_threshold: 101,
        ..Options::default()
    };
    assert!(matches!(
        Store::open(dir.path(), over),
        Err(Error::CompactionThresholdTooHigh { threshold: 101 })
    ));
}

#[test]
fn memory_backend_has_the_same_semantics() {
    let store = Store::in_memory();
    let t = store.table("t").unwrap();
    store.put(t, b"a", b"1").unwrap();
    store.put(t, b"b", b"2").unwrap();
    let snapshot = store.snapshot();
    store.delete(t, b"a").unwrap();

    // The snapshot is frozen, the store moves on.
    assert_eq!(snapshot.get(t, b"a").unwrap(), Some(b"1".to_vec()));
    assert_eq!(store.get(t, b"a").unwrap(), None);
    // Compaction and sync are no-ops without a disk.
    store.compact().unwrap();
    store.sync().unwrap();
    assert_eq!(store.metrics().segments(), 0);
    assert_eq!(store.metrics().batches(), 4);
}
