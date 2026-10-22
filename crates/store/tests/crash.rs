//! Crash recovery: every torn or corrupt tail reopens to the last whole batch.

mod support;

use std::{collections::BTreeMap, fs, path::Path};

use axiom_store::{Batch, Options, Store, SyncPolicy, Table};
use support::{TempDir, segment_files, small_segments};

/// Every table's content, as ordered maps.
type Dump = Vec<BTreeMap<Vec<u8>, Vec<u8>>>;

/// Opens a store, resolves two tables, and reads both whole.
fn dump(dir: &Path, options: Options) -> Dump {
    let store = Store::open(dir, options).expect("fixture operation succeeds");
    let snapshot = store.snapshot();
    tables(&store)
        .into_iter()
        .map(|table| {
            snapshot
                .entries(table)
                .expect("fixture operation succeeds")
                .map(Result::unwrap)
                .collect()
        })
        .collect()
}

/// Resolves the two tables every fixture uses.
fn tables(store: &Store) -> [Table; 2] {
    [
        store.table("blocks").expect("fixture operation succeeds"),
        store.table("states").expect("fixture operation succeeds"),
    ]
}

/// Copies every file of one directory into another.
fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("fixture operation succeeds");
    for entry in fs::read_dir(from).expect("fixture operation succeeds") {
        let path = entry.expect("fixture operation succeeds").path();
        fs::copy(
            &path,
            to.join(path.file_name().expect("fixture operation succeeds")),
        )
        .expect("fixture operation succeeds");
    }
}

/// Copies a directory, then replaces one segment's bytes.
fn clone_with_segment(from: &Path, to: &Path, segment: &str, bytes: &[u8]) {
    copy_dir(from, to);
    fs::write(to.join(segment), bytes).expect("fixture operation succeeds");
}

/// A store with three committed batches, then a fourth whose bytes are returned separately.
///
/// Returns the segment bytes without and with the last batch, and both dumps.
fn fixture(dir: &Path) -> (Vec<u8>, Vec<u8>, Dump, Dump) {
    let options = Options::default();
    {
        let store = Store::open(dir, options).expect("fixture operation succeeds");
        let [blocks, states] = tables(&store);
        store
            .put(blocks, b"a", b"block a")
            .expect("fixture operation succeeds");
        store
            .put(states, b"a", &[1; 40])
            .expect("fixture operation succeeds");
        store
            .delete(blocks, b"missing")
            .expect("fixture operation succeeds");
    }
    let segment = dir.join("00000000.seg");
    let before = fs::read(&segment).expect("fixture operation succeeds");
    let dump_before = dump(dir, options);

    // The last batch touches both tables: an overwrite, a new key, and a delete.
    //
    //     frame: 16 header + (12 + 1 + 7) + (12 + 1 + 64) + (12 + 1) = 126 bytes
    {
        let store = Store::open(dir, options).expect("fixture operation succeeds");
        let [blocks, states] = tables(&store);
        let mut batch = Batch::new();
        batch
            .put(blocks, b"a", b"block A")
            .expect("fixture operation succeeds");
        batch
            .put(states, b"b", &[2; 64])
            .expect("fixture operation succeeds");
        batch
            .delete(states, b"a")
            .expect("fixture operation succeeds");
        store.write(&batch).expect("fixture operation succeeds");
    }
    let after = fs::read(&segment).expect("fixture operation succeeds");
    let dump_after = dump(dir, options);
    assert_eq!(after.len() - before.len(), 126);
    assert_ne!(dump_before, dump_after);
    (before, after, dump_before, dump_after)
}

#[test]
fn truncation_at_every_offset_of_the_last_batch() {
    let source = TempDir::new("crash-source");
    let (before, after, dump_before, dump_after) = fixture(source.path());

    // A crash can cut the file anywhere inside the last frame: 126 cut points.
    //
    //     | ... committed frames ... | last frame ............. |
    //                                ^ before.len()             ^ after.len()
    //     cut in [before.len(), after.len()) -> state before the batch
    for cut in before.len()..=after.len() {
        let dir = TempDir::new("crash-truncate");
        clone_with_segment(source.path(), dir.path(), "00000000.seg", &after[..cut]);

        let expected = if cut == after.len() {
            &dump_after
        } else {
            &dump_before
        };
        assert_eq!(
            &dump(dir.path(), Options::default()),
            expected,
            "cut at {cut}"
        );

        // Recovery cut the torn frame off the file, so the tail is a frame boundary again.
        let expected_len = if cut == after.len() {
            after.len()
        } else {
            before.len()
        };
        let len = fs::metadata(dir.path().join("00000000.seg")).unwrap().len();
        assert_eq!(len as usize, expected_len, "cut at {cut}");
    }
}

#[test]
fn bit_flips_at_every_offset_of_the_last_batch() {
    let source = TempDir::new("crash-source");
    let (before, after, dump_before, _) = fixture(source.path());

    // Every single-bit error inside the last frame fails one of its checksums.
    //
    //     flip in frame header -> header checksum fails
    //     flip in an entry     -> that entry's checksum fails
    for offset in before.len()..after.len() {
        for bit in [0x01, 0x80] {
            let mut damaged = after.clone();
            damaged[offset] ^= bit;
            let dir = TempDir::new("crash-flip");
            clone_with_segment(source.path(), dir.path(), "00000000.seg", &damaged);
            assert_eq!(
                dump(dir.path(), Options::default()),
                dump_before,
                "flip {bit:#x} at {offset}"
            );
        }
    }
}

#[test]
fn zero_filled_tails_are_discarded() {
    // Some filesystems extend a file before its data lands, leaving zeros after a crash.
    let source = TempDir::new("crash-source");
    let (_, after, _, dump_after) = fixture(source.path());

    for zeros in [1, 15, 16, 17, 4096] {
        let mut padded = after.clone();
        padded.resize(after.len() + zeros, 0);
        let dir = TempDir::new("crash-zeros");
        clone_with_segment(source.path(), dir.path(), "00000000.seg", &padded);
        assert_eq!(
            dump(dir.path(), Options::default()),
            dump_after,
            "{zeros} zeros"
        );
    }
}

#[test]
fn recovered_store_accepts_new_writes_after_the_cut() {
    let source = TempDir::new("crash-source");
    let (before, after, _, _) = fixture(source.path());

    // Fixture state: the last frame is torn in its middle, 60 bytes in.
    let dir = TempDir::new("crash-continue");
    clone_with_segment(
        source.path(),
        dir.path(),
        "00000000.seg",
        &after[..before.len() + 60],
    );

    // A write after recovery starts on the cut frame boundary and survives a reopen.
    {
        let store = Store::open(dir.path(), Options::default()).unwrap();
        let [blocks, _] = tables(&store);
        store.put(blocks, b"z", b"after the crash").unwrap();
    }
    let store = Store::open(dir.path(), Options::default()).unwrap();
    let [blocks, _] = tables(&store);
    assert_eq!(
        store.get(blocks, b"z").unwrap(),
        Some(b"after the crash".to_vec())
    );
    assert_eq!(store.get(blocks, b"a").unwrap(), Some(b"block a".to_vec()));
}

#[test]
fn corruption_mid_log_keeps_the_prefix_before_it() {
    // Recovery cannot resynchronize past a bad frame, as frames carry no sync marker.
    // It keeps the longest valid prefix, the same choice as LevelDB's default recovery.
    let source = TempDir::new("crash-source");
    let (before, after, _, _) = fixture(source.path());

    // Mutation: damage the second-to-last frame, the 40-byte put into "states".
    //
    //     | ... | put states a (16 + 12 + 1 + 40 = 69) | delete (29) | last batch (126) |
    let second_to_last = before.len() - 29 - 69;
    let mut damaged = after;
    damaged[second_to_last + 30] ^= 0x01;
    let dir = TempDir::new("crash-mid");
    clone_with_segment(source.path(), dir.path(), "00000000.seg", &damaged);

    // Only the frames before the damage remain: the first put, nothing after it.
    let dump = dump(dir.path(), Options::default());
    assert_eq!(
        dump[0],
        BTreeMap::from([(b"a".to_vec(), b"block a".to_vec())])
    );
    assert!(dump[1].is_empty());
}

#[test]
fn compaction_interrupted_before_or_during_deletion_loses_nothing() {
    let source = TempDir::new("crash-compact");
    let options = Options {
        sync: SyncPolicy::EveryBatch,
        ..small_segments()
    };

    // Fixture state: 8 keys rewritten 6 times across many small segments.
    {
        let store = Store::open(source.path(), options).unwrap();
        let [blocks, states] = tables(&store);
        for round in 0u8..6 {
            for key in 0u8..8 {
                let table = if key % 2 == 0 { blocks } else { states };
                store.put(table, &[key], &[round; 50]).unwrap();
            }
            store.delete(blocks, &[round]).unwrap();
        }
    }
    let expected = dump(source.path(), options);
    let originals: Vec<_> = fs::read_dir(source.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension().is_some_and(|ext| {
                ext.eq_ignore_ascii_case("seg") || ext.eq_ignore_ascii_case("hint")
            })
        })
        .map(|path| {
            (
                path.file_name().unwrap().to_owned(),
                fs::read(&path).unwrap(),
            )
        })
        .collect();

    // Compact for real, and note which segments it deleted.
    let compacted = TempDir::new("crash-compacted");
    copy_dir(source.path(), compacted.path());
    Store::open(compacted.path(), options)
        .unwrap()
        .compact()
        .unwrap();
    let survivors: Vec<_> = segment_files(compacted.path())
        .iter()
        .map(|path| path.file_name().unwrap().to_owned())
        .collect();
    let mut victims: Vec<_> = originals
        .iter()
        .filter(|(name, _)| {
            Path::new(name).extension().is_some_and(|ext| ext == "seg") && !survivors.contains(name)
        })
        .map(|(name, _)| name.clone())
        .collect();
    victims.sort();
    assert!(victims.len() >= 3);

    // Deletion goes oldest first, so a crash leaves a newest-first suffix of the victims.
    //
    //     victims [v0, v1, v2, v3]: crash states keep [], [v3], [v2, v3], ... [v0 .. v3]
    for kept in 0..=victims.len() {
        let dir = TempDir::new("crash-partial");
        copy_dir(compacted.path(), dir.path());
        for victim in &victims[victims.len() - kept..] {
            let stem = victim.to_str().unwrap().trim_end_matches(".seg");
            for (name, bytes) in &originals {
                if name.to_str().unwrap().starts_with(stem) {
                    fs::write(dir.path().join(name), bytes).unwrap();
                }
            }
        }
        // Copies and originals coexist; replay order makes the copies win.
        assert_eq!(
            dump(dir.path(), options),
            expected,
            "{kept} victims left behind"
        );
    }
}
