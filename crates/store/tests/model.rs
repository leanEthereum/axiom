//! Model checking: random operation sequences against an ordered map per table.

mod support;

use std::collections::BTreeMap;

use axiom_store::{Batch, Options, Snapshot, Store, SyncPolicy, Table};
use proptest::prelude::*;
use support::TempDir;

/// Number of tables the operations spread over.
const TABLES: usize = 3;

/// The reference: one ordered map per table.
type Model = Vec<BTreeMap<Vec<u8>, Vec<u8>>>;

#[derive(Clone, Debug)]
enum Write {
    Put {
        table: usize,
        key: Vec<u8>,
        len: usize,
        fill: u8,
    },
    Delete {
        table: usize,
        key: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
enum Op {
    Single(Write),
    Batch(Vec<Write>),
    Reopen,
    Compact,
    Snapshot,
}

fn write() -> impl Strategy<Value = Write> {
    // Keys over a 4-letter alphabet, at most 2 bytes: 21 keys per table, so collisions are frequent.
    let key = proptest::collection::vec(0u8..4, 0..3);
    // Values up to 300 bytes against 256-byte segments: rotations happen every few writes.
    prop_oneof![
        3 => (0..TABLES, key.clone(), 0usize..300, any::<u8>())
            .prop_map(|(table, key, len, fill)| Write::Put { table, key, len, fill }),
        2 => (0..TABLES, key).prop_map(|(table, key)| Write::Delete { table, key }),
    ]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        8 => write().prop_map(Op::Single),
        3 => proptest::collection::vec(write(), 1..6).prop_map(Op::Batch),
        1 => Just(Op::Reopen),
        2 => Just(Op::Compact),
        1 => Just(Op::Snapshot),
    ]
}

/// Adds one write to a batch and mirrors it in the model.
fn stage(batch: &mut Batch, model: &mut Model, tables: &[Table], write: &Write) {
    match write {
        Write::Put {
            table,
            key,
            len,
            fill,
        } => {
            let value = vec![*fill; *len];
            batch
                .put(tables[*table], key, &value)
                .expect("store operation succeeds");
            model[*table].insert(key.clone(), value);
        }
        Write::Delete { table, key } => {
            batch
                .delete(tables[*table], key)
                .expect("store operation succeeds");
            model[*table].remove(key);
        }
    }
}

/// Asserts that a snapshot holds exactly the model, through iteration and point reads.
fn assert_matches(snapshot: &Snapshot, tables: &[Table], model: &Model) {
    for (table, expected) in tables.iter().zip(model) {
        let entries: BTreeMap<_, _> = snapshot
            .entries(*table)
            .expect("store operation succeeds")
            .map(Result::unwrap)
            .collect();
        assert_eq!(&entries, expected);
        for (key, value) in expected {
            assert_eq!(
                snapshot
                    .get(*table, key)
                    .expect("store operation succeeds")
                    .as_ref(),
                Some(value)
            );
        }
        assert_eq!(
            snapshot.len(*table).expect("store operation succeeds"),
            expected.len()
        );
    }
}

/// Opens a store and resolves the table handles by name.
fn open(dir: Option<&TempDir>, options: Options) -> (Store, Vec<Table>) {
    let store = match dir {
        Some(dir) => Store::open(dir.path(), options).expect("store operation succeeds"),
        None => Store::in_memory(),
    };
    let tables = (0..TABLES)
        .map(|i| {
            store
                .table(&format!("table {i}"))
                .expect("store operation succeeds")
        })
        .collect();
    (store, tables)
}

/// Runs a sequence against one backend, checking it against the model after every step.
fn run(ops: &[Op], options: Options, on_disk: bool) {
    let dir = on_disk.then(|| TempDir::new("model"));
    let (mut store, mut tables) = open(dir.as_ref(), options);
    let mut model: Model = vec![BTreeMap::new(); TABLES];
    // Snapshots with the model as it stood when each was taken.
    let mut frozen = Vec::new();

    for op in ops {
        match op {
            Op::Single(write) => {
                let mut batch = Batch::new();
                stage(&mut batch, &mut model, &tables, write);
                store.write(&batch).expect("store operation succeeds");
            }
            Op::Batch(writes) => {
                let mut batch = Batch::new();
                for write in writes {
                    stage(&mut batch, &mut model, &tables, write);
                }
                store.write(&batch).expect("store operation succeeds");
            }
            Op::Reopen => {
                // The memory backend has nothing to reopen; the disk backend replays its log.
                if on_disk {
                    drop(store);
                    (store, tables) = open(dir.as_ref(), options);
                }
            }
            Op::Compact => store.compact().expect("store operation succeeds"),
            Op::Snapshot => frozen.push((store.snapshot(), model.clone())),
        }
        assert_matches(&store.snapshot(), &tables, &model);
    }

    // Snapshots never change, across later writes, compactions and even reopens.
    for (snapshot, model) in &frozen {
        assert_matches(snapshot, &tables, model);
    }

    // A final reopen restores the final model.
    if on_disk {
        drop(store);
        let (store, tables) = open(dir.as_ref(), options);
        assert_matches(&store.snapshot(), &tables, &model);
    }
}

fn options() -> impl Strategy<Value = Options> {
    (0u8..=100, any::<bool>()).prop_map(|(compaction_threshold, auto_compact)| Options {
        sync: SyncPolicy::Manual,
        segment_size: 256,
        compaction_threshold,
        auto_compact,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn disk_store_matches_model(ops in proptest::collection::vec(op(), 1..60), options in options()) {
        run(&ops, options, true);
    }

    #[test]
    fn memory_store_matches_model(ops in proptest::collection::vec(op(), 1..60)) {
        run(&ops, Options::default(), false);
    }
}
