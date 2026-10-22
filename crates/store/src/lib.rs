//! Embedded key-value storage for the beacon node: blocks, states, blobs, columns, fork choice.
//!
//! # Overview
//!
//! The store keeps named tables of byte keys and byte values in one directory.
//!
//! - Point reads, writes and deletes.
//! - Atomic batches across tables.
//! - Ordered range and prefix scans, from either end.
//! - Consistent snapshots in O(1).
//! - An in-memory backend behind the same type, for tests and simulation.
//!
//! ```text
//!               writers (serialized)                 readers (never blocked)
//!                      |                                      |
//!                      v                                      v
//!     +----------------------------------+   swap   +-------------------+
//!     | log: append frame, sync, publish | -------> | current version   |
//!     +----------------------------------+          | per-table index:  |
//!                      |                            |  key -> location  |
//!                      v                            +-------------------+
//!     +---------+---------+-----+--------+                    |
//!     | seg 0   | seg 1   | ... | active | <------- pread ----+
//!     +---------+---------+-----+--------+
//! ```
//!
//! # Algorithm
//!
//! The engine is log-structured, in the family of Bitcask (Sheehy and Smith, Basho, 2010).
//!
//! - Every write appends to a log of segment files; nothing is updated in place.
//! - An in-memory ordered index maps each key to the segment and offset of its value.
//! - Compaction rewrites mostly-dead segments and deletes them.
//! - A hint file per sealed segment lists its keys, so startup never reads old values.
//!
//! The beacon workload decides this shape.
//!
//! - Values are large and written once: a state weighs tens to hundreds of megabytes.
//!   An LSM tree such as LevelDB, Pebble or RocksDB rewrites a value at every level.
//!   Here a value is written once, and again only if compaction moves it.
//! - Keys are few and small: roots, slots and column indices, about a million in all.
//!   An index of every key fits in memory, so a lookup costs no disk read.
//! - Order matters: pruning walks slots, and a head lookup wants the last slot.
//!   Bitcask's hash index cannot scan, so the index here is an ordered tree.
//!
//! Geth keeps chain data in Pebble, an LSM tree, beside flat "freezer" files for old data.
//! Lighthouse splits a hot LevelDB database from a cold freezer database.
//! Both splits exist because LSM write amplification hurts large immutable values.
//! A log with in-memory locations has no such amplification, so one engine serves both roles.
//!
//! The index stores 16-byte locations, never values.
//! A 300 MB state therefore costs the index what a 32-byte root costs.
//!
//! The index is a persistent AVL tree with reference-counted nodes.
//! A snapshot is one pointer copy, and a write copies only the path it changes.
//! A B-tree is denser, but path copying in a B-tree copies whole wide nodes.
//!
//! Both backends are one type.
//! The memory backend's index slots hold value bytes instead of file locations.
//! Every other line, from batches to snapshots, is shared, so no trait or enum is needed.
//!
//! # Invariants
//!
//! Durability:
//!
//! - A batch is one checksummed frame, appended with one positional write.
//! - Under the default sync policy, a write returns once its frame is on stable storage.
//! - Recovery keeps every whole frame and cuts the first torn or corrupt one, with all after it.
//! - Every entry carries a CRC-32C, checked again on each read.
//! - Only the newest segment can be torn: a segment is synced before its successor exists.
//!
//! Concurrency:
//!
//! - A reader clones a pointer to the current version, then holds no lock.
//! - A version never changes once published.
//! - Writers are serialized by one lock, as the log has one tail.
//! - A lock file stops a second handle, in any process, from opening the directory.
//!
//! # Performance
//!
//! Measured on one NVMe drive with a warm page cache, by the ignored benchmark tests.
//!
//! ```text
//!     put 1 KiB, manual sync            ~760k ops/s     ~740 MiB/s
//!     put 1 KiB, sync every batch       ~890 ops/s      one device flush each
//!     put 1 KiB, 1000 per batch         ~280k ops/s     one flush per batch
//!     get 1 KiB                         ~1.06M ops/s
//!     put 1 MiB, manual sync            ~1.7 GiB/s
//!     get 1 MiB                         ~9 GiB/s
//!     open 400 MiB in 7 segments        ~60 ms with hints
//!     open 400 MiB by full scan         ~130 ms, ~3 GiB/s of checksumming
//! ```
//!
//! Limits:
//!
//! - Keys up to 65535 bytes, values up to 4 GiB minus one byte, 255 tables.
//! - Every key lives in memory, at about 100 bytes of overhead plus the key itself.
//! - Unix only: reads rely on positional I/O and on unlinked files staying readable.

mod batch;
mod compaction;
mod directory;
mod error;
mod format;
mod hint;
mod iter;
mod log;
mod map;
mod metrics;
mod options;
mod record;
mod scan;
mod segment;
mod slot;
mod snapshot;
mod store;
mod table;
mod usage;
mod version;

pub use batch::Batch;
pub use error::Error;
pub use iter::{Iter, Keys};
pub use metrics::Metrics;
pub use options::{Options, SyncPolicy};
pub use snapshot::Snapshot;
pub use store::Store;
pub use table::Table;
