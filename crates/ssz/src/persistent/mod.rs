//! Persistent collections: cheap to clone, and re-hashed only where they changed.
//!
//! # Overview
//!
//! A beacon state holds a few huge collections: validators, balances, participation flags.
//! A node hashes the state every slot and keeps many copies of it.
//! With plain buffers, each root re-hashes every element and each copy duplicates them.
//!
//! These collections encode and hash exactly like the plain ones.
//! They differ only in their storage, which makes both operations proportional to the change.
//!
//! # Algorithm
//!
//! The elements live in packs, each holding the elements of 2^6 consecutive leaves.
//! Each pack is one aligned subtree of the spec's hash tree, so it caches that subtree's root.
//!
//! 1. A clone copies one pointer to the table of packs.
//! 2. The first edit after a clone copies the table, a pointer per pack.
//! 3. An edit copies the one pack it touches and clears that pack's root.
//! 4. A root hashes the packs whose roots are clear, on all cores when there are many.
//! 5. It then folds the cached pack roots, padded with zero subtrees, up to the root.
//! 6. The collection caches that root too, so an unchanged collection costs nothing.
//!
//! A progressive tree's subtrees start at leaf offsets that a shifted grid of packs still fits.
//! The first pack holds the small subtrees before that grid starts, see EIP-7916.
//!
//! # Invariants
//!
//! A cached root, when present, is the root of the elements as they are now.
//! Every edit of a pack or of the table passes through one method that clears the root first.
//! Equality, hashing, and encoding read only the elements, never a cached root.
//!
//! # Performance
//!
//! A flat table, not a deep tree, holds the packs.
//! Indexing is a shift, a mask, and a few loads, with no walk down a tree.
//! The fold over pack roots is linear in the pack count, a few milliseconds for a mainnet registry.
//!
//! An edit through an index checks two reference counts, so long loops prefer the edit iterator.
//!
//! Memory stays close to the plain buffers: one cached root per 64 leaves.
//!
//! The common alternative is a deep persistent tree with a hash per node.
//! It costs memory, and every index walks the tree.
//! A hash cache kept beside the value instead must be rebuilt after a clone.
//! Here the cache is part of the value, so a clone keeps it, and no caller ever sees it.

mod iter;
mod layout;
mod list;
mod pack;
mod progressive_list;
mod sequence;
mod sequence_mut;
mod threads;
mod vector;

pub use iter::{Iter, IterMut};
pub use list::PersistentList;
pub use progressive_list::PersistentProgressiveList;
pub use sequence::Sequence;
pub use sequence_mut::SequenceMut;
pub use vector::PersistentVector;
