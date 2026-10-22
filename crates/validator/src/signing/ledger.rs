//! The durable record of which one-time leaves each stateful key has spent.

use std::{
    path::Path,
    sync::{Mutex, PoisonError},
};

use axiom_store::{Error as StoreError, Options, Store, Table};
use thiserror::Error;

use crate::signing::Leaf;

/// Name of the table mapping a public key to its next unspent leaf.
const NEXT_LEAF: &str = "next_leaf";

/// Every stateful key's next unspent leaf, kept on stable storage.
///
/// # Invariants
///
/// A leaf is recorded as spent before the signature it makes exists.
/// A crash between the two wastes one leaf, and never signs twice with it.
///
/// Reuse is the attack this guards against.
/// Two messages under one one-time leaf reveal enough of it to forge a third.
/// A restored backup or a second client sharing the key reuses leaves the same way.
/// The ledger therefore travels with the key, and keys must never run in two places.
#[derive(Debug)]
pub struct LeafLedger {
    /// The store holding one counter per key.
    store: Store,
    /// The counter table.
    table: Table,
    /// Serializes read, check, and write of a counter.
    reserving: Mutex<()>,
}

impl LeafLedger {
    /// Opens the ledger in a directory, creating it if needed.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot open, such as when another process holds it.
    pub fn open(directory: &Path) -> Result<Self, LedgerError> {
        // Every batch reaches stable storage before the write returns.
        Self::over(Store::open(directory, Options::default())?)
    }

    /// A ledger that lives in memory only, for tests and simulations.
    #[must_use]
    pub fn in_memory() -> Self {
        let store = Store::in_memory();
        // Invariant: a fresh memory store has room for its first table.
        let table = store
            .table(NEXT_LEAF)
            .expect("a fresh store creates its first table");
        Self {
            store,
            table,
            reserving: Mutex::new(()),
        }
    }

    /// A ledger over an open store.
    fn over(store: Store) -> Result<Self, LedgerError> {
        let table = store.table(NEXT_LEAF)?;
        Ok(Self {
            store,
            table,
            reserving: Mutex::new(()),
        })
    }

    /// Spends the next leaf of a key, durably, and returns it.
    ///
    /// # Errors
    ///
    /// Fails when the key has spent all its leaves, or the store fails.
    pub fn reserve(&self, key: &[u8], leaves: u64) -> Result<Leaf, LedgerError> {
        // Two tasks signing with one key must never read the same counter.
        let _reserving = self
            .reserving
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let next = self.next(key)?;
        if next >= leaves {
            return Err(LedgerError::Exhausted { leaves });
        }
        // The spent mark is on disk before the caller can sign.
        self.store.put(self.table, key, &(next + 1).to_be_bytes())?;
        Ok(Leaf(next))
    }

    /// The next unspent leaf of a key, zero for a key that never signed.
    ///
    /// # Errors
    ///
    /// Fails when the store fails or holds a malformed counter.
    pub fn next(&self, key: &[u8]) -> Result<u64, LedgerError> {
        let Some(bytes) = self.store.get(self.table, key)? else {
            return Ok(0);
        };
        let counter: [u8; 8] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| LedgerError::Corrupt { len: bytes.len() })?;
        Ok(u64::from_be_bytes(counter))
    }
}

/// Why a leaf could not be spent.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Every leaf of the key is spent: the key can never sign again.
    #[error("all {leaves} one-time leaves of the key are spent")]
    Exhausted {
        /// Leaves the key held.
        leaves: u64,
    },
    /// A stored counter is not eight bytes.
    #[error("leaf counter of {len} bytes, expected 8")]
    Corrupt {
        /// Bytes found.
        len: usize,
    },
    /// The store failed.
    #[error("leaf ledger store: {0}")]
    Store(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use std::{env, fs, process};

    use super::*;

    #[test]
    fn leaves_are_spent_in_order_until_none_remain() {
        // Fixture state: a key with a supply of 3 leaves.
        let ledger = LeafLedger::in_memory();
        let key = [7; 52];

        // Leaves 0, 1, 2 come out in order, then the supply is gone.
        let spent: Vec<Leaf> = (0..3).map(|_| ledger.reserve(&key, 3).unwrap()).collect();
        assert_eq!(spent, [Leaf(0), Leaf(1), Leaf(2)]);
        assert!(matches!(
            ledger.reserve(&key, 3),
            Err(LedgerError::Exhausted { leaves: 3 })
        ));

        // Another key has its own counter.
        assert_eq!(ledger.reserve(&[8; 52], 3).unwrap(), Leaf(0));
    }

    #[test]
    fn a_reopened_ledger_never_hands_out_a_spent_leaf() {
        let directory = env::temp_dir().join(format!("axiom-ledger-{}", process::id()));
        let key = [1; 52];

        // Spend leaves 0 and 1, then close the ledger as a crash would.
        {
            let ledger = LeafLedger::open(&directory).unwrap();
            ledger.reserve(&key, 100).unwrap();
            ledger.reserve(&key, 100).unwrap();
        }

        // After reopening, the next leaf is 2, never 0 or 1 again.
        let ledger = LeafLedger::open(&directory).unwrap();
        assert_eq!(ledger.reserve(&key, 100).unwrap(), Leaf(2));
        drop(ledger);
        fs::remove_dir_all(&directory).unwrap();
    }
}
