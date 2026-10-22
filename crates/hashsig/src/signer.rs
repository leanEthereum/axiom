//! A stateful signer: a secret key bound to a durable ledger of the epochs it has spent.
//!
//! # Overview
//!
//! A synchronized key must never sign two messages in one epoch.
//! Two signatures at one epoch reveal chain values at two codewords, enough to forge a third.
//! A crash, a restored backup, or a second process with the same key all risk exactly that.
//!
//! The signer therefore keeps the next unspent epoch, and spends forward only.
//!
//! 1. Refuse an epoch below the next unspent one.
//! 2. Refuse an epoch outside the prepared window, before spending anything.
//! 3. Record the new next epoch durably through the ledger.
//! 4. Only then sign.
//!
//! A crash between steps 3 and 4 wastes one epoch and never reuses one.
//!
//! The window slides ahead of signing.
//! Once signing has entered the window's second tree, the next tree is due.
//! Its preparation is detached work that any thread can run, and the signer installs the result.

use thiserror::Error;

use crate::{
    encoding::MESSAGE_LEN,
    error::{PrepareError, SignError},
    keys::{LeafEpoch, PublicKey, SecretKey, Signature},
    one_time::{BottomTree, Preparation},
};

/// Durable storage of the next epoch a key may sign in.
///
/// A node backs it with its database, a test with memory.
pub trait EpochLedger {
    /// Why the ledger could not record.
    type Error: std::error::Error + 'static;

    /// Records that every epoch below the given one is spent.
    ///
    /// It must reach stable storage before returning, since a signature may follow at once.
    fn spend_below(&mut self, next: u64) -> Result<(), Self::Error>;
}

/// A secret key that signs each epoch at most once, across crashes.
#[derive(Debug)]
pub struct StatefulSigner<L> {
    /// The secret key.
    key: SecretKey,
    /// Where spent epochs are recorded.
    ledger: L,
    /// The first epoch not yet spent, as last recorded.
    next: u64,
}

impl<L: EpochLedger> StatefulSigner<L> {
    /// A signer over a key, its ledger, and the next unspent epoch the ledger holds.
    pub const fn new(key: SecretKey, ledger: L, next: u64) -> Self {
        Self { key, ledger, next }
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    /// The first epoch not yet spent.
    #[must_use]
    pub const fn next_epoch(&self) -> u64 {
        self.next
    }

    /// The secret key, for storage.
    #[must_use]
    pub const fn key(&self) -> &SecretKey {
        &self.key
    }

    /// Spends an epoch durably, then signs a message in it.
    ///
    /// # Errors
    ///
    /// Fails for a spent epoch or one outside the prepared window, before spending anything.
    /// Fails when the ledger cannot record, before signing.
    pub fn sign(
        &mut self,
        epoch: LeafEpoch,
        message: &[u8; MESSAGE_LEN],
    ) -> Result<Signature, SignerError<L::Error>> {
        let at = u64::from(epoch.0);
        if at < self.next {
            return Err(SignerError::Spent {
                epoch: at,
                next: self.next,
            });
        }
        let prepared = self.key.prepared();
        if !prepared.contains(&at) {
            return Err(SignerError::Key(SignError::NotPrepared {
                epoch: at,
                start: prepared.start,
                end: prepared.end,
            }));
        }
        // The spent mark is durable before the signature exists.
        self.ledger
            .spend_below(at + 1)
            .map_err(SignerError::Ledger)?;
        self.next = at + 1;
        Ok(self.key.sign(epoch, message)?)
    }

    /// The next bottom tree's preparation, once signing has entered the window's second tree.
    ///
    /// The work is detached: run it on any thread, then hand the tree back to install.
    #[must_use]
    pub fn due_preparation(&self) -> Option<Preparation> {
        let half = self.key.prepared().start + self.key.scheme().leaves_per_bottom_tree();
        if self.next > half {
            self.key.preparation()
        } else {
            None
        }
    }

    /// Slides the window onto a prepared tree.
    ///
    /// # Errors
    ///
    /// Fails when the tree is not the next one, or the window already ends the activation.
    pub fn install(&mut self, tree: BottomTree) -> Result<(), PrepareError> {
        self.key.install(tree)
    }
}

/// Why a stateful signer refused to sign.
#[derive(Debug, Error)]
pub enum SignerError<E> {
    /// The epoch is already spent: signing it again could reveal the key.
    #[error("epoch {epoch} is spent, the next unspent epoch is {next}")]
    Spent {
        /// The requested epoch.
        epoch: u64,
        /// The first unspent epoch.
        next: u64,
    },
    /// The ledger could not record the spent epoch, so nothing was signed.
    #[error("epoch ledger: {0}")]
    Ledger(#[source] E),
    /// The key refused after the epoch was spent.
    #[error("secret key: {0}")]
    Key(#[from] SignError),
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, thread};

    use super::*;
    use crate::{
        entropy::SeedStream,
        instantiation::{HypercubeLifetime, Instantiation},
    };

    /// A ledger in memory that records every write.
    #[derive(Debug, Default)]
    struct Recorded(Vec<u64>);

    impl EpochLedger for Recorded {
        type Error = Infallible;

        fn spend_below(&mut self, next: u64) -> Result<(), Infallible> {
            self.0.push(next);
            Ok(())
        }
    }

    /// A ledger whose disk is full.
    #[derive(Debug)]
    struct Full;

    /// The error of a full disk.
    #[derive(Debug, Error)]
    #[error("disk full")]
    struct DiskFull;

    impl EpochLedger for Full {
        type Error = DiskFull;

        fn spend_below(&mut self, _: u64) -> Result<(), DiskFull> {
            Err(DiskFull)
        }
    }

    /// A key of the test lifetime over epochs 0 to 47: bottom trees 0, 1 and 2 of 16 epochs.
    fn key() -> SecretKey {
        Instantiation::Hypercube(HypercubeLifetime::TestOnly8)
            .scheme()
            .generate(&mut SeedStream::new(b"signer"), 0..48)
            .unwrap()
            .1
    }

    #[test]
    fn epochs_are_spent_before_signing_and_never_reused() {
        let mut signer = StatefulSigner::new(key(), Recorded::default(), 0);
        let scheme = *signer.key().scheme();
        let public = signer.public_key();

        // Epochs 3 then 9: each is recorded spent before its signature, gaps are fine.
        let first = signer.sign(LeafEpoch(3), &[1; 32]).unwrap();
        let second = signer.sign(LeafEpoch(9), &[2; 32]).unwrap();
        assert_eq!(signer.ledger.0, [4, 10]);
        assert_eq!(
            scheme.verify(&public, LeafEpoch(3), &[1; 32], &first),
            Ok(())
        );
        assert_eq!(
            scheme.verify(&public, LeafEpoch(9), &[2; 32], &second),
            Ok(())
        );

        // Epoch 9 again, or 5 behind it, is refused without touching the ledger.
        for epoch in [9, 5] {
            assert!(matches!(
                signer.sign(LeafEpoch(epoch), &[3; 32]),
                Err(SignerError::Spent { epoch: e, next: 10 }) if e == u64::from(epoch)
            ));
        }
        assert_eq!(signer.ledger.0, [4, 10]);
    }

    #[test]
    fn an_epoch_past_the_window_spends_nothing() {
        // Fixture state: window [0, 32), epoch 40 lies in tree 2, not yet prepared.
        let mut signer = StatefulSigner::new(key(), Recorded::default(), 0);
        assert!(matches!(
            signer.sign(LeafEpoch(40), &[0; 32]),
            Err(SignerError::Key(SignError::NotPrepared {
                epoch: 40,
                start: 0,
                end: 32
            }))
        ));
        assert_eq!((signer.ledger.0.len(), signer.next_epoch()), (0, 0));
    }

    #[test]
    fn a_failed_ledger_write_signs_nothing() {
        let mut signer = StatefulSigner::new(key(), Full, 0);
        assert!(matches!(
            signer.sign(LeafEpoch(0), &[0; 32]),
            Err(SignerError::Ledger(DiskFull))
        ));
        assert_eq!(signer.next_epoch(), 0);
    }

    #[test]
    fn preparation_runs_on_another_thread_once_the_second_tree_is_entered() {
        let mut signer = StatefulSigner::new(key(), Recorded::default(), 0);

        // Epoch 15 is the last of tree 0: nothing is due yet.
        signer.sign(LeafEpoch(15), &[0; 32]).unwrap();
        assert!(signer.due_preparation().is_none());

        // Epoch 16 enters tree 1, so tree 2 is due; it builds on a worker thread.
        signer.sign(LeafEpoch(16), &[0; 32]).unwrap();
        let preparation = signer.due_preparation().unwrap();
        let tree = thread::spawn(move || preparation.build()).join().unwrap();
        signer.install(tree).unwrap();

        // The window is now [16, 48), and epoch 40 signs.
        assert_eq!(signer.key().prepared(), 16..48);
        let signature = signer.sign(LeafEpoch(40), &[4; 32]).unwrap();
        let scheme = *signer.key().scheme();
        assert_eq!(
            scheme.verify(&signer.public_key(), LeafEpoch(40), &[4; 32], &signature),
            Ok(())
        );
    }
}
