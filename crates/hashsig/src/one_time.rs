//! The one-time keys of every epoch, derived on demand from the PRF key, and the bottom trees over them.
//!
//! # Overview
//!
//! The one-time secret key of an epoch is v chain starts, each a PRF output.
//! Its public key is the v chain ends, w - 1 steps further, hashed into one Merkle leaf.
//!
//! ```text
//! start_i = PRF(key, epoch, i)
//! end_i   = Th^(w - 1)(start_i)
//! leaf    = Th_leaf(end_1, ..., end_v)
//! ```
//!
//! Nothing per epoch is stored: a bottom tree is rebuilt from the PRF key when the key needs it.

use crate::{
    leaf_kernel::{LANES, LeafKernel},
    merkle::Subtree,
    parallel::Threads,
    prf::PrfKey,
    scheme::Scheme,
    tweak_hash::{DigestLanes, TweakHash},
    words::Digest,
};

/// The derivation of every one-time key of a key pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OneTimeKeys {
    /// The instantiation.
    scheme: Scheme,
    /// The secret PRF key.
    prf: PrfKey,
    /// The key pair's tweakable hash.
    hash: TweakHash,
}

impl OneTimeKeys {
    /// The derivation from a PRF key and a tweakable hash.
    pub(crate) const fn new(scheme: Scheme, prf: PrfKey, hash: TweakHash) -> Self {
        Self { scheme, prf, hash }
    }

    /// The instantiation.
    pub(crate) const fn scheme(&self) -> &Scheme {
        &self.scheme
    }

    /// The secret PRF key.
    pub(crate) const fn prf(&self) -> &PrfKey {
        &self.prf
    }

    /// The tweakable hash.
    pub(crate) const fn hash(&self) -> &TweakHash {
        &self.hash
    }

    /// The secret start of one chain of an epoch.
    pub(crate) fn chain_start(&self, epoch: u32, chain: usize) -> Digest {
        self.prf
            .chain_start(epoch, chain as u64, self.scheme.hash_len)
    }

    /// The Merkle leaf of an epoch: its one-time public key, hashed.
    #[cfg(test)]
    pub(crate) fn leaf(&self, epoch: u32) -> Digest {
        let [leaf] = self.leaves_lanes(&[epoch]);
        leaf
    }

    /// The Merkle leaves of N epochs, which walk each chain index in lockstep, one per lane.
    #[inline(always)]
    pub(crate) fn leaves_lanes<const N: usize>(&self, epochs: &[u32; N]) -> [Digest; N] {
        let last = self.scheme.base - 1;
        let ends: Vec<DigestLanes<N>> = (0..self.scheme.dimension)
            .map(|chain| {
                let starts = epochs.map(|epoch| self.chain_start(epoch, chain));
                let mut lanes = DigestLanes::from_digests(&starts);
                // Invariant: at most 256 chains, so the index fits a byte.
                self.hash
                    .walk_lanes(epochs, chain as u8, 0, last, &mut lanes);
                lanes
            })
            .collect();
        self.hash.leaf_lanes(epochs, &ends)
    }

    /// Bottom tree number index, its leaves computed in SIMD batches on all cores.
    pub(crate) fn bottom_tree(&self, index: u64) -> BottomTree {
        let leaves_per_tree = self.scheme.leaves_per_bottom_tree();
        let first = index * leaves_per_tree;
        // Invariant: lifetimes of at least 2^8 give bottom trees of at least 16 epochs, a power of two.
        debug_assert!(leaves_per_tree.is_multiple_of(LANES as u64));
        let kernel = LeafKernel::detect();
        let batches = Threads::available().map(leaves_per_tree as usize / LANES, |batch| {
            // Invariant: epochs stay below the lifetime, at most 2^32.
            let epochs = std::array::from_fn(|lane| (first + (batch * LANES + lane) as u64) as u32);
            kernel.leaves(self, &epochs)
        });
        let leaves = batches.into_iter().flatten().collect();
        BottomTree(Subtree::bottom(
            &self.hash,
            self.scheme.log_lifetime,
            index,
            leaves,
        ))
    }
}

/// One bottom tree of a key: the leaves of 2^(h/2) consecutive epochs and the levels above them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BottomTree(pub(crate) Subtree);

impl BottomTree {
    /// The tree's index: its epochs start at index * 2^(h/2).
    #[must_use]
    pub fn index(&self) -> u64 {
        self.0.index()
    }
}

/// The work of building the next bottom tree, detached from the key so it can run on any thread.
///
/// It holds a copy of the PRF key, wiped when it drops.
#[derive(Clone, Debug)]
pub struct Preparation {
    /// The derivation of the key's one-time keys.
    keys: OneTimeKeys,
    /// The bottom tree to build.
    index: u64,
}

impl Preparation {
    /// The work of building one bottom tree.
    pub(crate) const fn new(keys: OneTimeKeys, index: u64) -> Self {
        Self { keys, index }
    }

    /// The bottom tree the work builds.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Builds the tree: one leaf per epoch, each v chains of w - 1 hashes.
    #[must_use]
    pub fn build(self) -> BottomTree {
        self.keys.bottom_tree(self.index)
    }
}
