//! Forgetting what finality made irrelevant.

use axiom_types::{Preset, Root};

use crate::Store;

impl<P: Preset> Store<P> {
    /// Drops every block that does not descend from the finalized block, with its state.
    ///
    /// No head can leave the finalized block's subtree, so nothing dropped can matter again.
    /// The spec's store grows forever; a node prunes to keep memory bounded.
    ///
    /// # Returns
    ///
    /// The roots dropped, so the caller can also forget them elsewhere.
    pub fn prune(&mut self) -> Vec<Root> {
        let finalized = self.finalized_checkpoint;

        // The finalized block becomes the new anchor of the tree.
        let dropped = self.blocks.retain_subtree(finalized.root);
        for root in &dropped {
            self.block_states.remove(root);
            self.block_timeliness.remove(root);
            self.unrealized_justifications.remove(root);
        }

        // Justified checkpoints never precede the finalized one, so older states are unreachable.
        self.checkpoint_states
            .retain(|checkpoint, _| checkpoint.epoch >= finalized.epoch);
        dropped
    }
}
