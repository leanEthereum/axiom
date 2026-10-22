//! What an operator may change about how the chain thread runs.

use axiom_types::{Epoch, Slot};

use crate::ChainError;

/// Operator choices the chain thread applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainSettings {
    /// Most slots a vote's slot may lie past the block it votes for; none bounds nothing.
    ///
    /// A vote for an old block makes the node advance a state through every skipped slot.
    /// The bound stops a minority fork's votes from costing that work.
    pub max_skip_slots: Option<u64>,
    /// Whether the fast confirmation rule names the engine's safe block, instead of justification.
    pub fast_confirmation: bool,
    /// Whether light client data is derived, stored, and served.
    pub light_client_server: bool,
    /// When expired sidecars leave the disk.
    pub sidecar_pruning: SidecarPruning,
}

impl Default for ChainSettings {
    fn default() -> Self {
        // Every vote counts, justification names the safe block, and light clients are served.
        Self {
            max_skip_slots: None,
            fast_confirmation: false,
            light_client_server: true,
            sidecar_pruning: SidecarPruning::default(),
        }
    }
}

impl ChainSettings {
    /// Refuses a vote whose slot lies too far past the block it votes for.
    ///
    /// A vote for an unknown block passes: the fork choice refuses it on its own.
    pub(crate) const fn check_skips(
        &self,
        vote_slot: Slot,
        block_slot: Option<Slot>,
    ) -> Result<(), ChainError> {
        let (Some(max), Some(block_slot)) = (self.max_skip_slots, block_slot) else {
            return Ok(());
        };
        // Threshold: a vote may sit at most max slots past its block.
        if vote_slot.0 > block_slot.0.saturating_add(max) {
            return Err(ChainError::TooManySkippedSlots {
                vote_slot,
                block_slot,
                max,
            });
        }
        Ok(())
    }
}

/// When blob and column sidecars past their retention window leave the disk.
///
/// # Overview
///
/// Peers must serve sidecars for a bounded window of recent epochs, then may forget them.
/// See `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` in the Deneb p2p spec.
///
/// Pruning runs at finality.
/// Once due, passes repeat at each finality until one finds nothing left to delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SidecarPruning {
    /// Whether expired sidecars are deleted at all.
    pub enabled: bool,
    /// Epochs from the end of one pruning round to the start of the next.
    pub interval_epochs: u64,
    /// Epochs kept past the retention window.
    pub margin_epochs: u64,
}

impl Default for SidecarPruning {
    fn default() -> Self {
        // Prune at every finality, keeping exactly the window peers may ask for.
        Self {
            enabled: true,
            interval_epochs: 1,
            margin_epochs: 0,
        }
    }
}

impl SidecarPruning {
    /// Whether a pruning pass is due, given when the last round ended.
    pub(crate) fn is_due(&self, current: Epoch, last_round: Option<Epoch>) -> bool {
        self.enabled
            && last_round
                .is_none_or(|last| current.0 >= last.0.saturating_add(self.interval_epochs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn votes_may_skip_at_most_the_bound() {
        // Fixture state: a block at slot 100 and a bound of 32 slots.
        let settings = ChainSettings {
            max_skip_slots: Some(32),
            ..ChainSettings::default()
        };

        // Slot 132 is 32 past the block, the most allowed; slot 133 is one more.
        assert!(settings.check_skips(Slot(132), Some(Slot(100))).is_ok());
        assert!(matches!(
            settings.check_skips(Slot(133), Some(Slot(100))),
            Err(ChainError::TooManySkippedSlots {
                vote_slot: Slot(133),
                block_slot: Slot(100),
                max: 32,
            })
        ));

        // An unknown block, or no bound at all, lets the vote through.
        assert!(settings.check_skips(Slot(1000), None).is_ok());
        assert!(
            ChainSettings::default()
                .check_skips(Slot(1000), Some(Slot(0)))
                .is_ok()
        );
    }

    #[test]
    fn pruning_rounds_wait_their_interval() {
        // Fixture state: a round every 256 epochs, the last one ending at epoch 1000.
        let pruning = SidecarPruning {
            interval_epochs: 256,
            ..SidecarPruning::default()
        };

        // The first round is due at once; later ones 256 epochs after the last.
        assert!(pruning.is_due(Epoch(5), None));
        assert!(!pruning.is_due(Epoch(1255), Some(Epoch(1000))));
        assert!(pruning.is_due(Epoch(1256), Some(Epoch(1000))));

        // Disabled pruning is never due.
        let disabled = SidecarPruning {
            enabled: false,
            ..pruning
        };
        assert!(!disabled.is_due(Epoch(5), None));
    }
}
