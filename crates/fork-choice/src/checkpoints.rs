//! The Casper FFG checkpoints the store tracks, realized and pulled up.

use axiom_types::phase0::Checkpoint;

/// The store's justified and finalized checkpoints, and the unrealized ones ahead of them.
///
/// # Overview
///
/// A checkpoint is realized once an epoch transition processes the votes behind it.
/// The unrealized pair already counts votes that blocks carry but no transition processed.
/// It becomes the realized pair at the next epoch boundary.
///
/// Every update only moves a checkpoint to a later epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Checkpoints {
    /// Justified checkpoint LMD-GHOST starts from.
    justified: Checkpoint,
    /// Latest finalized checkpoint, which no head may conflict with.
    finalized: Checkpoint,
    /// Best justified checkpoint seen, counting votes not yet processed on chain.
    unrealized_justified: Checkpoint,
    /// Best finalized checkpoint seen, counting votes not yet processed on chain.
    unrealized_finalized: Checkpoint,
}

impl Checkpoints {
    /// Every checkpoint at the anchor.
    #[must_use]
    pub(crate) const fn at(anchor: Checkpoint) -> Self {
        Self {
            justified: anchor,
            finalized: anchor,
            unrealized_justified: anchor,
            unrealized_finalized: anchor,
        }
    }

    /// Justified checkpoint LMD-GHOST starts from.
    #[must_use]
    pub(crate) const fn justified(&self) -> Checkpoint {
        self.justified
    }

    /// Latest finalized checkpoint.
    #[must_use]
    pub(crate) const fn finalized(&self) -> Checkpoint {
        self.finalized
    }

    /// Best justified checkpoint seen, counting votes not yet processed on chain.
    #[must_use]
    pub(crate) const fn unrealized_justified(&self) -> Checkpoint {
        self.unrealized_justified
    }

    /// Adopts checkpoints that are newer than the realized ones.
    ///
    /// See `update_checkpoints` in the phase0 fork choice spec.
    pub(crate) const fn update(&mut self, justified: Checkpoint, finalized: Checkpoint) {
        if justified.epoch.0 > self.justified.epoch.0 {
            self.justified = justified;
        }
        if finalized.epoch.0 > self.finalized.epoch.0 {
            self.finalized = finalized;
        }
    }

    /// Adopts unrealized checkpoints that are newer than the store's.
    ///
    /// See `update_unrealized_checkpoints` in the phase0 fork choice spec.
    pub(crate) const fn update_unrealized(&mut self, justified: Checkpoint, finalized: Checkpoint) {
        if justified.epoch.0 > self.unrealized_justified.epoch.0 {
            self.unrealized_justified = justified;
        }
        if finalized.epoch.0 > self.unrealized_finalized.epoch.0 {
            self.unrealized_finalized = finalized;
        }
    }

    /// Realizes the unrealized checkpoints, as an epoch boundary does.
    pub(crate) const fn realize(&mut self) {
        self.update(self.unrealized_justified, self.unrealized_finalized);
    }
}
