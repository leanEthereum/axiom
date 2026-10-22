//! Churn queues: balance that leaves or merges at a bounded rate per epoch.

use axiom_types::{Epoch, Gwei};

/// The tail of one churn queue: its last scheduled epoch and the balance that epoch can still take.
///
/// Exits and consolidations each keep such a tail in the state.
/// See `compute_exit_epoch_and_update_churn` in the Electra beacon chain spec.
#[derive(Debug)]
pub(crate) struct ChurnQueue<'a> {
    /// The latest epoch anything in the queue is scheduled for.
    earliest_epoch: &'a mut Epoch,
    /// Balance that epoch can still admit.
    balance_to_consume: &'a mut Gwei,
}

impl<'a> ChurnQueue<'a> {
    /// The queue whose tail sits in two state fields.
    pub(crate) const fn new(
        earliest_epoch: &'a mut Epoch,
        balance_to_consume: &'a mut Gwei,
    ) -> Self {
        Self {
            earliest_epoch,
            balance_to_consume,
        }
    }

    /// Schedules a balance and returns the epoch it lands in, consuming that churn.
    ///
    /// # Arguments
    ///
    /// The balance to schedule, the churn each epoch admits, and the earliest epoch allowed.
    ///
    /// # Algorithm
    ///
    /// Entries queue behind each other, each epoch admitting one epoch's churn of balance.
    ///
    /// ```text
    /// churn = 128 ETH per epoch, 40 ETH left in epoch 10, exit of 200 ETH
    ///
    /// 200 - 40 = 160 more ETH, needing ceil(160 / 128) = 2 more epochs
    /// the exit lands in epoch 12, leaving 40 + 256 - 200 = 96 ETH there
    /// ```
    pub(crate) fn schedule(self, balance: Gwei, per_epoch_churn: Gwei, earliest: Epoch) -> Epoch {
        let mut epoch = (*self.earliest_epoch).max(earliest);

        // A later epoch than the queue's tail starts with a full churn budget.
        let mut to_consume = if *self.earliest_epoch < epoch {
            per_epoch_churn
        } else {
            *self.balance_to_consume
        };

        if balance > to_consume {
            let remaining = balance - to_consume;
            let additional_epochs = (remaining.0 - 1) / per_epoch_churn.0 + 1;
            epoch += additional_epochs;
            to_consume += per_epoch_churn * additional_epochs;
        }

        *self.balance_to_consume = to_consume - balance;
        *self.earliest_epoch = epoch;
        epoch
    }
}
