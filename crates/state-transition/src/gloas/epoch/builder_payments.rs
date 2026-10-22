//! Builder payments: paying builders whose payload the attesters saw in time.

use axiom_types::{
    Gwei, Preset,
    accessors::BuilderState,
    constants::{BUILDER_PAYMENT_THRESHOLD_DENOMINATOR, BUILDER_PAYMENT_THRESHOLD_NUMERATOR},
    gloas::BuilderPendingPayment,
};

use crate::{ActiveBalance, StateError};

/// The settlement of the previous epoch's builder payments at the end of an epoch.
///
/// # Overview
///
/// A bid's payment waits in the slot's entry while same-slot attesters add their weight.
/// An entry that gathers the quorum by the end of the next epoch becomes a builder withdrawal.
/// An entry that misses it is dropped, and the builder keeps its balance.
///
/// The payments hold two epochs: the previous one first, then the current one.
/// See EIP-7732 and `process_builder_pending_payments` in the Gloas beacon chain spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuilderPayments {
    /// Attesting weight a payment needs to be paid.
    quorum: Gwei,
}

impl BuilderPayments {
    /// The settlement under the ending epoch's total active balance.
    ///
    /// ```text
    /// quorum = (total / SLOTS_PER_EPOCH) * 6 / 10
    /// ```
    ///
    /// Threshold: six tenths of one slot's share of the stake.
    /// See `get_builder_payment_quorum_threshold` in the Gloas beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the scaled share overflows 64 bits.
    pub fn new<P: Preset>(total_active_balance: ActiveBalance) -> Result<Self, StateError> {
        let per_slot = total_active_balance.0.0 / P::SLOTS_PER_EPOCH;
        let scaled = per_slot
            .checked_mul(BUILDER_PAYMENT_THRESHOLD_NUMERATOR)
            .ok_or(StateError::Overflow {
                quantity: "builder payment quorum",
            })?;
        Ok(Self {
            quorum: Gwei(scaled / BUILDER_PAYMENT_THRESHOLD_DENOMINATOR),
        })
    }

    /// Attesting weight a payment needs to be paid.
    #[must_use]
    pub const fn quorum(self) -> Gwei {
        self.quorum
    }

    /// Pays the previous epoch's payments that reached the quorum, then shifts the window.
    ///
    /// 1. Each previous-epoch payment with enough weight joins the builder withdrawal queue.
    /// 2. The current epoch's payments move into the previous epoch's half.
    /// 3. The current epoch's half starts empty.
    pub fn apply<S: BuilderState>(self, state: &mut S) {
        let slots = S::Preset::SLOTS_PER_EPOCH as usize;
        let settled: Vec<_> = state.builder_pending_payments()[..slots]
            .iter()
            .filter(|payment| payment.weight >= self.quorum)
            .map(|payment| payment.withdrawal.clone())
            .collect();
        for withdrawal in settled {
            state.builder_pending_withdrawals_mut().push(withdrawal);
        }

        let payments = state.builder_pending_payments_mut();
        payments.rotate_left(slots);
        let tail = payments.len() - slots;
        payments[tail..].fill(BuilderPendingPayment::default());
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        BuilderIndex, Minimal,
        gloas::{BeaconState, BuilderPendingWithdrawal},
    };

    use super::*;

    /// A payment of 10 Gwei to a builder, with some attesting weight.
    fn payment(builder: u64, weight: u64) -> BuilderPendingPayment {
        BuilderPendingPayment {
            weight: Gwei(weight),
            withdrawal: BuilderPendingWithdrawal {
                amount: Gwei(10),
                builder_index: BuilderIndex(builder),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn the_quorum_is_six_tenths_of_a_slot_share() {
        // 8 slots per minimal epoch: 800 Gwei of stake gives a 100 Gwei slot share, quorum 60.
        let payments = BuilderPayments::new::<Minimal>(ActiveBalance(Gwei(800))).unwrap();
        assert_eq!(payments.quorum(), Gwei(60));
    }

    #[test]
    fn only_previous_payments_at_quorum_are_paid() {
        // Fixture state: slot 0 of the previous epoch has weight 60, slot 1 has 59.
        // Slot 8, the first of the current epoch, has weight 100 but waits another epoch.
        let mut state = BeaconState::<Minimal>::default();
        state.builder_pending_payments[0] = payment(1, 60);
        state.builder_pending_payments[1] = payment(2, 59);
        state.builder_pending_payments[8] = payment(3, 100);

        BuilderPayments { quorum: Gwei(60) }.apply(&mut state);

        // Only builder 1 is paid.
        assert_eq!(
            state.builder_pending_withdrawals.to_vec(),
            [payment(1, 60).withdrawal]
        );
        // The current epoch's payment moves to the previous half, and the current half empties.
        assert_eq!(state.builder_pending_payments[0], payment(3, 100));
        assert!(
            state.builder_pending_payments[1..]
                .iter()
                .all(|entry| *entry == BuilderPendingPayment::default())
        );
    }
}
