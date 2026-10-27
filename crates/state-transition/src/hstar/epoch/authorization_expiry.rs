//! The expiry of owner key authorizations that no registration used.

use axiom_types::{Epoch, accessors::PqRegistryState};

/// The pass that drops the key authorizations which cannot be used in the next epoch.
///
/// An authorization is usable up to and including its expiry epoch.
/// Expiry keeps the queue at one short-lived entry per validator at most.
/// See `process_pending_pq_key_authorizations` in EIP-8450.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationExpiry {
    /// The epoch after the one that ends, the first an authorization must still cover.
    next_epoch: Epoch,
}

impl AuthorizationExpiry {
    /// The pass at the end of an epoch.
    #[must_use]
    pub const fn new(current_epoch: Epoch) -> Self {
        Self {
            next_epoch: Epoch(current_epoch.0 + 1),
        }
    }

    /// Keeps the authorizations that expire in the next epoch or later, in queue order.
    pub fn apply<S: PqRegistryState + ?Sized>(self, state: &mut S) {
        state
            .pending_pq_key_authorizations_mut()
            .retain(|authorization| authorization.expiry_epoch >= self.next_epoch);
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, ValidatorIndex, hstar};

    use super::*;

    #[test]
    fn an_authorization_lives_through_its_expiry_epoch() {
        // Fixture state: three authorizations expiring at epochs 9, 10, and 11.
        let mut state = hstar::BeaconState::<Minimal>::default();
        for (index, expiry) in [(0, 9), (1, 10), (2, 11)] {
            state
                .pending_pq_key_authorizations
                .push(hstar::PendingPqKeyAuthorization {
                    validator_index: ValidatorIndex(index),
                    expiry_epoch: Epoch(expiry),
                    ..Default::default()
                });
        }

        // Timing: epoch 9 ends, so the next epoch is 10.
        //
        //     expiry 9    usable through epoch 9 only     dropped
        //     expiry 10   usable in epoch 10              kept
        //     expiry 11   usable in epochs 10 and 11      kept
        AuthorizationExpiry::new(Epoch(9)).apply(&mut state);

        // The survivors keep their queue order.
        let kept: Vec<ValidatorIndex> = state
            .pending_pq_key_authorizations()
            .iter()
            .map(|authorization| authorization.validator_index)
            .collect();
        assert_eq!(kept, [ValidatorIndex(1), ValidatorIndex(2)]);
    }
}
