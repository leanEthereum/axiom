//! The post-quantum key registry, from Hstar on.

use axiom_ssz::{Sequence, SequenceMut};

use crate::{
    Gwei, ValidatorIndex, XmssPublicKey,
    accessors::CoreState,
    hstar::{PendingPqKeyAuthorization, PendingPqKeyAuthorizations, PqPublicKeys},
};

/// Each validator's registered post-quantum key, and the owner authorizations waiting for one.
///
/// See EIP-8450.
pub trait PqRegistryState: CoreState {
    /// Registered keys, one entry per validator, by validator index.
    fn pq_public_keys(&self) -> &Sequence<PqPublicKeys>;

    /// Registered keys, for registrations.
    ///
    /// The view has a fixed length: entries grow only with the validators.
    fn pq_public_keys_mut(&mut self) -> SequenceMut<'_, PqPublicKeys>;

    /// Key authorizations waiting for a matching registration, oldest first.
    fn pending_pq_key_authorizations(&self) -> &Sequence<PendingPqKeyAuthorization>;

    /// Key authorizations, for requests, registrations, and expiry.
    fn pending_pq_key_authorizations_mut(&mut self) -> &mut PendingPqKeyAuthorizations;

    /// Whether a validator has a registered key.
    ///
    /// An index outside the registry has none.
    /// See `is_pq_registered` in EIP-8450.
    fn is_pq_registered(&self, index: ValidatorIndex) -> bool {
        self.pq_public_keys()
            .get(index.as_usize())
            .is_some_and(PqPublicKeys::is_registered)
    }

    /// Another validator that already registered a key, if any.
    ///
    /// The excluded validator is skipped, so it can register its own current key again.
    /// Entries without a key are skipped too, so the all-zero key never collides.
    /// See `is_pq_public_key_in_use` in EIP-8450.
    ///
    /// # Performance
    ///
    /// One pass over the registry, linear in the number of validators.
    fn pq_public_key_holder(
        &self,
        key: &XmssPublicKey,
        excluded: ValidatorIndex,
    ) -> Option<ValidatorIndex> {
        self.pq_public_keys()
            .iter()
            .enumerate()
            .find(|(index, entry)| {
                *index != excluded.as_usize()
                    && entry.is_registered()
                    && entry.xmss_public_key == *key
            })
            .map(|(index, _)| ValidatorIndex::from(index))
    }

    /// Position of a validator's pending authorization in the queue, if it has one.
    ///
    /// A validator has at most one pending authorization, so the first match is the only one.
    /// See `get_pq_key_authorization_position` in EIP-8450.
    fn pq_key_authorization_position(&self, index: ValidatorIndex) -> Option<usize> {
        self.pending_pq_key_authorizations()
            .iter()
            .position(|authorization| authorization.validator_index == index)
    }

    /// Total effective balance of the active validators with a registered key.
    ///
    /// This is the readiness signal the signature switch is scheduled against.
    /// No state transition reads it.
    /// See `get_pq_registered_balance` in EIP-8450.
    fn pq_registered_balance(&self) -> Gwei {
        let epoch = self.current_epoch();
        self.validators()
            .iter()
            .zip(self.pq_public_keys().iter())
            .filter(|(validator, keys)| validator.is_active_at(epoch) && keys.is_registered())
            .map(|(validator, _)| validator.effective_balance)
            .sum()
    }
}
