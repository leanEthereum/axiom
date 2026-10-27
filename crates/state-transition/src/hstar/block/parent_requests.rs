//! The parent payload's requests in Hstar, which add key authorizations to Gloas's.

use axiom_types::{
    Preset,
    accessors::{BuilderState, PqRegistryState},
    hstar::ExecutionRequests,
};

use crate::{
    BlockError, BlockProcessor, Fork, Operation,
    electra::churn::BalanceChurn,
    fulu::block::QueuedDeposit,
    gloas::block::{ArrivedParentBid, ParentRequests},
};

impl<S> Operation<S> for ParentRequests<'_, ExecutionRequests>
where
    S: BalanceChurn + BuilderState + Fork + PqRegistryState,
{
    /// Pays the parent's builder, applies the requests, and marks the payload as available.
    ///
    /// # Algorithm
    ///
    /// 0. Check each request list against its limit.
    /// 1. Settle the parent bid's payment, before any request, as in Gloas.
    /// 2. Apply Gloas's requests, then the key authorization requests after them.
    /// 3. Mark the parent slot's payload as available, and adopt its block hash.
    ///
    /// See `apply_parent_execution_payload` in the Gloas beacon chain spec and EIP-8450.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError> {
        let requests = self.0;

        // Phase 0: each list within its per-payload limit; deposits carry none, as in the spec.
        let lists = [
            (
                "withdrawal requests",
                requests.withdrawals.len(),
                S::Preset::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
            ),
            (
                "consolidation requests",
                requests.consolidations.len(),
                S::Preset::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
            ),
            (
                "builder deposit requests",
                requests.builder_deposits.len(),
                S::Preset::MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD,
            ),
            (
                "builder exit requests",
                requests.builder_exits.len(),
                S::Preset::MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD,
            ),
            (
                "key authorization requests",
                requests.pq_key_authorizations.len(),
                S::Preset::MAX_PQ_KEY_AUTHORIZATION_REQUESTS_PER_PAYLOAD,
            ),
        ];
        for (operation, count, limit) in lists {
            if count as u64 > limit {
                return Err(BlockError::TooManyOperations {
                    operation,
                    count,
                    limit,
                });
            }
        }

        // Phase 1: the builder payment.
        let parent = ArrivedParentBid::of(&*processor.state.beacon);
        parent.pay(&mut *processor.state.beacon);

        // Phase 2: the requests, in the order the payload lists their types.
        for request in &requests.deposits {
            processor.apply(&QueuedDeposit(request))?;
        }
        processor.apply_all(&requests.withdrawals)?;
        processor.apply_all(&requests.consolidations)?;
        processor.apply_all(&requests.builder_deposits)?;
        processor.apply_all(&requests.builder_exits)?;
        processor.apply_all(&requests.pq_key_authorizations)?;

        // Phase 3: the payload is available, and the execution chain moves to it.
        parent.deliver(&mut *processor.state.beacon);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Ssz;
    use axiom_types::{Hash32, Minimal, accessors::CoreState, hstar::PqKeyAuthorizationRequest};

    use super::*;
    use crate::hstar::block::fixture::{self, apply, state};

    #[test]
    fn a_full_parent_applies_its_key_authorizations() {
        // Fixture state: the parent's bid committed to block 0x0b and to one authorization.
        let mut state = state();
        let mut requests = ExecutionRequests::default();
        requests
            .pq_key_authorizations
            .push(PqKeyAuthorizationRequest {
                source_address: fixture::withdrawal_address(3),
                validator_pubkey: state.validators()[3].pubkey,
                public_keys_root: fixture::keys(1).hash_tree_root(),
            });

        // Applying the parent's requests records the authorization and adopts the parent's hash.
        state.latest_execution_payload_bid.block_hash = Hash32([0x0b; 32]);
        apply(&mut state, &ParentRequests(&requests)).unwrap();

        assert_eq!(state.pending_pq_key_authorizations.len(), 1);
        assert_eq!(state.latest_block_hash, Hash32([0x0b; 32]));
    }

    #[test]
    fn a_seventeenth_authorization_exceeds_the_payload_limit() {
        // The limit is 16 authorizations per payload; the parent reports 17.
        let mut state = state();
        let mut requests = ExecutionRequests::default();
        for _ in 0..17 {
            requests
                .pq_key_authorizations
                .push(PqKeyAuthorizationRequest::default());
        }

        assert_eq!(
            apply::<ParentRequests<'_, ExecutionRequests>>(&mut state, &ParentRequests(&requests)),
            Err(BlockError::TooManyOperations {
                operation: "key authorization requests",
                count: 17,
                limit: <Minimal as Preset>::MAX_PQ_KEY_AUTHORIZATION_REQUESTS_PER_PAYLOAD,
            })
        );
    }
}
