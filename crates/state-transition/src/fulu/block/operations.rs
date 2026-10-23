//! What a Fulu block body carries besides its payload, whole or blinded alike.

use axiom_types::{
    Preset,
    fulu::{BeaconBlockBody, BeaconState, BlindedBeaconBlockBody},
};

use crate::{
    BlockError, BlockProcessor, electra, electra::block::Exit, fulu::block::QueuedDeposit,
    phase0::block::RandaoReveal,
};

/// The steps of a Fulu block after its payload, read from a whole or a blinded body.
///
/// Fulu keeps Electra's body, and retires deposits from the deposit contract.
#[derive(Clone, Copy, Debug)]
pub struct BodyOperations<'a, P: Preset>(electra::block::BodyOperations<'a, P>);

impl<'a, P: Preset> From<&'a BeaconBlockBody<P>> for BodyOperations<'a, P> {
    fn from(body: &'a BeaconBlockBody<P>) -> Self {
        Self(body.into())
    }
}

impl<'a, P: Preset> From<&'a BlindedBeaconBlockBody<P>> for BodyOperations<'a, P> {
    fn from(body: &'a BlindedBeaconBlockBody<P>) -> Self {
        Self(body.into())
    }
}

impl<P: Preset> BodyOperations<'_, P> {
    /// Runs the steps after the payload.
    ///
    /// 1. The RANDAO reveal and the eth1 vote, by phase0's rules.
    /// 2. The operations, with no deposits from the old mechanism.
    /// 3. The sync aggregate, by Altair's rule.
    ///
    /// See `process_block` and `process_operations` in the Fulu beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails at the first broken rule.
    pub fn apply(
        self,
        processor: &mut BlockProcessor<'_, BeaconState<P>>,
    ) -> Result<(), BlockError> {
        let operations = self.0;
        processor.apply(&RandaoReveal(operations.randao_reveal))?;
        processor.apply(operations.eth1_data)?;

        // Fulu retired deposits from the deposit contract; they arrive as requests instead.
        if !operations.deposits.is_empty() {
            return Err(BlockError::DepositsNotAllowed(operations.deposits.len()));
        }
        processor.apply_all(operations.proposer_slashings)?;
        processor.apply_all(operations.attester_slashings)?;
        processor.apply_all(operations.attestations)?;
        for exit in operations.voluntary_exits {
            processor.apply(&Exit(exit))?;
        }
        processor.apply_all(operations.bls_to_execution_changes)?;
        for request in &operations.execution_requests.deposits {
            processor.apply(&QueuedDeposit(request))?;
        }
        processor.apply_all(&operations.execution_requests.withdrawals)?;
        processor.apply_all(&operations.execution_requests.consolidations)?;

        processor.apply(operations.sync_aggregate)
    }
}
