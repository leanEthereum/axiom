//! What an Electra block body carries besides its payload, whole or blinded alike.

use axiom_types::{
    BlsSignature, Preset,
    electra::{
        Attestation, AttesterSlashing, BeaconBlockBody, BeaconState, BlindedBeaconBlockBody,
        Deposit, Eth1Data, ExecutionRequests, ProposerSlashing, SignedBlsToExecutionChange,
        SignedVoluntaryExit, SyncAggregate,
    },
};

use crate::{
    BlockError, BlockProcessor,
    electra::block::{BridgeDeposits, Exit, RequestedDeposit},
    phase0::block::RandaoReveal,
};

/// The steps of an Electra block after its payload, read from a whole or a blinded body.
///
/// A blinded body differs from a whole one only in its payload, so both run these steps alike.
/// Fulu keeps the body and changes how deposits enter, in its own type.
#[derive(Clone, Copy, Debug)]
pub struct BodyOperations<'a, P: Preset> {
    /// The proposer's RANDAO reveal.
    pub(crate) randao_reveal: BlsSignature,
    /// The proposer's eth1 vote.
    pub(crate) eth1_data: &'a Eth1Data,
    /// Proposer slashings.
    pub(crate) proposer_slashings: &'a [ProposerSlashing],
    /// Attester slashings.
    pub(crate) attester_slashings: &'a [AttesterSlashing<P>],
    /// Attestations.
    pub(crate) attestations: &'a [Attestation<P>],
    /// Deposits from the deposit contract.
    pub(crate) deposits: &'a [Deposit],
    /// Voluntary exits.
    pub(crate) voluntary_exits: &'a [SignedVoluntaryExit],
    /// Withdrawal credential changes.
    pub(crate) bls_to_execution_changes: &'a [SignedBlsToExecutionChange],
    /// The requests the execution layer made.
    pub(crate) execution_requests: &'a ExecutionRequests<P>,
    /// The sync committee's signature over the parent.
    pub(crate) sync_aggregate: &'a SyncAggregate<P>,
}

impl<'a, P: Preset> From<&'a BeaconBlockBody<P>> for BodyOperations<'a, P> {
    fn from(body: &'a BeaconBlockBody<P>) -> Self {
        Self {
            randao_reveal: body.randao_reveal,
            eth1_data: &body.eth1_data,
            proposer_slashings: &body.proposer_slashings,
            attester_slashings: &body.attester_slashings,
            attestations: &body.attestations,
            deposits: &body.deposits,
            voluntary_exits: &body.voluntary_exits,
            bls_to_execution_changes: &body.bls_to_execution_changes,
            execution_requests: &body.execution_requests,
            sync_aggregate: &body.sync_aggregate,
        }
    }
}

impl<'a, P: Preset> From<&'a BlindedBeaconBlockBody<P>> for BodyOperations<'a, P> {
    fn from(body: &'a BlindedBeaconBlockBody<P>) -> Self {
        Self {
            randao_reveal: body.randao_reveal,
            eth1_data: &body.eth1_data,
            proposer_slashings: &body.proposer_slashings,
            attester_slashings: &body.attester_slashings,
            attestations: &body.attestations,
            deposits: &body.deposits,
            voluntary_exits: &body.voluntary_exits,
            bls_to_execution_changes: &body.bls_to_execution_changes,
            execution_requests: &body.execution_requests,
            sync_aggregate: &body.sync_aggregate,
        }
    }
}

impl<P: Preset> BodyOperations<'_, P> {
    /// Runs the steps after the payload.
    ///
    /// 1. The RANDAO reveal and the eth1 vote, by phase0's rules.
    /// 2. The operations, with contract deposits bridged until requests take over.
    /// 3. The sync aggregate, by Altair's rule.
    ///
    /// See `process_block` and `process_operations` in the Electra beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails at the first broken rule.
    pub fn apply(
        self,
        processor: &mut BlockProcessor<'_, BeaconState<P>>,
    ) -> Result<(), BlockError> {
        processor.apply(&RandaoReveal(self.randao_reveal))?;
        processor.apply(self.eth1_data)?;

        processor.apply_all(self.proposer_slashings)?;
        processor.apply_all(self.attester_slashings)?;
        processor.apply_all(self.attestations)?;
        // The spec asserts the deposit count first; no earlier operation moves the counts it reads.
        processor.apply(&BridgeDeposits(self.deposits))?;
        for exit in self.voluntary_exits {
            processor.apply(&Exit(exit))?;
        }
        processor.apply_all(self.bls_to_execution_changes)?;
        for request in &self.execution_requests.deposits {
            processor.apply(&RequestedDeposit(request))?;
        }
        processor.apply_all(&self.execution_requests.withdrawals)?;
        processor.apply_all(&self.execution_requests.consolidations)?;

        processor.apply(self.sync_aggregate)
    }
}
