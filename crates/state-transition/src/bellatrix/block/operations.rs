//! What a Bellatrix block body carries besides its payload, whole or blinded alike.

use axiom_types::{
    BlsSignature, Preset,
    bellatrix::{
        Attestation, AttesterSlashing, BeaconBlockBody, BeaconState, BlindedBeaconBlockBody,
        Deposit, Eth1Data, ProposerSlashing, SignedVoluntaryExit, SyncAggregate,
    },
};

use crate::{
    BlockError, BlockProcessor,
    altair::block::{FlaggedAttestation, ParticipantDeposit},
    phase0::block::{DepositQuota, RandaoReveal},
};

/// The steps of a Bellatrix block after its payload, read from a whole or a blinded body.
///
/// A blinded body differs from a whole one only in its payload, so both run these steps alike.
#[derive(Clone, Copy, Debug)]
pub struct BodyOperations<'a, P: Preset> {
    /// The proposer's RANDAO reveal.
    randao_reveal: BlsSignature,
    /// The proposer's eth1 vote.
    eth1_data: &'a Eth1Data,
    /// Proposer slashings.
    proposer_slashings: &'a [ProposerSlashing],
    /// Attester slashings.
    attester_slashings: &'a [AttesterSlashing<P>],
    /// Attestations.
    attestations: &'a [Attestation<P>],
    /// Deposits from the deposit contract.
    deposits: &'a [Deposit],
    /// Voluntary exits.
    voluntary_exits: &'a [SignedVoluntaryExit],
    /// The sync committee's signature over the parent.
    sync_aggregate: &'a SyncAggregate<P>,
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
            sync_aggregate: &body.sync_aggregate,
        }
    }
}

impl<P: Preset> BodyOperations<'_, P> {
    /// Runs the steps after the payload.
    ///
    /// 1. The RANDAO reveal and the eth1 vote, by phase0's rules.
    /// 2. The operations, by Altair's rules under Bellatrix's penalty constants.
    /// 3. The sync aggregate, by Altair's rule.
    ///
    /// See `process_block` in the Bellatrix beacon chain spec.
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

        DepositQuota::of(processor.state.beacon()).check(self.deposits.len())?;
        processor.apply_all(self.proposer_slashings)?;
        processor.apply_all(self.attester_slashings)?;
        for attestation in self.attestations {
            processor.apply(&FlaggedAttestation(attestation))?;
        }
        for deposit in self.deposits {
            processor.apply(&ParticipantDeposit(deposit))?;
        }
        processor.apply_all(self.voluntary_exits)?;

        processor.apply(self.sync_aggregate)
    }
}
