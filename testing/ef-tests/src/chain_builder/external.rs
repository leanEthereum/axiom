//! Blocks built around a reveal and votes the caller supplies, as a node builds for a validator client.

use axiom_types::{BlsSignature, Preset, altair::SyncAggregate, combined, electra, gloas, phase0};

use crate::chain_builder::ChainBuilderError;

/// The votes a caller collected for a block, in the shape of the block's fork.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum BlockAttestations<P: Preset> {
    /// No votes.
    #[default]
    None,
    /// Votes of phase0 to Deneb, one committee each.
    Phase0(Vec<phase0::Attestation<P>>),
    /// Votes of Electra and Fulu, across committees.
    Electra(Vec<electra::Attestation<P>>),
    /// Votes of Gloas.
    Gloas(Vec<gloas::Attestation<P>>),
}

/// What a proposer supplies to a block a node builds for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockInputs<P: Preset> {
    /// The proposer's randao reveal.
    pub randao_reveal: BlsSignature,
    /// The votes to include.
    pub attestations: BlockAttestations<P>,
    /// The sync committee's aggregate, from Altair on; empty when none.
    pub sync_aggregate: Option<SyncAggregate<P>>,
}

/// A block built for a proposer to sign, with the envelope it must reveal once payloads separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedProposal<P: Preset> {
    /// The block, with its true state root.
    pub block: combined::BeaconBlock<P>,
    /// The envelope of a self-built Gloas payload.
    pub envelope: Option<gloas::ExecutionPayloadEnvelope<P>>,
}

impl<P: Preset> BlockInputs<P> {
    /// Places the votes in a block's body.
    ///
    /// # Errors
    ///
    /// Fails when the votes are of another fork's shape, or overflow the body's list.
    pub(crate) fn attach(
        &self,
        block: &mut combined::BeaconBlock<P>,
    ) -> Result<(), ChainBuilderError> {
        let (slot, fork) = (block.slot(), block.fork_name());
        let shape = || ChainBuilderError::AttestationShape { slot, fork };
        let overflow = |count: usize, limit: u64| ChainBuilderError::TooManyAttestations {
            count,
            limit: limit as usize,
        };
        match (&self.attestations, &mut *block) {
            (BlockAttestations::None, _) => {}
            (BlockAttestations::Phase0(votes), combined::BeaconBlock::Phase0(block)) => {
                block.body.attestations = votes
                    .clone()
                    .try_into()
                    .map_err(|_| overflow(votes.len(), P::MAX_ATTESTATIONS))?;
            }
            (BlockAttestations::Phase0(votes), combined::BeaconBlock::Altair(block)) => {
                block.body.attestations = votes
                    .clone()
                    .try_into()
                    .map_err(|_| overflow(votes.len(), P::MAX_ATTESTATIONS))?;
            }
            (BlockAttestations::Phase0(votes), combined::BeaconBlock::Bellatrix(block)) => {
                block.body.attestations = votes
                    .clone()
                    .try_into()
                    .map_err(|_| overflow(votes.len(), P::MAX_ATTESTATIONS))?;
            }
            (BlockAttestations::Phase0(votes), combined::BeaconBlock::Capella(block)) => {
                block.body.attestations = votes
                    .clone()
                    .try_into()
                    .map_err(|_| overflow(votes.len(), P::MAX_ATTESTATIONS))?;
            }
            (BlockAttestations::Phase0(votes), combined::BeaconBlock::Deneb(block)) => {
                block.body.attestations = votes
                    .clone()
                    .try_into()
                    .map_err(|_| overflow(votes.len(), P::MAX_ATTESTATIONS))?;
            }
            (
                BlockAttestations::Electra(votes),
                combined::BeaconBlock::Electra(block) | combined::BeaconBlock::Fulu(block),
            ) => {
                block.body.attestations = votes
                    .clone()
                    .try_into()
                    .map_err(|_| overflow(votes.len(), P::MAX_ATTESTATIONS_ELECTRA))?;
            }
            (BlockAttestations::Gloas(votes), combined::BeaconBlock::Gloas(block)) => {
                block.body.attestations = votes.clone().into();
            }
            (BlockAttestations::Gloas(votes), combined::BeaconBlock::Hstar(block)) => {
                block.body.attestations = votes.clone().into();
            }
            _ => return Err(shape()),
        }
        let Some(aggregate) = &self.sync_aggregate else {
            return Ok(());
        };
        let target = match block {
            combined::BeaconBlock::Phase0(_) => {
                return Err(ChainBuilderError::NoSyncAggregate(slot));
            }
            combined::BeaconBlock::Altair(block) => &mut block.body.sync_aggregate,
            combined::BeaconBlock::Bellatrix(block) => &mut block.body.sync_aggregate,
            combined::BeaconBlock::Capella(block) => &mut block.body.sync_aggregate,
            combined::BeaconBlock::Deneb(block) => &mut block.body.sync_aggregate,
            combined::BeaconBlock::Electra(block) | combined::BeaconBlock::Fulu(block) => {
                &mut block.body.sync_aggregate
            }
            combined::BeaconBlock::Gloas(block) => &mut block.body.sync_aggregate,
            combined::BeaconBlock::Hstar(block) => &mut block.body.sync_aggregate,
        };
        *target = aggregate.clone();
        Ok(())
    }
}
