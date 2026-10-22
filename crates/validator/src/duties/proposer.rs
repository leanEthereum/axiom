//! Block proposal: produce through a beacon node, sign, and publish.

use std::sync::Arc;

use axiom_beacon_json::api::ProposerDuty;
use axiom_ssz::Ssz;
use axiom_types::{Preset, Root, Slot, constants::BUILDER_INDEX_SELF_BUILD, gloas};
use tracing::{info, warn};

use crate::{
    beacon::BeaconClient,
    duties::{DutyContext, DutyError},
    signing::SigningRequest,
};

/// Proposes the blocks this client's validators are elected for.
///
/// # Overview
///
/// At the start of its slot, a proposer runs four steps:
///
/// 1. Sign the randao reveal of the epoch.
/// 2. Ask a beacon node to build a block around it.
/// 3. Sign the block's header, after slashing protection records it.
/// 4. Publish the block on every beacon node.
///
/// From Gloas on, a self-built block's payload follows in an envelope the proposer also signs.
/// The envelope comes from the node that built the block, which alone holds its blobs.
/// See the honest validator specs of phase0 and Gloas, and `produceBlockV3` and `produceBlockV4`.
#[derive(Clone, Debug)]
pub struct BlockProposer<P: Preset> {
    /// What the proposer reaches.
    context: DutyContext<P>,
}

impl<P: Preset> BlockProposer<P> {
    /// A proposer over a context.
    #[must_use]
    pub const fn new(context: DutyContext<P>) -> Self {
        Self { context }
    }

    /// Proposes every block this client owes at a slot.
    pub async fn propose(&self, slot: Slot) {
        // Invariant: the genesis block fills slot 0, so no proposer is owed a block there.
        // Duties still name a proposer for it, since the shuffling covers every slot of epoch 0.
        if slot == Slot(0) {
            return;
        }
        let duties: Vec<ProposerDuty> = self
            .context
            .book()
            .proposers(slot.epoch::<P>())
            .map(|duties| {
                duties
                    .data
                    .iter()
                    .filter(|duty| duty.slot == slot)
                    .copied()
                    .collect()
            })
            .unwrap_or_default();
        for duty in duties {
            if !self.context.store.contains(&duty.pubkey) {
                continue;
            }
            match self.propose_as(duty).await {
                Ok(()) => info!(
                    slot = slot.0,
                    proposer = duty.validator_index.0,
                    "block proposed"
                ),
                Err(error) => warn!(slot = slot.0, %error, "block proposal failed"),
            }
        }
    }

    /// Proposes one block.
    async fn propose_as(&self, duty: ProposerDuty) -> Result<(), DutyError> {
        let context = &self.context;
        let slot = duty.slot;
        let epoch = slot.epoch::<P>();
        let randao_reveal = context
            .store
            .sign::<P>(&duty.pubkey, SigningRequest::RandaoReveal(epoch))
            .await?;
        let graffiti = context.store.settings(&duty.pubkey).graffiti;
        let boost = context.settings.builder_boost_factor;

        // Gloas separates the payload from the block, and its route keeps the payload for the envelope.
        let separated = context.fork(slot).separates_payloads();
        let (produced, producer) = context
            .nodes
            .first(|client| async move {
                let produced = if separated {
                    client
                        .validator()
                        .produce_gloas_block::<P>(slot, randao_reveal, graffiti)
                        .await?
                } else {
                    client
                        .validator()
                        .produce_block::<P>(slot, randao_reveal, graffiti, boost)
                        .await?
                };
                Ok((produced, client))
            })
            .await?;

        // The node is not trusted to build what was asked: a block for another slot or proposer is refused.
        let header = produced.header();
        if header.slot != slot || header.proposer_index != duty.validator_index {
            return Err(DutyError::WrongBlock {
                slot: header.slot,
                proposer: header.proposer_index,
                expected_slot: slot,
                expected_proposer: duty.validator_index,
            });
        }
        let signature = context
            .store
            .sign::<P>(&duty.pubkey, SigningRequest::Block(&header))
            .await?;
        let proposal = Arc::new(produced.sign(signature));
        context
            .nodes
            .broadcast(|client| {
                let proposal = Arc::clone(&proposal);
                async move { client.beacon().publish_block(&proposal).await }
            })
            .await?;
        if separated {
            self.reveal(&duty, &producer, header.hash_tree_root())
                .await?;
        }
        Ok(())
    }

    /// Signs and publishes a self-built Gloas payload's envelope.
    ///
    /// A block that committed to a builder's bid has no envelope to sign here: the builder reveals it.
    async fn reveal(
        &self,
        duty: &ProposerDuty,
        producer: &BeaconClient,
        block_root: Root,
    ) -> Result<(), DutyError> {
        let envelope = producer
            .validator()
            .execution_payload_envelope::<P>(duty.slot, block_root)
            .await?;
        if envelope.builder_index != BUILDER_INDEX_SELF_BUILD {
            return Ok(());
        }
        let signature = self
            .context
            .store
            .sign::<P>(
                &duty.pubkey,
                SigningRequest::ExecutionPayloadEnvelope(&envelope),
            )
            .await?;
        let signed = gloas::SignedExecutionPayloadEnvelope {
            message: envelope,
            signature,
        };
        producer.beacon().publish_envelope(&signed).await?;
        Ok(())
    }
}
