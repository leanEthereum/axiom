//! Payload timeliness votes: whether a Gloas block's payload and blobs arrived on time.

use std::sync::Arc;

use axiom_beacon_json::api::PtcDuty;
use axiom_types::{Preset, Slot, gloas::PayloadAttestationMessage};
use tracing::{debug, info, warn};

use crate::{
    beacon::BeaconError,
    duties::{DutyContext, DutyError},
    signing::SigningRequest,
};

/// Votes from this client's payload timeliness committee seats.
///
/// # Overview
///
/// At the payload attestation deadline, the node reports what it saw of the slot's block:
///
/// - whether the payload envelope arrived by the payload deadline,
/// - and whether the blob data is available.
///
/// Each seat signs that report.
/// A node that saw no block for the slot has nothing to report, and no vote is sent.
/// See the Gloas honest validator spec and `get_payload_attestation_due_ms`.
#[derive(Clone, Debug)]
pub struct PayloadTimeliness<P: Preset> {
    /// What the duty reaches.
    context: DutyContext<P>,
}

impl<P: Preset> PayloadTimeliness<P> {
    /// Payload timeliness duties over a context.
    #[must_use]
    pub const fn new(context: DutyContext<P>) -> Self {
        Self { context }
    }

    /// Votes for every seat at a slot.
    pub async fn run(&self, slot: Slot) {
        let seats: Vec<PtcDuty> = self
            .context
            .book()
            .ptc_at::<P>(slot)
            .into_iter()
            .filter(|duty| self.context.store.contains(&duty.pubkey))
            .collect();
        if seats.is_empty() {
            return;
        }
        let due = self.context.config.payload_attestation_due_bps;
        self.context.timer.wait_until(slot, due).await;
        match self.vote(slot, &seats).await {
            Ok(()) | Err(DutyError::Beacon(BeaconError::NoContent)) => {}
            Err(error) => warn!(slot = slot.0, %error, "payload timeliness votes failed"),
        }
    }

    /// Signs and submits each seat's vote.
    async fn vote(&self, slot: Slot, seats: &[PtcDuty]) -> Result<(), DutyError> {
        let context = &self.context;
        let data = context
            .nodes
            .first(|client| async move { client.validator().payload_attestation_data(slot).await })
            .await?;
        if data.slot != slot {
            return Err(DutyError::WrongSlot {
                slot: data.slot,
                expected: slot,
            });
        }
        let mut messages = Vec::with_capacity(seats.len());
        for seat in seats {
            let signature = context
                .store
                .sign::<P>(&seat.pubkey, SigningRequest::PayloadAttestation(&data))
                .await;
            match signature {
                Ok(signature) => messages.push(PayloadAttestationMessage {
                    validator_index: seat.validator_index,
                    data: data.clone(),
                    signature,
                }),
                Err(error) => debug!(slot = slot.0, %error, "payload vote not signed"),
            }
        }
        if messages.is_empty() {
            return Ok(());
        }
        let count = messages.len();
        let messages = Arc::new(messages);
        context
            .nodes
            .broadcast(|client| {
                let messages = Arc::clone(&messages);
                async move { client.beacon().submit_payload_attestations(&messages).await }
            })
            .await?;
        info!(slot = slot.0, count, "payload timeliness votes published");
        Ok(())
    }
}
