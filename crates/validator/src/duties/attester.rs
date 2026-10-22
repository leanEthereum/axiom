//! Attestation and aggregation: vote by the attestation deadline, aggregate by the next.

use std::{collections::BTreeMap, sync::Arc};

use axiom_ssz::Ssz;
use axiom_types::{BlsPubkey, CommitteeIndex, Preset, Slot, phase0::AttestationData};
use tracing::{debug, info, warn};

use crate::{
    beacon::{PoolAttestation, SignedAggregate},
    duties::{AttesterSeat, DutyContext, DutyError},
    signing::SigningRequest,
};

/// Votes and aggregates for this client's committee seats.
///
/// # Overview
///
/// A slot's attesters run in two steps:
///
/// 1. At the attestation deadline, fetch each committee's vote, sign it, and submit it.
/// 2. At the aggregate deadline, each selected aggregator fetches the best aggregate and signs it.
///
/// Waiting for the deadline rather than the block is allowed by the honest validator spec.
/// It gives the block the whole first part of the slot to arrive.
/// The deadlines move earlier at Gloas, see `get_attestation_due_ms` and `get_aggregate_due_ms`.
#[derive(Clone, Debug)]
pub struct Attester<P: Preset> {
    /// What the attester reaches.
    context: DutyContext<P>,
}

impl<P: Preset> Attester<P> {
    /// An attester over a context.
    #[must_use]
    pub const fn new(context: DutyContext<P>) -> Self {
        Self { context }
    }

    /// Votes, then aggregates, for every seat at a slot.
    pub async fn run(&self, slot: Slot) {
        let seats = self.context.book().attesters_at::<P>(slot);
        let seats: Vec<AttesterSeat> = seats
            .into_iter()
            .filter(|seat| self.context.store.contains(&seat.duty.pubkey))
            .collect();
        if seats.is_empty() {
            return;
        }
        let fork = self.context.fork(slot);
        let config = &self.context.config;
        self.context
            .timer
            .wait_until(slot, config.attestation_due_bps(fork))
            .await;
        let votes = match self.vote(slot, &seats).await {
            Ok(votes) => votes,
            Err(error) => {
                warn!(slot = slot.0, %error, "attestations failed");
                return;
            }
        };
        if seats.iter().all(|seat| seat.selection_proof.is_none()) {
            return;
        }
        self.context
            .timer
            .wait_until(slot, config.aggregate_due_bps(fork))
            .await;
        if let Err(error) = self.aggregate(slot, &seats, &votes).await {
            warn!(slot = slot.0, %error, "aggregation failed");
        }
    }

    /// Signs and submits each seat's vote; returns each committee's vote.
    async fn vote(
        &self,
        slot: Slot,
        seats: &[AttesterSeat],
    ) -> Result<BTreeMap<CommitteeIndex, AttestationData>, DutyError> {
        let context = &self.context;
        let fork = context.fork(slot);

        // Phase 1: one vote per committee, checked to be for the slot asked.
        let mut votes = BTreeMap::new();
        for seat in seats {
            let committee = seat.duty.committee_index;
            if votes.contains_key(&committee) {
                continue;
            }
            let data = context
                .nodes
                .first(|client| async move {
                    client.validator().attestation_data(slot, committee).await
                })
                .await?;
            if data.slot != slot {
                return Err(DutyError::WrongSlot {
                    slot: data.slot,
                    expected: slot,
                });
            }
            votes.insert(committee, data);
        }

        // Phase 2: every seat's vote cleared in one durable write, then signed.
        let requests: Vec<(BlsPubkey, &AttestationData)> = seats
            .iter()
            .filter_map(|seat| Some((seat.duty.pubkey, votes.get(&seat.duty.committee_index)?)))
            .collect();
        let signatures = context.store.sign_votes::<P>(&requests).await;

        // Phase 3: each fork's shape of a single vote, submitted together.
        let mut attestations = Vec::with_capacity(seats.len());
        for (seat, signature) in seats.iter().zip(signatures) {
            let Some(data) = votes.get(&seat.duty.committee_index) else {
                continue;
            };
            match signature {
                Ok(signature) => attestations.push(PoolAttestation::<P>::new(
                    fork,
                    &seat.duty,
                    data.clone(),
                    signature,
                )?),
                Err(error) => {
                    warn!(slot = slot.0, validator = seat.duty.validator_index.0, %error, "vote not signed");
                }
            }
        }
        if attestations.is_empty() {
            return Ok(votes);
        }
        let count = attestations.len();
        let attestations = Arc::new(attestations);
        context
            .nodes
            .broadcast(|client| {
                let attestations = Arc::clone(&attestations);
                async move {
                    client
                        .beacon()
                        .submit_attestations(fork, &attestations)
                        .await
                }
            })
            .await?;
        info!(slot = slot.0, count, "attestations published");
        Ok(votes)
    }

    /// Signs and publishes an aggregate for every seat selected to aggregate.
    async fn aggregate(
        &self,
        slot: Slot,
        seats: &[AttesterSeat],
        votes: &BTreeMap<CommitteeIndex, AttestationData>,
    ) -> Result<(), DutyError> {
        let context = &self.context;
        let fork = context.fork(slot);
        let mut signed = Vec::new();
        for seat in seats {
            let (Some(selection_proof), Some(data)) =
                (seat.selection_proof, votes.get(&seat.duty.committee_index))
            else {
                continue;
            };
            let committee = seat.duty.committee_index;
            let data_root = data.hash_tree_root();
            let aggregate = context
                .nodes
                .first(|client| async move {
                    client
                        .validator()
                        .aggregate_attestation::<P>(slot, data_root, committee, fork)
                        .await
                })
                .await;
            let aggregate = match aggregate {
                Ok(aggregate) if aggregate.data() == data => aggregate,
                Ok(_) => {
                    warn!(slot = slot.0, "aggregate is for another vote");
                    continue;
                }
                Err(error) => {
                    debug!(slot = slot.0, committee = committee.0, %error, "no aggregate");
                    continue;
                }
            };
            let message = aggregate.with_proof(seat.duty.validator_index, selection_proof);
            let signature = context
                .store
                .sign::<P>(
                    &seat.duty.pubkey,
                    SigningRequest::AggregateAndProof(message.as_ref()),
                )
                .await;
            match signature {
                Ok(signature) => signed.push(message.sign(signature)),
                Err(error) => warn!(slot = slot.0, %error, "aggregate not signed"),
            }
        }
        if signed.is_empty() {
            return Ok(());
        }
        let count = signed.len();
        let signed: Arc<Vec<SignedAggregate<P>>> = Arc::new(signed);
        context
            .nodes
            .broadcast(|client| {
                let signed = Arc::clone(&signed);
                async move { client.validator().publish_aggregates(fork, &signed).await }
            })
            .await?;
        info!(slot = slot.0, count, "aggregates published");
        Ok(())
    }
}
