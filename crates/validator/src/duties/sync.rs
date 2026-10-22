//! Sync committee duties: a vote for the head each slot, and contributions from aggregators.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use axiom_beacon_json::api::{SyncCommitteeSelection, SyncDuty};
use axiom_types::{
    BlsPubkey, BlsSignature, Preset, Root, Slot, ValidatorIndex,
    altair::{
        ContributionAndProof, SignedContributionAndProof, SyncAggregatorSelectionData,
        SyncCommitteeMessage,
    },
    constants::SYNC_COMMITTEE_SUBNET_COUNT,
};
use tracing::{debug, info, warn};

use crate::{
    beacon::ApiTopic,
    duties::{AggregatorSelection, DutyContext, DutyError},
    signing::SigningRequest,
};

/// A sync committee member's seat in one subcommittee, with the proof that may select it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SubcommitteeAggregator {
    /// The member's key.
    pubkey: BlsPubkey,
    /// The member.
    validator_index: ValidatorIndex,
    /// The subcommittee.
    subcommittee_index: u64,
    /// The proof that decides whether the member aggregates.
    selection_proof: BlsSignature,
}

/// Signs for this client's sync committee seats.
///
/// # Overview
///
/// A slot's sync duties run in two steps:
///
/// 1. At the sync message deadline, each member signs the head block's root once.
/// 2. At the contribution deadline, each selected aggregator signs its subcommittee's contribution.
///
/// A member with several seats signs one message; the node counts it for every seat.
/// See the Altair honest validator spec and `get_sync_message_due_ms`.
#[derive(Clone, Debug)]
pub struct SyncCommittee<P: Preset> {
    /// What the duties reach.
    context: DutyContext<P>,
}

impl<P: Preset> SyncCommittee<P> {
    /// Sync duties over a context.
    #[must_use]
    pub const fn new(context: DutyContext<P>) -> Self {
        Self { context }
    }

    /// Signs the slot's messages, then its contributions.
    pub async fn run(&self, slot: Slot) {
        let members: Vec<SyncDuty> = self
            .context
            .book()
            .sync_at::<P>(slot)
            .into_iter()
            .filter(|duty| self.context.store.contains(&duty.pubkey))
            .collect();
        if members.is_empty() {
            return;
        }
        let fork = self.context.fork(slot);
        let config = &self.context.config;
        self.context
            .timer
            .wait_until(slot, config.sync_message_due_bps(fork))
            .await;
        let root = match self.sign_messages(slot, &members).await {
            Ok(root) => root,
            Err(error) => {
                warn!(slot = slot.0, %error, "sync messages failed");
                return;
            }
        };
        let aggregators = self.aggregators(slot, &members).await;
        if aggregators.is_empty() {
            return;
        }
        self.context
            .timer
            .wait_until(slot, config.contribution_due_bps(fork))
            .await;
        if let Err(error) = self.contribute(slot, root, &aggregators).await {
            warn!(slot = slot.0, %error, "sync contributions failed");
        }
    }

    /// Signs and submits each member's vote for the head; returns the head's root.
    async fn sign_messages(&self, slot: Slot, members: &[SyncDuty]) -> Result<Root, DutyError> {
        let context = &self.context;
        let root = context
            .nodes
            .first(|client| async move { client.beacon().head_root().await })
            .await?;
        let mut messages = Vec::with_capacity(members.len());
        for member in members {
            let request = SigningRequest::<P>::SyncCommitteeMessage {
                slot,
                beacon_block_root: root,
            };
            match context.store.sign(&member.pubkey, request).await {
                Ok(signature) => messages.push(SyncCommitteeMessage {
                    slot,
                    beacon_block_root: root,
                    validator_index: member.validator_index,
                    signature,
                }),
                Err(error) => warn!(slot = slot.0, %error, "sync message not signed"),
            }
        }
        if messages.is_empty() {
            return Ok(root);
        }
        let count = messages.len();
        let messages = Arc::new(messages);
        context
            .nodes
            .publish(ApiTopic::SyncCommittee, |client| {
                let messages = Arc::clone(&messages);
                async move { client.beacon().submit_sync_messages(&messages).await }
            })
            .await?;
        info!(slot = slot.0, count, "sync messages published");
        Ok(root)
    }

    /// The members selected to aggregate each of their subcommittees.
    ///
    /// A distributed validator's shares sign partial proofs, which its middleware combines.
    /// See `is_sync_committee_aggregator` in the Altair validator spec.
    async fn aggregators(&self, slot: Slot, members: &[SyncDuty]) -> Vec<SubcommitteeAggregator> {
        let seats_per_subcommittee = P::SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT;
        let mut candidates = Vec::new();
        for member in members {
            // A member with several seats in one subcommittee aggregates it once.
            let subcommittees: BTreeSet<u64> = member
                .validator_sync_committee_indices
                .iter()
                .map(|seat| seat / seats_per_subcommittee)
                .collect();
            for subcommittee_index in subcommittees {
                let data = SyncAggregatorSelectionData {
                    slot,
                    subcommittee_index,
                };
                let proof = self
                    .context
                    .store
                    .sign::<P>(&member.pubkey, SigningRequest::SyncSelectionProof(&data))
                    .await;
                match proof {
                    Ok(selection_proof) => candidates.push(SubcommitteeAggregator {
                        pubkey: member.pubkey,
                        validator_index: member.validator_index,
                        subcommittee_index,
                        selection_proof,
                    }),
                    Err(error) => debug!(slot = slot.0, %error, "no sync selection proof"),
                }
            }
        }
        if self.context.settings.distributed {
            candidates = self.combine(slot, candidates).await;
        }
        let selection = AggregatorSelection::sync_subcommittee::<P>();
        candidates
            .into_iter()
            .filter(|candidate| selection.selects(&candidate.selection_proof))
            .collect()
    }

    /// Exchanges each share's partial selection proof for the cluster's combined one.
    ///
    /// A seat the middleware does not answer for is dropped, so it does not aggregate.
    /// See `submitSyncCommitteeSelections` in the beacon API.
    async fn combine(
        &self,
        slot: Slot,
        partial: Vec<SubcommitteeAggregator>,
    ) -> Vec<SubcommitteeAggregator> {
        if partial.is_empty() {
            return partial;
        }
        let selections: Vec<SyncCommitteeSelection> = partial
            .iter()
            .map(|candidate| SyncCommitteeSelection {
                validator_index: candidate.validator_index,
                slot,
                subcommittee_index: candidate.subcommittee_index,
                selection_proof: candidate.selection_proof,
            })
            .collect();
        let selections = &selections;
        let combined = self
            .context
            .nodes
            .first(|client| async move {
                client
                    .validator()
                    .sync_committee_selections(selections)
                    .await
            })
            .await;
        let combined: BTreeMap<(ValidatorIndex, u64), BlsSignature> = match combined {
            Ok(combined) => combined
                .into_iter()
                .filter(|selection| selection.slot == slot)
                .map(|selection| {
                    (
                        (selection.validator_index, selection.subcommittee_index),
                        selection.selection_proof,
                    )
                })
                .collect(),
            Err(error) => {
                warn!(slot = slot.0, %error, "distributed sync selection proofs unavailable");
                BTreeMap::new()
            }
        };
        partial
            .into_iter()
            .filter_map(|candidate| {
                let key = (candidate.validator_index, candidate.subcommittee_index);
                Some(SubcommitteeAggregator {
                    selection_proof: *combined.get(&key)?,
                    ..candidate
                })
            })
            .collect()
    }

    /// Signs and publishes each aggregator's contribution.
    async fn contribute(
        &self,
        slot: Slot,
        root: Root,
        aggregators: &[SubcommitteeAggregator],
    ) -> Result<(), DutyError> {
        let context = &self.context;
        let mut signed = Vec::new();
        for aggregator in aggregators {
            let subcommittee = aggregator.subcommittee_index;
            let contribution = context
                .nodes
                .first(|client| async move {
                    client
                        .validator()
                        .sync_contribution::<P>(slot, subcommittee, root)
                        .await
                })
                .await;
            let contribution = match contribution {
                Ok(contribution)
                    if contribution.slot == slot && contribution.beacon_block_root == root =>
                {
                    contribution
                }
                Ok(_) => {
                    warn!(slot = slot.0, "contribution is for another block");
                    continue;
                }
                Err(error) => {
                    debug!(slot = slot.0, subcommittee, %error, "no contribution");
                    continue;
                }
            };
            let message = ContributionAndProof {
                aggregator_index: aggregator.validator_index,
                contribution,
                selection_proof: aggregator.selection_proof,
            };
            let signature = context
                .store
                .sign::<P>(
                    &aggregator.pubkey,
                    SigningRequest::ContributionAndProof(&message),
                )
                .await;
            match signature {
                Ok(signature) => signed.push(SignedContributionAndProof { message, signature }),
                Err(error) => warn!(slot = slot.0, %error, "contribution not signed"),
            }
        }
        if signed.is_empty() {
            return Ok(());
        }
        let count = signed.len();
        let signed = Arc::new(signed);
        context
            .nodes
            .publish(ApiTopic::SyncCommittee, |client| {
                let signed = Arc::clone(&signed);
                async move { client.validator().publish_contributions(&signed).await }
            })
            .await?;
        info!(slot = slot.0, count, "sync contributions published");
        Ok(())
    }
}
