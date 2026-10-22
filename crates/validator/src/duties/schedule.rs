//! Fetching duties from the beacon nodes, and preparing the subnets they need.

use std::sync::Arc;

use axiom_types::{Epoch, Preset, ValidatorIndex};
use tracing::{debug, info, warn};

use crate::{
    beacon::{BeaconCommitteeSubscription, SyncCommitteeSubscription},
    duties::{AggregatorSelection, AttesterSeat, DutyContext},
    signing::SigningRequest,
};

/// Keeps the duty book current for the epoch at hand and the next.
///
/// # Overview
///
/// Each refresh asks for duties again, which costs a few small requests a slot.
/// A changed dependent root means a reorg moved the shuffling, and the seats are rebuilt.
/// Unchanged seats keep their selection proofs, so no key signs a slot twice for nothing.
#[derive(Clone, Debug)]
pub struct DutyScheduler<P: Preset> {
    /// What the scheduler reaches.
    context: DutyContext<P>,
}

impl<P: Preset> DutyScheduler<P> {
    /// A scheduler over a context.
    #[must_use]
    pub const fn new(context: DutyContext<P>) -> Self {
        Self { context }
    }

    /// Brings the book up to date for an epoch and the next.
    pub async fn refresh(&self, epoch: Epoch) {
        self.resolve_indices().await;
        let indices: Vec<ValidatorIndex> = self
            .context
            .store
            .indices()
            .into_iter()
            .map(|(index, _)| index)
            .collect();
        if indices.is_empty() {
            return;
        }
        for epoch in [epoch, epoch + 1] {
            self.proposers(epoch).await;
            self.attesters(epoch, &indices).await;
            self.ptc(epoch, &indices).await;
        }
        self.sync(epoch, &indices).await;
        self.context.book().prune::<P>(epoch.saturating_sub(1));
    }

    /// Asks the nodes for the registry index of every key that lacks one.
    async fn resolve_indices(&self) {
        let unindexed = self.context.store.unindexed();
        if unindexed.is_empty() {
            return;
        }
        let keys = &unindexed;
        let found = self
            .context
            .nodes
            .first(|client| async move { client.beacon().validators(keys).await })
            .await;
        match found {
            Ok(summaries) => {
                for summary in summaries {
                    info!(
                        index = summary.index.0,
                        status = summary.status.as_str(),
                        "validator found"
                    );
                    self.context.store.set_index(&summary.pubkey, summary.index);
                }
            }
            Err(error) => warn!(%error, "validator indices unavailable"),
        }
    }

    /// Records an epoch's proposers.
    async fn proposers(&self, epoch: Epoch) {
        let duties = self
            .context
            .nodes
            .first(|client| async move { client.validator().proposer_duties(epoch).await })
            .await;
        match duties {
            Ok(duties) => self.context.book().set_proposers(epoch, duties),
            // The next epoch's proposers are known only from Fulu's lookahead on.
            Err(error) => debug!(epoch = epoch.0, %error, "proposer duties unavailable"),
        }
    }

    /// Records an epoch's committee seats, with aggregator proofs, and subscribes their subnets.
    async fn attesters(&self, epoch: Epoch, indices: &[ValidatorIndex]) {
        let duties = self
            .context
            .nodes
            .first(|client| async move { client.validator().attester_duties(epoch, indices).await })
            .await;
        let duties = match duties {
            Ok(duties) => duties,
            Err(error) => {
                warn!(epoch = epoch.0, %error, "attester duties unavailable");
                return;
            }
        };
        if self.context.book().attester_root(epoch) == Some(duties.dependent_root) {
            return;
        }

        // A seat aggregates when its slot signature selects it, see is_aggregator in the phase0 spec.
        let mut seats = Vec::with_capacity(duties.data.len());
        for duty in duties.data {
            let proof = self
                .context
                .store
                .sign::<P>(&duty.pubkey, SigningRequest::AggregationSlot(duty.slot))
                .await;
            let selection_proof = match proof {
                Ok(proof)
                    if AggregatorSelection::committee(duty.committee_length).selects(&proof) =>
                {
                    Some(proof)
                }
                Ok(_) => None,
                Err(error) => {
                    debug!(slot = duty.slot.0, %error, "no selection proof");
                    None
                }
            };
            seats.push(AttesterSeat {
                duty,
                selection_proof,
            });
        }
        let subscriptions: Arc<[BeaconCommitteeSubscription]> = seats
            .iter()
            .map(|seat| BeaconCommitteeSubscription {
                validator_index: seat.duty.validator_index,
                committee_index: seat.duty.committee_index,
                committees_at_slot: seat.duty.committees_at_slot,
                slot: seat.duty.slot,
                is_aggregator: seat.selection_proof.is_some(),
            })
            .collect();
        self.context
            .book()
            .set_attesters(epoch, duties.dependent_root, seats);
        if subscriptions.is_empty() {
            return;
        }
        let subscribed = self
            .context
            .nodes
            .broadcast(|client| {
                let subscriptions = Arc::clone(&subscriptions);
                async move {
                    client
                        .validator()
                        .beacon_committee_subscriptions(&subscriptions)
                        .await
                }
            })
            .await;
        if let Err(error) = subscribed {
            warn!(epoch = epoch.0, %error, "committee subscriptions refused");
        }
    }

    /// Records the sync committee seats of the current and next periods, and subscribes them.
    async fn sync(&self, epoch: Epoch, indices: &[ValidatorIndex]) {
        let length = P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let period = epoch.0 / length;
        for period in [period, period + 1] {
            if self.context.book().has_sync(period) {
                continue;
            }
            let start = Epoch(period * length);
            let duties = self
                .context
                .nodes
                .first(|client| async move { client.validator().sync_duties(start, indices).await })
                .await;
            let duties = match duties {
                Ok(duties) => duties.data,
                // Before Altair, and beyond the next period, there are no sync duties to know.
                Err(error) => {
                    debug!(period, %error, "sync duties unavailable");
                    continue;
                }
            };
            let subscriptions: Arc<[SyncCommitteeSubscription]> = duties
                .iter()
                .map(|duty| SyncCommitteeSubscription {
                    validator_index: duty.validator_index,
                    sync_committee_indices: duty.validator_sync_committee_indices.clone(),
                    until_epoch: Epoch((period + 1) * length),
                })
                .collect();
            self.context.book().set_sync(period, duties);
            if subscriptions.is_empty() {
                continue;
            }
            let subscribed = self
                .context
                .nodes
                .broadcast(|client| {
                    let subscriptions = Arc::clone(&subscriptions);
                    async move {
                        client
                            .validator()
                            .sync_committee_subscriptions(&subscriptions)
                            .await
                    }
                })
                .await;
            if let Err(error) = subscribed {
                warn!(period, %error, "sync subscriptions refused");
            }
        }
    }

    /// Records an epoch's payload timeliness seats.
    async fn ptc(&self, epoch: Epoch, indices: &[ValidatorIndex]) {
        // Only Gloas has a payload timeliness committee.
        if !self.context.fork_at(epoch).separates_payloads() {
            return;
        }
        let duties = self
            .context
            .nodes
            .first(|client| async move { client.validator().ptc_duties(epoch, indices).await })
            .await;
        match duties {
            Ok(duties) => self.context.book().set_ptc(epoch, duties.data),
            Err(error) => warn!(epoch = epoch.0, %error, "payload timeliness duties unavailable"),
        }
    }
}
