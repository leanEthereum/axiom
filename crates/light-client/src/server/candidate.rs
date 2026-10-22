//! An update derived from one block, with its rank and the latest-update forms it yields.

use axiom_types::Preset;

use super::latest::Summary;
use crate::{
    LightClientError, UpdateQuality,
    combined::{LightClientFinalityUpdate, LightClientOptimisticUpdate, LightClientUpdate},
};

/// An update a block's sync aggregate signs, ready to serve in every form.
///
/// The forms are derived once, when the update is offered.
/// Choosing among candidates then never fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Candidate<P: Preset> {
    /// Rank among the updates of its period.
    pub(super) quality: UpdateQuality,
    /// Its slots and participation.
    pub(super) summary: Summary,
    /// The update, as range requests serve it.
    pub(super) update: LightClientUpdate<P>,
    /// Its finality form, when it proves a finalized header.
    pub(super) finality: Option<LightClientFinalityUpdate<P>>,
    /// Its optimistic form.
    pub(super) optimistic: LightClientOptimisticUpdate<P>,
}

impl<P: Preset> Candidate<P> {
    /// Ranks an update and derives its forms.
    ///
    /// See `create_light_client_finality_update` and `create_light_client_optimistic_update`.
    ///
    /// # Errors
    ///
    /// Fails when the update's headers have different formats.
    pub(super) fn new(update: LightClientUpdate<P>) -> Result<Self, LightClientError> {
        let data = update.clone().into_data();
        let finality = if data.is_finality_update() {
            Some(update.finality_update()?)
        } else {
            None
        };
        Ok(Self {
            quality: UpdateQuality::of(&data),
            summary: Summary::of(&data),
            optimistic: update.optimistic_update()?,
            finality,
            update,
        })
    }

    /// The period this update may be the best of, if any.
    ///
    /// Updates are assigned to the period of their attested header.
    /// A signature from the next period cannot vouch for the attested period's next committee.
    /// See the serving rules of the Altair light client full node spec.
    pub(super) fn period(&self) -> Option<u64> {
        let period = self.summary.attested.sync_committee_period::<P>();
        (period == self.summary.signature.sync_committee_period::<P>()).then_some(period)
    }

    /// The better of two candidates for the same period, by the spec's ranking.
    pub(super) fn better<'a>(first: &'a Self, second: &'a Self) -> &'a Self {
        if second.quality > first.quality {
            second
        } else {
            first
        }
    }
}
