//! What validators tell the node ahead of their duties: fees, builders, subnets, and selections.
//!
//! See the preparation, subscription, and selection routes of beacon-APIs.

use std::future::{Ready, ready};

use axiom_beacon_json::api::{
    BeaconCommitteeSubscription, ProposerPreparation, SyncCommitteeSubscription,
};
use axiom_bls::{PublicKey, Signature};
use axiom_http::{Request, Response, StatusCode};
use axiom_p2p::eth::GossipKind;
use axiom_ssz::Ssz;
use axiom_types::{
    ForkName, Preset, bellatrix::SignedValidatorRegistrationV1, gloas::SignedProposerPreferences,
    phase0,
};

use super::{
    ApiContext,
    query::Body,
    reply::{ApiError, ApiResult, Failure, Reply, Routes},
};

/// Routes that prepare the node for its validators' coming duties.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PreparationRoutes;

impl PreparationRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .post(
                "/eth/v1/validator/prepare_beacon_proposer",
                Self::prepare_beacon_proposer::<P>,
            )
            .post(
                "/eth/v1/validator/register_validator",
                Self::register_validator::<P>,
            )
            .post(
                "/eth/v1/validator/proposer_preferences",
                Self::proposer_preferences::<P>,
            )
            .post(
                "/eth/v1/validator/beacon_committee_subscriptions",
                Self::beacon_committee_subscriptions::<P>,
            )
            .post(
                "/eth/v1/validator/sync_committee_subscriptions",
                Self::sync_committee_subscriptions::<P>,
            )
            .post(
                "/eth/v1/validator/beacon_committee_selections",
                Self::selections::<P>,
            )
            .post(
                "/eth/v1/validator/sync_committee_selections",
                Self::selections::<P>,
            )
    }

    /// Records the fee recipients validators name for their coming proposals.
    ///
    /// Unknown and inactive validators are accepted too: they may propose at a later epoch.
    /// See `prepareBeaconProposer` in the beacon API.
    async fn prepare_beacon_proposer<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let preparations: Vec<ProposerPreparation> = Body(&request).json_items()?;
        context.proposer.prepare(
            preparations
                .into_iter()
                .map(|preparation| (preparation.validator_index, preparation.fee_recipient)),
        );
        Ok(Response::new(StatusCode::OK))
    }

    /// Records the builder registrations validators signed.
    ///
    /// Each registration must carry its key's signature in the application builder domain.
    /// See `verify_registration_signature` in the Bellatrix builder spec.
    async fn register_validator<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        let registrations: Vec<SignedValidatorRegistrationV1> = Body(&request).items()?;
        let domain = context
            .query(|chain| Ok(chain.config().application_builder_domain()))
            .await?;
        let mut accepted = Vec::with_capacity(registrations.len());
        for (position, signed) in registrations.into_iter().enumerate() {
            let root = phase0::SigningData::signing_root(&signed.message, domain);
            let valid = PublicKey::from_bytes(&signed.message.pubkey.0)
                .ok()
                .zip(Signature::from_bytes(&signed.signature.0).ok())
                .is_some_and(|(key, signature)| signature.verify(&key, root.as_ref()));
            if !valid {
                return Err(ApiError::bad_request(format!(
                    "registration {position} is not signed by its key"
                )));
            }
            accepted.push(signed);
        }
        context.proposer.register_with_builders(&accepted).await;
        Ok(Response::new(StatusCode::OK))
    }

    /// Checks proposers' signed preferences as gossip would, then broadcasts those that pass.
    ///
    /// # Overview
    ///
    /// The gossip rules check the proposal slot, the dependent block, the proposer, and the signature.
    /// Preferences that pass are remembered by proposal slot and dependent root.
    /// Bids are then checked against them, until their slot is two epochs old.
    /// Any refusal, even one gossip would only ignore, is reported for its item.
    ///
    /// See `submitProposerPreferences` in the beacon API.
    /// See `validate_proposer_preferences_gossip` in the Gloas p2p spec.
    async fn proposer_preferences<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let named = request
            .headers
            .get("eth-consensus-version")
            .ok_or_else(|| ApiError::bad_request("missing consensus version header"))?;
        if ForkName::from_name(named).is_none() {
            return Err(ApiError::bad_request(format!(
                "unknown consensus version: {named}"
            )));
        }
        let submitted: Vec<SignedProposerPreferences> = Body(&request).items()?;
        let now = context.publisher.now_ms();
        let mut failures = Vec::<Failure>::new();
        for (position, signed) in submitted.into_iter().enumerate() {
            let epoch = signed.message.proposal_slot.epoch::<P>();
            let bytes = signed.encode();
            let verdict = context
                .query(move |chain| {
                    chain
                        .validate_gossip(|validator| validator.proposer_preferences(&signed, now))
                        .map_err(|error| ApiError::bad_request(error.to_string()))
                })
                .await;
            match verdict {
                Ok(()) => {
                    context
                        .publisher
                        .gossip(GossipKind::ProposerPreferences, epoch, bytes)
                        .await;
                }
                Err(error) => failures.push((position, error.to_string())),
            }
        }
        Reply::submission(failures)
    }

    /// Accepts attestation committee subscriptions.
    ///
    /// The node joins the attestation subnets of its own identity only.
    /// An aggregator on another subnet still receives the aggregates of its committee.
    /// See `prepareBeaconCommitteeSubnet` in the beacon API.
    async fn beacon_committee_subscriptions<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let _subscriptions: Vec<BeaconCommitteeSubscription> = Body(&request).json_items()?;
        // A subscription needs a running chain, whose subnets it would join.
        context.query(|_| Ok(())).await?;
        Ok(Response::new(StatusCode::OK))
    }

    /// Accepts sync committee subscriptions.
    ///
    /// The node joins no sync committee subnet on request, as with attestation subnets.
    /// See `prepareSyncCommitteeSubnets` in the beacon API.
    async fn sync_committee_subscriptions<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> ApiResult {
        let _subscriptions: Vec<SyncCommitteeSubscription> = Body(&request).json_items()?;
        context.query(|_| Ok(())).await?;
        Ok(Response::new(StatusCode::OK))
    }

    /// Refuses selection proof exchanges with a 501.
    ///
    /// Only distributed validator middleware combines partial selection proofs.
    /// A beacon node has no partial proofs to combine, and the API lets it answer so.
    /// See `submitBeaconCommitteeSelections` and `submitSyncCommitteeSelections` in the beacon API.
    fn selections<P: Preset>(_context: ApiContext<P>, _request: Request) -> Ready<ApiResult> {
        // Nothing to wait for: the answer never depends on the request.
        ready(Err(ApiError::not_implemented(
            "selection proofs are combined by distributed validator middleware, not a beacon node",
        )))
    }
}
