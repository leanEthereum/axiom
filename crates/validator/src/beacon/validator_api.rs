//! The validator namespace: duties, block and vote production, and preparation.

use axiom_beacon_json::{
    ApiJson, Fields, ForkedJson,
    api::{
        AttesterDuty, BeaconCommitteeSubscription, Duties, Liveness, ProposerDuty,
        ProposerPreparation, PtcDuty, SyncCommitteeSubscription, SyncDuty,
    },
};
use axiom_http::{Method, Request};
use axiom_json::{Data, Json};
use axiom_ssz::Ssz;
use axiom_types::{
    BlsSignature, Bytes32, CommitteeIndex, Epoch, ForkName, Preset, Root, Slot, ValidatorIndex,
    altair::{SignedContributionAndProof, SyncCommitteeContribution},
    bellatrix::SignedValidatorRegistrationV1,
    gloas::{ExecutionPayloadEnvelope, PayloadAttestationData, SignedProposerPreferences},
    phase0::AttestationData,
};

use crate::beacon::{
    Aggregate, BeaconClient, BeaconError, ProducedBlock, SignedAggregate,
    client::{CONSENSUS_VERSION, JSON, SSZ},
};

/// Header saying whether a produced block is blinded.
const BLINDED: &str = "eth-execution-payload-blinded";

/// The validator namespace of one beacon node.
#[derive(Clone, Copy, Debug)]
pub struct ValidatorEndpoints<'a> {
    /// The node.
    client: &'a BeaconClient,
}

impl<'a> ValidatorEndpoints<'a> {
    /// The namespace of a node.
    pub(crate) const fn new(client: &'a BeaconClient) -> Self {
        Self { client }
    }

    /// Every proposer of an epoch.
    ///
    /// See `getProposerDuties` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable, cannot see that epoch, or answers malformed data.
    pub async fn proposer_duties(self, epoch: Epoch) -> Result<Duties<ProposerDuty>, BeaconError> {
        let json = self
            .client
            .get_json(&format!("/eth/v1/validator/duties/proposer/{}", epoch.0))
            .await?;
        Ok(Duties::from_json(&json)?)
    }

    /// The committee seats of some validators in an epoch.
    ///
    /// See `getAttesterDuties` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable, cannot see that epoch, or answers malformed data.
    pub async fn attester_duties(
        self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<Duties<AttesterDuty>, BeaconError> {
        self.post_duties(
            &format!("/eth/v1/validator/duties/attester/{}", epoch.0),
            indices,
        )
        .await
    }

    /// The sync committee seats of some validators in an epoch's period.
    ///
    /// See `getSyncCommitteeDuties` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable, cannot see that period, or answers malformed data.
    pub async fn sync_duties(
        self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<Duties<SyncDuty>, BeaconError> {
        self.post_duties(
            &format!("/eth/v1/validator/duties/sync/{}", epoch.0),
            indices,
        )
        .await
    }

    /// The payload timeliness committee seats of some validators in an epoch.
    ///
    /// See `getPtcDuties` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable, cannot see that epoch, or answers malformed data.
    pub async fn ptc_duties(
        self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<Duties<PtcDuty>, BeaconError> {
        self.post_duties(
            &format!("/eth/v1/validator/duties/ptc/{}", epoch.0),
            indices,
        )
        .await
    }

    /// Duties of some validators, asked for by index.
    async fn post_duties<T: ApiJson>(
        self,
        target: &str,
        indices: &[ValidatorIndex],
    ) -> Result<Duties<T>, BeaconError> {
        let body = Json::Array(indices.iter().map(ApiJson::to_json).collect());
        let json = self
            .client
            .post_json(target, &body, None)
            .await?
            .ok_or(BeaconError::NoContent)?;
        Ok(Duties::from_json(&json)?)
    }

    /// A block for a slot before Gloas, with the proposer's randao reveal.
    ///
    /// A builder boost factor of zero asks for a locally built payload.
    /// See `produceBlockV3` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node cannot produce, answers a blinded block, or answers malformed data.
    pub async fn produce_block<P: Preset>(
        self,
        slot: Slot,
        randao_reveal: BlsSignature,
        graffiti: Bytes32,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProducedBlock<P>, BeaconError> {
        let boost = builder_boost_factor
            .map(|factor| format!("&builder_boost_factor={factor}"))
            .unwrap_or_default();
        let target = format!(
            "/eth/v3/validator/blocks/{}?randao_reveal={}&graffiti={}{boost}",
            slot.0,
            randao_reveal.0.to_data(),
            graffiti.0.to_data(),
        );
        let response = self.client.get_ssz(&target).await?;
        if response
            .headers
            .get(BLINDED)
            .is_some_and(|blinded| blinded.eq_ignore_ascii_case("true"))
        {
            return Err(BeaconError::Blinded);
        }
        let fork = BeaconClient::fork_of(&response)?;
        Ok(ProducedBlock::decode(&response.body, fork)?)
    }

    /// A Gloas block for a slot, whose self-built payload the node keeps for the envelope.
    ///
    /// The request takes only the local payload and p2p bids, with no external builder.
    /// See `produceBlockV4` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node cannot produce, or answers malformed data.
    pub async fn produce_gloas_block<P: Preset>(
        self,
        slot: Slot,
        randao_reveal: BlsSignature,
        graffiti: Bytes32,
    ) -> Result<ProducedBlock<P>, BeaconError> {
        let target = format!(
            "/eth/v4/validator/blocks/{}?randao_reveal={}&graffiti={}&include_payload=false",
            slot.0,
            randao_reveal.0.to_data(),
            graffiti.0.to_data(),
        );
        // A boost factor of zero prefers the local payload; no builder is asked.
        let config = Json::from([
            ("min_bid", 0_u64.to_json()),
            ("builder_boost_factor", 0_u64.to_json()),
            ("builders", Json::Array(Vec::new())),
        ]);
        let request = Request::new(Method::Post, &target)
            .with_header("accept", SSZ)
            .with_header(CONSENSUS_VERSION, ForkName::Gloas.as_str())
            .with_body(JSON, config.to_string().into_bytes());
        let response = self.client.send(request).await?;
        let fork = BeaconClient::fork_of(&response)?;
        Ok(ProducedBlock::decode(&response.body, fork)?)
    }

    /// The payload envelope the node built beside a Gloas block, for the proposer to sign.
    ///
    /// See `getExecutionPayloadEnvelope` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node holds no such envelope, or answers malformed data.
    pub async fn execution_payload_envelope<P: Preset>(
        self,
        slot: Slot,
        block_root: Root,
    ) -> Result<ExecutionPayloadEnvelope<P>, BeaconError> {
        let target = format!(
            "/eth/v1/validator/execution_payload_envelopes/{}/{}",
            slot.0,
            block_root.0.to_data()
        );
        let response = self.client.get_ssz(&target).await?;
        Ok(ExecutionPayloadEnvelope::decode(&response.body)?)
    }

    /// The vote a committee should sign at a slot.
    ///
    /// See `produceAttestationData` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or answers malformed data.
    pub async fn attestation_data(
        self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<AttestationData, BeaconError> {
        let json = self
            .client
            .get_json(&format!(
                "/eth/v1/validator/attestation_data?slot={}&committee_index={}",
                slot.0, committee_index.0
            ))
            .await?;
        BeaconClient::data(&json)
    }

    /// The best aggregate the node holds for a vote.
    ///
    /// See `getAggregatedAttestationV2` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node holds no aggregate for the vote, or answers malformed data.
    pub async fn aggregate_attestation<P: Preset>(
        self,
        slot: Slot,
        data_root: Root,
        committee_index: CommitteeIndex,
        fork: ForkName,
    ) -> Result<Aggregate<P>, BeaconError> {
        let json = self
            .client
            .get_json(&format!(
                "/eth/v2/validator/aggregate_attestation?attestation_data_root={}&slot={}&committee_index={}",
                data_root.0.to_data(),
                slot.0,
                committee_index.0
            ))
            .await?;
        let data = Fields::of(&json)?.raw("data")?;
        Ok(Aggregate::from_json_in(fork, data)?)
    }

    /// Publishes signed aggregates.
    ///
    /// See `publishAggregateAndProofsV2` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses an aggregate.
    pub async fn publish_aggregates<P: Preset>(
        self,
        fork: ForkName,
        aggregates: &[SignedAggregate<P>],
    ) -> Result<(), BeaconError> {
        let body = Json::Array(aggregates.iter().map(ForkedJson::to_json).collect());
        self.client
            .post_json("/eth/v2/validator/aggregate_and_proofs", &body, Some(fork))
            .await?;
        Ok(())
    }

    /// Asks the node to follow committee subnets, and to collect votes where an attester aggregates.
    ///
    /// See `prepareBeaconCommitteeSubnet` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses a subscription.
    pub async fn beacon_committee_subscriptions(
        self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), BeaconError> {
        let body = Json::Array(subscriptions.iter().map(ApiJson::to_json).collect());
        self.client
            .post_json(
                "/eth/v1/validator/beacon_committee_subscriptions",
                &body,
                None,
            )
            .await?;
        Ok(())
    }

    /// Asks the node to follow sync committee subnets.
    ///
    /// See `prepareSyncCommitteeSubnets` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses a subscription.
    pub async fn sync_committee_subscriptions(
        self,
        subscriptions: &[SyncCommitteeSubscription],
    ) -> Result<(), BeaconError> {
        let body = Json::Array(subscriptions.iter().map(ApiJson::to_json).collect());
        self.client
            .post_json(
                "/eth/v1/validator/sync_committee_subscriptions",
                &body,
                None,
            )
            .await?;
        Ok(())
    }

    /// The best sync contribution the node holds for a subcommittee and a block.
    ///
    /// See `produceSyncCommitteeContribution` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node holds no contribution, or answers malformed data.
    pub async fn sync_contribution<P: Preset>(
        self,
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: Root,
    ) -> Result<SyncCommitteeContribution<P>, BeaconError> {
        let json = self
            .client
            .get_json(&format!(
                "/eth/v1/validator/sync_committee_contribution?slot={}&subcommittee_index={}&beacon_block_root={}",
                slot.0,
                subcommittee_index,
                beacon_block_root.0.to_data()
            ))
            .await?;
        BeaconClient::data(&json)
    }

    /// Publishes signed sync contributions.
    ///
    /// See `publishContributionAndProofs` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses a contribution.
    pub async fn publish_contributions<P: Preset>(
        self,
        contributions: &[SignedContributionAndProof<P>],
    ) -> Result<(), BeaconError> {
        let body = Json::Array(contributions.iter().map(ApiJson::to_json).collect());
        self.client
            .post_json("/eth/v1/validator/contribution_and_proofs", &body, None)
            .await?;
        Ok(())
    }

    /// The payload timeliness vote for a slot, once the node has seen its block.
    ///
    /// See `producePayloadAttestationData` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails with no content when the node has seen no block for the slot.
    pub async fn payload_attestation_data(
        self,
        slot: Slot,
    ) -> Result<PayloadAttestationData, BeaconError> {
        let json = self
            .client
            .get_json(&format!(
                "/eth/v1/validator/payload_attestation_data?slot={}",
                slot.0
            ))
            .await?;
        BeaconClient::data(&json)
    }

    /// Tells the node where proposers' execution fees go.
    ///
    /// See `prepareBeaconProposer` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses a preparation.
    pub async fn prepare_beacon_proposer(
        self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        let body = Json::Array(preparations.iter().map(ApiJson::to_json).collect());
        self.client
            .post_json("/eth/v1/validator/prepare_beacon_proposer", &body, None)
            .await?;
        Ok(())
    }

    /// Registers validators with external builders, through the node.
    ///
    /// See `registerValidator` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses a registration.
    pub async fn register_validators(
        self,
        registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<(), BeaconError> {
        let body = Json::Array(registrations.iter().map(ApiJson::to_json).collect());
        self.client
            .post_json("/eth/v1/validator/register_validator", &body, None)
            .await?;
        Ok(())
    }

    /// Publishes signed proposer preferences for coming Gloas slots.
    ///
    /// See `submitProposerPreferences` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses a preference.
    pub async fn submit_proposer_preferences(
        self,
        preferences: &[SignedProposerPreferences],
    ) -> Result<(), BeaconError> {
        let body = Json::Array(preferences.iter().map(ApiJson::to_json).collect());
        self.client
            .post_json(
                "/eth/v1/validator/proposer_preferences",
                &body,
                Some(ForkName::Gloas),
            )
            .await?;
        Ok(())
    }

    /// Whether the node saw each validator active during an epoch.
    ///
    /// See `getLiveness` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable, cannot see that epoch, or answers malformed data.
    pub async fn liveness(
        self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<Vec<Liveness>, BeaconError> {
        let body = Json::Array(indices.iter().map(ApiJson::to_json).collect());
        let json = self
            .client
            .post_json(
                &format!("/eth/v1/validator/liveness/{}", epoch.0),
                &body,
                None,
            )
            .await?
            .ok_or(BeaconError::NoContent)?;
        BeaconClient::data(&json)
    }
}
