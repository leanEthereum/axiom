//! The beacon namespace: chain data a validator reads, and the messages it publishes.

use axiom_beacon_json::{
    ApiJson, Fields, ForkedJson,
    api::{Genesis, ValidatorResponse},
};
use axiom_http::{Method, Request};
use axiom_json::{Data, Json};
use axiom_ssz::Ssz;
use axiom_types::{
    BlsPubkey, ForkName, Preset, Root,
    altair::SyncCommitteeMessage,
    capella::SignedBlsToExecutionChange,
    gloas::{PayloadAttestationMessage, SignedExecutionPayloadEnvelope},
    phase0::SignedVoluntaryExit,
};

use crate::beacon::{BeaconClient, BeaconError, PoolAttestation, SignedProposal};

/// The beacon namespace of one beacon node.
#[derive(Clone, Copy, Debug)]
pub struct BeaconEndpoints<'a> {
    /// The node.
    client: &'a BeaconClient,
}

impl<'a> BeaconEndpoints<'a> {
    /// The namespace of a node.
    pub(crate) const fn new(client: &'a BeaconClient) -> Self {
        Self { client }
    }

    /// The chain's genesis.
    ///
    /// See `getGenesis` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable, has no genesis yet, or answers malformed data.
    pub async fn genesis(self) -> Result<Genesis, BeaconError> {
        let json = self.client.get_json("/eth/v1/beacon/genesis").await?;
        BeaconClient::data(&json)
    }

    /// The root of the node's head block.
    ///
    /// See `getBlockRoot` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or answers malformed data.
    pub async fn head_root(self) -> Result<Root, BeaconError> {
        let json = self
            .client
            .get_json("/eth/v1/beacon/blocks/head/root")
            .await?;
        let data = Fields::of(&json)?;
        Ok(Fields::of(data.raw("data")?)?.required("root")?)
    }

    /// The registry entries of the given keys in the head state; unknown keys are left out.
    ///
    /// See `postStateValidators` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or answers malformed data.
    pub async fn validators(
        self,
        pubkeys: &[BlsPubkey],
    ) -> Result<Vec<ValidatorResponse>, BeaconError> {
        let ids: Vec<Json> = pubkeys
            .iter()
            .map(|pubkey| Json::from(pubkey.0.to_data()))
            .collect();
        let body = Json::from([("ids", Json::Array(ids))]);
        let json = self
            .client
            .post_json("/eth/v1/beacon/states/head/validators", &body, None)
            .await?
            .ok_or(BeaconError::NoContent)?;
        BeaconClient::data(&json)
    }

    /// Publishes a signed block, with its blobs where its fork carries them.
    ///
    /// The node must check it as gossip would before broadcasting.
    /// See `publishBlockV2` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses the block.
    pub async fn publish_block<P: Preset>(
        self,
        proposal: &SignedProposal<P>,
    ) -> Result<(), BeaconError> {
        let request = Request::new(
            Method::Post,
            "/eth/v2/beacon/blocks?broadcast_validation=gossip",
        );
        self.client
            .post_ssz(request, proposal.encode(), proposal.fork())
            .await?;
        Ok(())
    }

    /// Publishes a self-built payload's signed envelope, whose blobs the node already holds.
    ///
    /// See `publishExecutionPayloadEnvelope` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses the envelope.
    pub async fn publish_envelope<P: Preset>(
        self,
        envelope: &SignedExecutionPayloadEnvelope<P>,
    ) -> Result<(), BeaconError> {
        let request = Request::new(Method::Post, "/eth/v1/beacon/execution_payload_envelopes")
            .with_header("eth-blob-data-included", "false");
        self.client
            .post_ssz(request, envelope.encode(), ForkName::Gloas)
            .await?;
        Ok(())
    }

    /// Submits single votes to the node's pool, for gossip.
    ///
    /// See `submitPoolAttestationsV2` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses a vote.
    pub async fn submit_attestations<P: Preset>(
        self,
        fork: ForkName,
        attestations: &[PoolAttestation<P>],
    ) -> Result<(), BeaconError> {
        let body = Json::Array(attestations.iter().map(ForkedJson::to_json).collect());
        self.client
            .post_json("/eth/v2/beacon/pool/attestations", &body, Some(fork))
            .await?;
        Ok(())
    }

    /// Submits sync committee messages.
    ///
    /// See `submitPoolSyncCommitteeSignatures` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses a message.
    pub async fn submit_sync_messages(
        self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), BeaconError> {
        let body = Json::Array(messages.iter().map(ApiJson::to_json).collect());
        self.client
            .post_json("/eth/v1/beacon/pool/sync_committees", &body, None)
            .await?;
        Ok(())
    }

    /// Submits payload timeliness votes.
    ///
    /// See `submitPayloadAttestationMessages` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses a vote.
    pub async fn submit_payload_attestations(
        self,
        messages: &[PayloadAttestationMessage],
    ) -> Result<(), BeaconError> {
        let body = Json::Array(messages.iter().map(ApiJson::to_json).collect());
        self.client
            .post_json(
                "/eth/v1/beacon/pool/payload_attestations",
                &body,
                Some(ForkName::Gloas),
            )
            .await?;
        Ok(())
    }

    /// Submits a voluntary exit.
    ///
    /// See `submitPoolVoluntaryExit` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses the exit.
    pub async fn submit_exit(self, exit: &SignedVoluntaryExit) -> Result<(), BeaconError> {
        self.client
            .post_json("/eth/v1/beacon/pool/voluntary_exits", &exit.to_json(), None)
            .await?;
        Ok(())
    }

    /// Submits withdrawal credential changes.
    ///
    /// See `submitPoolBLSToExecutionChange` in the beacon API.
    ///
    /// # Errors
    ///
    /// Fails when the node is unreachable or refuses a change.
    pub async fn submit_bls_changes(
        self,
        changes: &[SignedBlsToExecutionChange],
    ) -> Result<(), BeaconError> {
        let body = Json::Array(changes.iter().map(ApiJson::to_json).collect());
        self.client
            .post_json("/eth/v1/beacon/pool/bls_to_execution_changes", &body, None)
            .await?;
        Ok(())
    }
}
