//! Gossip validation vectors: a chain, then messages each expected to pass, be ignored, or be rejected.

use std::{collections::HashMap, marker::PhantomData};

use axiom_fork_choice::{BlockNode, ExecutionStatus, Store};
use axiom_gossip::{ChainView, GossipError, GossipValidator, Seen};
use axiom_ssz::{Root, Ssz};
use axiom_state_transition::{KnownVerdict, Verification};
use axiom_types::{
    AttesterSlashing, BeaconState, Checkpoint, DataColumnSidecar, Epoch, Preset, ProposerSlashing,
    SignedAggregateAndProof, SignedBeaconBlock, SignedBlsToExecutionChange,
    SignedContributionAndProof, SignedVoluntaryExit, SingleAttestation, SubnetId,
    SyncCommitteeMessage,
};
use axiom_yaml::Yaml;

use super::case_config;
use crate::{Case, Failure};

/// Builds the chain a gossip case describes, then checks each message's verdict.
#[derive(Debug)]
pub(super) struct GossipCase<'c, P: Preset> {
    /// The case directory.
    case: &'c Case,
    /// The case metadata.
    meta: Yaml,
    /// The preset.
    preset: PhantomData<P>,
}

impl<'c, P: Preset> GossipCase<'c, P> {
    /// A case ready to run.
    ///
    /// # Errors
    ///
    /// Fails when the metadata does not parse.
    pub(super) fn new(case: &'c Case) -> Result<Self, Failure> {
        Ok(Self {
            case,
            meta: case.yaml("meta.yaml")?,
            preset: PhantomData,
        })
    }

    /// Runs every message of the case.
    ///
    /// # Errors
    ///
    /// Fails when a verdict differs from the expected one.
    pub(super) fn run(&self) -> Result<(), Failure> {
        let config = case_config::<P>(self.case)?;
        let blocks = self
            .meta
            .get("blocks")
            .and_then(Yaml::as_sequence)
            .unwrap_or_default();
        let anchor_name = blocks
            .first()
            .and_then(|entry| entry.get("block"))
            .and_then(Yaml::as_str)
            .ok_or_else(|| Failure::new("meta.yaml has no anchor block"))?;
        let anchor = self.case.ssz::<SignedBeaconBlock<P>>(anchor_name)?;
        let anchor_state = self.case.ssz::<BeaconState<P>>("state")?;
        let mut store = Store::new(config.clone(), anchor_state, &anchor.message)
            .map_err(|error| Failure(format!("anchor rejected: {error}")))?;

        // Phase 1: replay the chain, keeping failed and pending blocks out of the store.
        let mut unimported = HashMap::new();
        let mut payload_statuses = HashMap::new();
        for entry in blocks {
            let name = entry
                .get("block")
                .and_then(Yaml::as_str)
                .ok_or_else(|| Failure::new("block entry without a name"))?;
            let block = self.case.ssz::<SignedBeaconBlock<P>>(name)?;
            let root = block.message.hash_tree_root();
            let flag = |key: &str| entry.get(key).and_then(Yaml::as_bool).unwrap_or(false);
            if let Some(status) = entry.get("payload_status").and_then(Yaml::as_str) {
                payload_statuses.insert(root, Self::execution_status(status)?);
            }
            if root == anchor.message.hash_tree_root() {
                continue;
            }
            if flag("failed") || flag("pending") {
                unimported.insert(root, Self::node(&block));
                continue;
            }
            let mut state = store
                .block_state(&block.message.parent_root)
                .cloned()
                .ok_or_else(|| Failure(format!("parent of {name} is unknown")))?;
            state
                .state_transition(&config, &block, Verification::Skip, &KnownVerdict(true))
                .map_err(|error| Failure(format!("{name} failed to import: {error}")))?;
            store.insert_validated_block(&block.message, state);
        }

        let mut view = ChainView::new(&mut store, &unimported, &payload_statuses);
        if let Some(finalized) = self.meta.get("finalized_checkpoint") {
            view.finalized = self.finalized(finalized)?;
        }

        // Phase 2: validate each message in order, updating the seen state on success.
        let mut seen = Seen::default();
        let topic = self
            .meta
            .get("topic")
            .and_then(Yaml::as_str)
            .unwrap_or_default()
            .to_owned();
        let messages = self
            .meta
            .get("messages")
            .and_then(Yaml::as_sequence)
            .unwrap_or_default();
        for (number, message) in messages.iter().enumerate() {
            let mut validator = GossipValidator::new(&mut view, &mut seen);
            let verdict = self.validate(&mut validator, &topic, message)?;
            let actual = match verdict {
                Ok(()) => "valid",
                Err(GossipError::Ignore(_)) => "ignore",
                Err(GossipError::Reject(_)) => "reject",
            };
            let expected = message
                .get("expected")
                .and_then(Yaml::as_str)
                .unwrap_or_default();
            if actual != expected {
                let reason = message
                    .get("reason")
                    .and_then(Yaml::as_str)
                    .unwrap_or_default();
                return Err(Failure(format!(
                    "message {number}: expected {expected} ({reason}), got {}",
                    verdict.map_or_else(|error| error.to_string(), |()| "valid".to_owned())
                )));
            }
        }
        Ok(())
    }

    /// Validates one message under its topic's rules.
    fn validate(
        &self,
        validator: &mut GossipValidator<'_, '_, P>,
        topic: &str,
        message: &Yaml,
    ) -> Result<Result<(), GossipError>, Failure> {
        let name = message
            .get("message")
            .and_then(Yaml::as_str)
            .ok_or_else(|| Failure::new("message without a name"))?;
        let now = message
            .get("current_time_ms")
            .and_then(Yaml::as_u64)
            .unwrap_or_default();
        let subnet = SubnetId(
            message
                .get("subnet_id")
                .and_then(Yaml::as_u64)
                .unwrap_or_default(),
        );
        Ok(match topic {
            "beacon_block" => {
                validator.beacon_block(&self.case.ssz::<SignedBeaconBlock<P>>(name)?, now)
            }
            "beacon_aggregate_and_proof" => validator
                .aggregate_and_proof(&self.case.ssz::<SignedAggregateAndProof<P>>(name)?, now),
            "beacon_attestation" => validator.beacon_attestation(
                &self.case.ssz::<SingleAttestation>(name)?,
                now,
                subnet,
            ),
            "voluntary_exit" => {
                validator.voluntary_exit(&self.case.ssz::<SignedVoluntaryExit>(name)?, now)
            }
            "proposer_slashing" => {
                validator.proposer_slashing(&self.case.ssz::<ProposerSlashing>(name)?)
            }
            "attester_slashing" => {
                validator.attester_slashing(&self.case.ssz::<AttesterSlashing<P>>(name)?)
            }
            "sync_committee_contribution_and_proof" => validator
                .sync_contribution(&self.case.ssz::<SignedContributionAndProof<P>>(name)?, now),
            "sync_committee" => validator.sync_committee_message(
                &self.case.ssz::<SyncCommitteeMessage>(name)?,
                now,
                subnet,
            ),
            "bls_to_execution_change" => validator
                .bls_to_execution_change(&self.case.ssz::<SignedBlsToExecutionChange>(name)?, now),
            "data_column_sidecar" => validator.data_column_sidecar(
                &self.case.ssz::<DataColumnSidecar<P>>(name)?,
                now,
                subnet,
                |_| true,
            ),
            other => return Err(Failure(format!("unsupported topic {other}"))),
        })
    }

    /// The finalized checkpoint the case imposes.
    fn finalized(&self, value: &Yaml) -> Result<Checkpoint, Failure> {
        let epoch = Epoch(
            value
                .get("epoch")
                .and_then(Yaml::as_u64)
                .ok_or_else(|| Failure::new("finalized checkpoint without epoch"))?,
        );
        let root = if let Some(root) = value.get("root").and_then(Yaml::as_hex_array::<32>) {
            Root(root)
        } else {
            let name = value
                .get("block")
                .and_then(Yaml::as_str)
                .ok_or_else(|| Failure::new("finalized checkpoint without root"))?;
            self.case
                .ssz::<SignedBeaconBlock<P>>(name)?
                .message
                .hash_tree_root()
        };
        Ok(Checkpoint { epoch, root })
    }

    /// The fork choice view of a block that was seen but not imported.
    const fn node(block: &SignedBeaconBlock<P>) -> BlockNode {
        BlockNode {
            slot: block.message.slot,
            parent_root: block.message.parent_root,
            proposer_index: block.message.proposer_index,
            execution_block_hash: block.message.body.execution_payload.block_hash,
            status: ExecutionStatus::Optimistic,
        }
    }

    /// A payload status from the vectors' vocabulary.
    fn execution_status(status: &str) -> Result<ExecutionStatus, Failure> {
        match status {
            "VALID" => Ok(ExecutionStatus::Valid),
            "INVALIDATED" => Ok(ExecutionStatus::Invalid),
            "NOT_VALIDATED" => Ok(ExecutionStatus::Optimistic),
            other => Err(Failure(format!("unknown payload status {other}"))),
        }
    }
}
