//! What a validator signs: one message, with what its signing root and its protection need.

use axiom_ssz::Ssz;
use axiom_types::{
    DomainType, Epoch, Preset, Root, Slot,
    altair::{ContributionAndProof, SyncAggregatorSelectionData},
    bellatrix::ValidatorRegistrationV1,
    capella::BlsToExecutionChange,
    constants::{
        DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER, DOMAIN_BEACON_ATTESTER,
        DOMAIN_BEACON_BUILDER, DOMAIN_BEACON_PROPOSER, DOMAIN_BLS_TO_EXECUTION_CHANGE,
        DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_DEPOSIT, DOMAIN_PROPOSER_PREFERENCES,
        DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF, DOMAIN_SYNC_COMMITTEE,
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
    },
    electra,
    gloas::{self, ExecutionPayloadEnvelope, PayloadAttestationData, ProposerPreferences},
    phase0::{self, AttestationData, BeaconBlockHeader, DepositMessage, VoluntaryExit},
};

/// One message a validator key is asked to sign.
///
/// Blocks are signed over their header, whose root equals the block's root.
/// A full block, a blinded block, and a Gloas block then share one path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningRequest<'a, P: Preset> {
    /// A block proposal.
    Block(&'a BeaconBlockHeader),
    /// The proposer's contribution to the epoch's randomness.
    RandaoReveal(Epoch),
    /// A vote for a head and a pair of checkpoints.
    Attestation(&'a AttestationData),
    /// The slot signature that decides whether an attester aggregates.
    AggregationSlot(Slot),
    /// An aggregate of a committee's votes, with the aggregator's proof.
    AggregateAndProof(AggregateAndProofRef<'a, P>),
    /// A sync committee member's vote for the head at a slot.
    SyncCommitteeMessage {
        /// The slot voted at.
        slot: Slot,
        /// The head block at that slot.
        beacon_block_root: Root,
    },
    /// The signature that decides whether a sync committee member aggregates.
    SyncSelectionProof(&'a SyncAggregatorSelectionData),
    /// A sync subcommittee aggregate, with the aggregator's proof.
    ContributionAndProof(&'a ContributionAndProof<P>),
    /// A payload timeliness committee vote.
    PayloadAttestation(&'a PayloadAttestationData),
    /// The payload a self-building proposer reveals.
    ExecutionPayloadEnvelope(&'a ExecutionPayloadEnvelope<P>),
    /// A proposer's fee recipient and gas limit for a coming slot.
    ProposerPreferences(&'a ProposerPreferences),
    /// A request to leave the validator set.
    VoluntaryExit(&'a VoluntaryExit),
    /// A registration with external block builders.
    ValidatorRegistration(&'a ValidatorRegistrationV1),
    /// A change of withdrawal credentials, signed by the withdrawal key.
    BlsToExecutionChange(&'a BlsToExecutionChange),
    /// A deposit, which proves possession of the key.
    Deposit(&'a DepositMessage),
}

/// An aggregate and proof, in the shape of the fork that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateAndProofRef<'a, P: Preset> {
    /// The phase0 to Deneb shape, one committee per aggregate.
    Phase0(&'a phase0::AggregateAndProof<P>),
    /// The Electra and Fulu shape, with committee bits.
    Electra(&'a electra::AggregateAndProof<P>),
    /// The Gloas shape, with unbounded aggregation bits.
    Gloas(&'a gloas::AggregateAndProof<P>),
}

impl<P: Preset> AggregateAndProofRef<'_, P> {
    /// The vote the aggregate carries.
    #[must_use]
    pub const fn data(&self) -> &AttestationData {
        match self {
            Self::Phase0(message) => &message.aggregate.data,
            Self::Electra(message) => &message.aggregate.data,
            Self::Gloas(message) => &message.aggregate.data,
        }
    }

    /// Root of the message.
    fn hash_tree_root(&self) -> Root {
        match self {
            Self::Phase0(message) => message.hash_tree_root(),
            Self::Electra(message) => message.hash_tree_root(),
            Self::Gloas(message) => message.hash_tree_root(),
        }
    }
}

/// How a message's signature domain picks its fork version and chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainScope {
    /// The version the fork schedule puts at an epoch, on this chain.
    ///
    /// See `get_domain` in the phase0 beacon chain spec.
    Epoch(Epoch),
    /// A voluntary exit's version: the schedule's until Deneb, Capella's from then on.
    ///
    /// See EIP-7044 and `process_voluntary_exit` in the Deneb beacon chain spec.
    VoluntaryExit(Epoch),
    /// The genesis version, on this chain.
    ///
    /// See `process_bls_to_execution_change` in the Capella beacon chain spec.
    Genesis,
    /// The genesis version, on no particular chain, so it is valid before genesis.
    ///
    /// See `process_deposit` in the phase0 beacon chain spec.
    PreGenesis,
}

/// The part of a message that slashing protection must see before it is signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protected {
    /// A block at a slot: a second, different block there is slashable.
    Block(Slot),
    /// A vote between two checkpoints: double and surround votes are slashable.
    Attestation {
        /// Epoch of the source checkpoint.
        source: Epoch,
        /// Epoch of the target checkpoint.
        target: Epoch,
    },
}

impl<P: Preset> SigningRequest<'_, P> {
    /// The signature domain type that separates this message from every other kind.
    #[must_use]
    pub const fn domain_type(&self) -> DomainType {
        match self {
            Self::Block(_) => DOMAIN_BEACON_PROPOSER,
            Self::RandaoReveal(_) => DOMAIN_RANDAO,
            Self::Attestation(_) => DOMAIN_BEACON_ATTESTER,
            Self::AggregationSlot(_) => DOMAIN_SELECTION_PROOF,
            Self::AggregateAndProof(_) => DOMAIN_AGGREGATE_AND_PROOF,
            Self::SyncCommitteeMessage { .. } => DOMAIN_SYNC_COMMITTEE,
            Self::SyncSelectionProof(_) => DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            Self::ContributionAndProof(_) => DOMAIN_CONTRIBUTION_AND_PROOF,
            Self::PayloadAttestation(_) => DOMAIN_PTC_ATTESTER,
            Self::ExecutionPayloadEnvelope(_) => DOMAIN_BEACON_BUILDER,
            Self::ProposerPreferences(_) => DOMAIN_PROPOSER_PREFERENCES,
            Self::VoluntaryExit(_) => DOMAIN_VOLUNTARY_EXIT,
            Self::ValidatorRegistration(_) => DOMAIN_APPLICATION_BUILDER,
            Self::BlsToExecutionChange(_) => DOMAIN_BLS_TO_EXECUTION_CHANGE,
            Self::Deposit(_) => DOMAIN_DEPOSIT,
        }
    }

    /// Which fork version and chain the signature domain commits to.
    ///
    /// Each epoch is the one its spec helper passes to the domain.
    /// See the signature helpers of the phase0, Altair, and Gloas validator specs.
    #[must_use]
    pub const fn domain_scope(&self) -> DomainScope {
        match self {
            Self::Block(header) => DomainScope::Epoch(header.slot.epoch::<P>()),
            Self::RandaoReveal(epoch) => DomainScope::Epoch(*epoch),
            Self::Attestation(data) => DomainScope::Epoch(data.target.epoch),
            Self::AggregationSlot(slot) | Self::SyncCommitteeMessage { slot, .. } => {
                DomainScope::Epoch(slot.epoch::<P>())
            }
            Self::AggregateAndProof(message) => {
                DomainScope::Epoch(message.data().slot.epoch::<P>())
            }
            Self::SyncSelectionProof(data) => DomainScope::Epoch(data.slot.epoch::<P>()),
            Self::ContributionAndProof(message) => {
                DomainScope::Epoch(message.contribution.slot.epoch::<P>())
            }
            Self::PayloadAttestation(data) => DomainScope::Epoch(data.slot.epoch::<P>()),
            Self::ExecutionPayloadEnvelope(envelope) => {
                DomainScope::Epoch(Slot(envelope.payload.slot_number).epoch::<P>())
            }
            Self::ProposerPreferences(preferences) => {
                DomainScope::Epoch(preferences.proposal_slot.epoch::<P>())
            }
            Self::VoluntaryExit(exit) => DomainScope::VoluntaryExit(exit.epoch),
            Self::BlsToExecutionChange(_) => DomainScope::Genesis,
            Self::ValidatorRegistration(_) | Self::Deposit(_) => DomainScope::PreGenesis,
        }
    }

    /// Root of the signed object, before the domain is mixed in.
    #[must_use]
    pub fn object_root(&self) -> Root {
        match self {
            Self::Block(header) => header.hash_tree_root(),
            Self::RandaoReveal(epoch) => epoch.hash_tree_root(),
            Self::Attestation(data) => data.hash_tree_root(),
            Self::AggregationSlot(slot) => slot.hash_tree_root(),
            Self::AggregateAndProof(message) => message.hash_tree_root(),
            // The root of a root is itself, so the message signs the block root directly.
            Self::SyncCommitteeMessage {
                beacon_block_root, ..
            } => *beacon_block_root,
            Self::SyncSelectionProof(data) => data.hash_tree_root(),
            Self::ContributionAndProof(message) => message.hash_tree_root(),
            Self::PayloadAttestation(data) => data.hash_tree_root(),
            Self::ExecutionPayloadEnvelope(envelope) => envelope.hash_tree_root(),
            Self::ProposerPreferences(preferences) => preferences.hash_tree_root(),
            Self::VoluntaryExit(exit) => exit.hash_tree_root(),
            Self::ValidatorRegistration(registration) => registration.hash_tree_root(),
            Self::BlsToExecutionChange(change) => change.hash_tree_root(),
            Self::Deposit(message) => message.hash_tree_root(),
        }
    }

    /// What slashing protection checks before this message is signed, if anything.
    ///
    /// Only blocks and attestations can be slashed, see the phase0 beacon chain spec.
    #[must_use]
    pub const fn protected(&self) -> Option<Protected> {
        match self {
            Self::Block(header) => Some(Protected::Block(header.slot)),
            Self::Attestation(data) => Some(Protected::Attestation {
                source: data.source.epoch,
                target: data.target.epoch,
            }),
            Self::RandaoReveal(_)
            | Self::AggregationSlot(_)
            | Self::AggregateAndProof(_)
            | Self::SyncCommitteeMessage { .. }
            | Self::SyncSelectionProof(_)
            | Self::ContributionAndProof(_)
            | Self::PayloadAttestation(_)
            | Self::ExecutionPayloadEnvelope(_)
            | Self::ProposerPreferences(_)
            | Self::VoluntaryExit(_)
            | Self::ValidatorRegistration(_)
            | Self::BlsToExecutionChange(_)
            | Self::Deposit(_) => None,
        }
    }

    /// The message kind, as the remote signing API and the logs name it.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Block(_) => "BLOCK_V2",
            Self::RandaoReveal(_) => "RANDAO_REVEAL",
            Self::Attestation(_) => "ATTESTATION",
            Self::AggregationSlot(_) => "AGGREGATION_SLOT",
            Self::AggregateAndProof(_) => "AGGREGATE_AND_PROOF_V2",
            Self::SyncCommitteeMessage { .. } => "SYNC_COMMITTEE_MESSAGE",
            Self::SyncSelectionProof(_) => "SYNC_COMMITTEE_SELECTION_PROOF",
            Self::ContributionAndProof(_) => "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
            Self::PayloadAttestation(_) => "PAYLOAD_ATTESTATION_MESSAGE",
            Self::ExecutionPayloadEnvelope(_) => "EXECUTION_PAYLOAD_ENVELOPE",
            Self::ProposerPreferences(_) => "PROPOSER_PREFERENCES",
            Self::VoluntaryExit(_) => "VOLUNTARY_EXIT",
            Self::ValidatorRegistration(_) => "VALIDATOR_REGISTRATION",
            Self::BlsToExecutionChange(_) => "BLS_TO_EXECUTION_CHANGE",
            Self::Deposit(_) => "DEPOSIT",
        }
    }
}
