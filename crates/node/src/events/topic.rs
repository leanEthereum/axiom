//! The topics of the beacon API's event stream, and sets of them.

use std::{fmt, str::FromStr};

use thiserror::Error;

/// One kind of event a client may subscribe to.
///
/// See the event stream route of the beacon API for when each fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventTopic {
    /// The fork choice picked a new head.
    Head,
    /// The fork choice picked a new head, with its payload status, from Gloas on.
    HeadV2,
    /// A block was imported.
    Block,
    /// A block passed gossip validation.
    BlockGossip,
    /// An attestation passed gossip validation.
    Attestation,
    /// A single attestation passed subnet validation, from Electra on.
    SingleAttestation,
    /// A voluntary exit passed gossip validation.
    VoluntaryExit,
    /// A withdrawal credential change passed gossip validation.
    BlsToExecutionChange,
    /// A proposer slashing passed gossip validation.
    ProposerSlashing,
    /// An attester slashing passed gossip validation.
    AttesterSlashing,
    /// A new checkpoint was finalized.
    FinalizedCheckpoint,
    /// The head moved off the previous head's chain.
    ChainReorg,
    /// A sync committee contribution passed gossip validation.
    ContributionAndProof,
    /// A new light client finality update is served.
    LightClientFinalityUpdate,
    /// A new light client optimistic update is served.
    LightClientOptimisticUpdate,
    /// The attributes a proposer will build its payload with.
    PayloadAttributes,
    /// A blob sidecar passed gossip validation.
    BlobSidecar,
    /// A data column sidecar passed gossip validation.
    DataColumnSidecar,
    /// A payload envelope was imported, from Gloas on.
    ExecutionPayload,
    /// A payload envelope passed gossip validation, from Gloas on.
    ExecutionPayloadGossip,
    /// A block's payload and blobs became available, from Gloas on.
    ExecutionPayloadAvailable,
    /// A builder's bid passed gossip validation, from Gloas on.
    ExecutionPayloadBid,
    /// A payload timeliness vote passed gossip validation, from Gloas on.
    PayloadAttestationMessage,
    /// A block reached fast confirmation.
    FastConfirmation,
    /// A proposer's preferences passed gossip validation, from Gloas on.
    ProposerPreferences,
}

impl EventTopic {
    /// Every topic, each with its own bit in a topic set.
    pub const ALL: [Self; 25] = [
        Self::Head,
        Self::HeadV2,
        Self::Block,
        Self::BlockGossip,
        Self::Attestation,
        Self::SingleAttestation,
        Self::VoluntaryExit,
        Self::BlsToExecutionChange,
        Self::ProposerSlashing,
        Self::AttesterSlashing,
        Self::FinalizedCheckpoint,
        Self::ChainReorg,
        Self::ContributionAndProof,
        Self::LightClientFinalityUpdate,
        Self::LightClientOptimisticUpdate,
        Self::PayloadAttributes,
        Self::BlobSidecar,
        Self::DataColumnSidecar,
        Self::ExecutionPayload,
        Self::ExecutionPayloadGossip,
        Self::ExecutionPayloadAvailable,
        Self::ExecutionPayloadBid,
        Self::PayloadAttestationMessage,
        Self::FastConfirmation,
        Self::ProposerPreferences,
    ];

    /// The topic's name, as subscriptions and the event field spell it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::HeadV2 => "head_v2",
            Self::Block => "block",
            Self::BlockGossip => "block_gossip",
            Self::Attestation => "attestation",
            Self::SingleAttestation => "single_attestation",
            Self::VoluntaryExit => "voluntary_exit",
            Self::BlsToExecutionChange => "bls_to_execution_change",
            Self::ProposerSlashing => "proposer_slashing",
            Self::AttesterSlashing => "attester_slashing",
            Self::FinalizedCheckpoint => "finalized_checkpoint",
            Self::ChainReorg => "chain_reorg",
            Self::ContributionAndProof => "contribution_and_proof",
            Self::LightClientFinalityUpdate => "light_client_finality_update",
            Self::LightClientOptimisticUpdate => "light_client_optimistic_update",
            Self::PayloadAttributes => "payload_attributes",
            Self::BlobSidecar => "blob_sidecar",
            Self::DataColumnSidecar => "data_column_sidecar",
            Self::ExecutionPayload => "execution_payload",
            Self::ExecutionPayloadGossip => "execution_payload_gossip",
            Self::ExecutionPayloadAvailable => "execution_payload_available",
            Self::ExecutionPayloadBid => "execution_payload_bid",
            Self::PayloadAttestationMessage => "payload_attestation_message",
            Self::FastConfirmation => "fast_confirmation",
            Self::ProposerPreferences => "proposer_preferences",
        }
    }

    /// The topic's bit in a set, from its place in declaration order.
    ///
    /// Twenty-five topics fit in a 32-bit word.
    const fn bit(self) -> u32 {
        1 << self as u32
    }
}

impl fmt::Display for EventTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A topic name no event carries.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("unknown event topic: {0}")]
pub struct UnknownTopic(pub String);

impl FromStr for EventTopic {
    type Err = UnknownTopic;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|topic| topic.as_str() == name)
            .ok_or_else(|| UnknownTopic(name.to_owned()))
    }
}

/// A set of topics, one bit each.
///
/// The set fits a machine word, so the hub publishes the union of every subscription atomically.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TopicSet(u32);

impl TopicSet {
    /// The empty set.
    pub const EMPTY: Self = Self(0);

    /// The set as a word, for an atomic.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// The set a word holds.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Whether the set holds a topic.
    #[must_use]
    pub const fn contains(self, topic: EventTopic) -> bool {
        self.0 & topic.bit() != 0
    }

    /// The set with a topic added.
    #[must_use]
    pub const fn with(self, topic: EventTopic) -> Self {
        Self(self.0 | topic.bit())
    }

    /// Both sets together.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether the set holds no topic.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl FromIterator<EventTopic> for TopicSet {
    fn from_iter<I: IntoIterator<Item = EventTopic>>(topics: I) -> Self {
        topics.into_iter().fold(Self::EMPTY, Self::with)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_topic_has_its_own_bit_and_name() {
        // Twenty-five topics, twenty-five distinct bits, all inside one word.
        let all: TopicSet = EventTopic::ALL.into_iter().collect();
        assert_eq!(all.bits().count_ones(), 25);

        // Every name parses back to its topic.
        for topic in EventTopic::ALL {
            assert_eq!(topic.as_str().parse(), Ok(topic));
        }
        assert_eq!(
            "heads".parse::<EventTopic>(),
            Err(UnknownTopic("heads".to_owned()))
        );
    }

    #[test]
    fn sets_hold_what_was_added() {
        let set = TopicSet::EMPTY
            .with(EventTopic::Head)
            .with(EventTopic::ChainReorg);
        assert!(set.contains(EventTopic::Head));
        assert!(set.contains(EventTopic::ChainReorg));
        assert!(!set.contains(EventTopic::Block));
        assert_eq!(
            set.union(TopicSet::EMPTY.with(EventTopic::Block))
                .bits()
                .count_ones(),
            3
        );
        assert!(TopicSet::EMPTY.is_empty());
    }
}
