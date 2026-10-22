//! Ethereum gossip topic names.

use std::{fmt, str::FromStr};

use axiom_types::ForkDigest;
use thiserror::Error;

use crate::gossipsub::Topic;

/// The only gossip encoding defined.
const ENCODING: &str = "ssz_snappy";

/// The family prefix of every consensus topic.
const PREFIX: &str = "eth2";

/// What a topic carries, independent of the fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GossipKind {
    /// Signed beacon blocks.
    BeaconBlock,
    /// Signed aggregates and their selection proofs.
    BeaconAggregateAndProof,
    /// Unaggregated attestations on one of 64 subnets.
    BeaconAttestation(u64),
    /// Signed voluntary exits.
    VoluntaryExit,
    /// Proposer slashings.
    ProposerSlashing,
    /// Attester slashings.
    AttesterSlashing,
    /// Sync committee contributions and proofs, Altair.
    SyncCommitteeContributionAndProof,
    /// Sync committee messages on one of 4 subnets, Altair.
    SyncCommittee(u64),
    /// BLS-to-execution credential changes, Capella.
    BlsToExecutionChange,
    /// Light client finality updates, Altair.
    LightClientFinalityUpdate,
    /// Light client optimistic updates, Altair.
    LightClientOptimisticUpdate,
    /// Blob sidecars on a subnet, Deneb to Electra; deprecated by Fulu.
    BlobSidecar(u64),
    /// Data column sidecars on one of 128 subnets, Fulu.
    DataColumnSidecar(u64),
    /// Signed execution payload envelopes, Gloas.
    ExecutionPayload,
    /// Payload timeliness committee votes, Gloas.
    PayloadAttestationMessage,
    /// Builders' signed bids for a slot's payload, Gloas.
    ExecutionPayloadBid,
    /// Proposers' signed preferences for their coming slots, Gloas.
    ProposerPreferences,
}

impl fmt::Display for GossipKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeaconBlock => f.write_str("beacon_block"),
            Self::BeaconAggregateAndProof => f.write_str("beacon_aggregate_and_proof"),
            Self::BeaconAttestation(subnet) => write!(f, "beacon_attestation_{subnet}"),
            Self::VoluntaryExit => f.write_str("voluntary_exit"),
            Self::ProposerSlashing => f.write_str("proposer_slashing"),
            Self::AttesterSlashing => f.write_str("attester_slashing"),
            Self::SyncCommitteeContributionAndProof => {
                f.write_str("sync_committee_contribution_and_proof")
            }
            Self::SyncCommittee(subnet) => write!(f, "sync_committee_{subnet}"),
            Self::BlsToExecutionChange => f.write_str("bls_to_execution_change"),
            Self::LightClientFinalityUpdate => f.write_str("light_client_finality_update"),
            Self::LightClientOptimisticUpdate => f.write_str("light_client_optimistic_update"),
            Self::BlobSidecar(subnet) => write!(f, "blob_sidecar_{subnet}"),
            Self::DataColumnSidecar(subnet) => write!(f, "data_column_sidecar_{subnet}"),
            Self::ExecutionPayload => f.write_str("execution_payload"),
            Self::PayloadAttestationMessage => f.write_str("payload_attestation_message"),
            Self::ExecutionPayloadBid => f.write_str("execution_payload_bid"),
            Self::ProposerPreferences => f.write_str("proposer_preferences"),
        }
    }
}

impl FromStr for GossipKind {
    type Err = TopicError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        // Fixed names first.
        let fixed = match name {
            "beacon_block" => Some(Self::BeaconBlock),
            "beacon_aggregate_and_proof" => Some(Self::BeaconAggregateAndProof),
            "voluntary_exit" => Some(Self::VoluntaryExit),
            "proposer_slashing" => Some(Self::ProposerSlashing),
            "attester_slashing" => Some(Self::AttesterSlashing),
            "sync_committee_contribution_and_proof" => {
                Some(Self::SyncCommitteeContributionAndProof)
            }
            "bls_to_execution_change" => Some(Self::BlsToExecutionChange),
            "light_client_finality_update" => Some(Self::LightClientFinalityUpdate),
            "light_client_optimistic_update" => Some(Self::LightClientOptimisticUpdate),
            "execution_payload" => Some(Self::ExecutionPayload),
            "payload_attestation_message" => Some(Self::PayloadAttestationMessage),
            "execution_payload_bid" => Some(Self::ExecutionPayloadBid),
            "proposer_preferences" => Some(Self::ProposerPreferences),
            _ => None,
        };
        if let Some(kind) = fixed {
            return Ok(kind);
        }
        // Then the subnet families: a prefix and a decimal subnet number.
        let subnet = |prefix: &str| -> Option<u64> {
            let digits = name.strip_prefix(prefix)?;
            // Reject "+1" and leading zeros, which u64 parsing would accept or normalize.
            if digits.is_empty()
                || !digits.bytes().all(|b| b.is_ascii_digit())
                || (digits.len() > 1 && digits.starts_with('0'))
            {
                return None;
            }
            digits.parse().ok()
        };
        let families: [(&str, SubnetKind); 4] = [
            ("beacon_attestation_", Self::BeaconAttestation),
            ("sync_committee_", Self::SyncCommittee),
            ("blob_sidecar_", Self::BlobSidecar),
            ("data_column_sidecar_", Self::DataColumnSidecar),
        ];
        families
            .into_iter()
            .find_map(|(prefix, make)| subnet(prefix).map(make))
            .ok_or(TopicError::UnknownName)
    }
}

/// Builds a subnet topic kind from its subnet number.
type SubnetKind = fn(u64) -> GossipKind;

/// A full consensus topic: fork digest, kind, and encoding.
///
/// ```text
/// /eth2/<fork digest as 8 lowercase hex digits>/<name>/ssz_snappy
///
/// example: /eth2/446a7232/beacon_aggregate_and_proof/ssz_snappy
/// ```
///
/// See `specs/phase0/p2p-interface.md`, topics and messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GossipTopic {
    /// The fork the messages belong to.
    pub fork_digest: ForkDigest,
    /// What the topic carries.
    pub kind: GossipKind,
}

impl GossipTopic {
    /// The topic as the gossipsub router names it.
    #[must_use]
    pub fn topic(&self) -> Topic {
        Topic::new(self.to_string())
    }
}

impl fmt::Display for GossipTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{PREFIX}/")?;
        for byte in self.fork_digest.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "/{}/{ENCODING}", self.kind)
    }
}

impl FromStr for GossipTopic {
    type Err = TopicError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // Exactly five slash-separated parts, the first empty.
        let parts: Vec<&str> = text.split('/').collect();
        let ["", PREFIX, digest, name, ENCODING] = parts.as_slice() else {
            return Err(TopicError::Malformed);
        };
        // Eight lowercase hex digits, no "0x" prefix.
        if digest.len() != 8
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(TopicError::Malformed);
        }
        let mut bytes = [0u8; 4];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digest[2 * index..2 * index + 2], 16)
                .map_err(|_| TopicError::Malformed)?;
        }
        Ok(Self {
            fork_digest: ForkDigest(bytes),
            kind: name.parse()?,
        })
    }
}

/// Text that is not a known consensus topic.
///
/// The caller holds the topic text, so the error does not copy it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TopicError {
    /// The topic does not have the five-part shape or a valid digest.
    #[error("malformed consensus topic")]
    Malformed,
    /// The name is not one the specs define.
    #[error("unknown consensus topic name")]
    UnknownName,
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn spec_example() {
        // The example from the phase0 encodings section.
        let text = "/eth2/446a7232/beacon_aggregate_and_proof/ssz_snappy";
        let topic: GossipTopic = text.parse().unwrap();
        assert_eq!(
            topic,
            GossipTopic {
                fork_digest: ForkDigest([0x44, 0x6a, 0x72, 0x32]),
                kind: GossipKind::BeaconAggregateAndProof
            }
        );
        assert_eq!(topic.to_string(), text);
    }

    #[test]
    fn subnet_topics() {
        let digest = ForkDigest([0xab, 0xcd, 0xef, 0x01]);
        let column = GossipTopic {
            fork_digest: digest,
            kind: GossipKind::DataColumnSidecar(127),
        };
        assert_eq!(
            column.to_string(),
            "/eth2/abcdef01/data_column_sidecar_127/ssz_snappy"
        );
        assert_eq!(
            "/eth2/abcdef01/beacon_attestation_63/ssz_snappy"
                .parse::<GossipTopic>()
                .unwrap()
                .kind,
            GossipKind::BeaconAttestation(63)
        );
    }

    #[test]
    fn gloas_topics_round_trip() {
        let digest = ForkDigest([0x01, 0x02, 0x03, 0x04]);
        for (kind, name) in [
            (GossipKind::ExecutionPayload, "execution_payload"),
            (
                GossipKind::PayloadAttestationMessage,
                "payload_attestation_message",
            ),
            (GossipKind::ExecutionPayloadBid, "execution_payload_bid"),
            (GossipKind::ProposerPreferences, "proposer_preferences"),
        ] {
            let text = format!("/eth2/01020304/{name}/ssz_snappy");
            let topic = GossipTopic {
                fork_digest: digest,
                kind,
            };
            assert_eq!(topic.to_string(), text);
            assert_eq!(text.parse::<GossipTopic>(), Ok(topic));
        }
    }

    #[test]
    fn rejects_malformed() {
        // Uppercase hex, a wrong encoding, a leading-zero subnet, an unknown name.
        assert_eq!(
            "/eth2/ABCDEF01/beacon_block/ssz_snappy".parse::<GossipTopic>(),
            Err(TopicError::Malformed)
        );
        assert_eq!(
            "/eth2/abcdef01/beacon_block/ssz".parse::<GossipTopic>(),
            Err(TopicError::Malformed)
        );
        assert_eq!(
            "/eth2/abcdef01/beacon_attestation_01/ssz_snappy".parse::<GossipTopic>(),
            Err(TopicError::UnknownName)
        );
        assert_eq!(
            "/eth2/abcdef01/beacon_blob/ssz_snappy".parse::<GossipTopic>(),
            Err(TopicError::UnknownName)
        );
    }

    proptest! {
        #[test]
        fn round_trip(digest: [u8; 4], subnet in 0u64..200, which in 0usize..4) {
            let kind = [GossipKind::BeaconAttestation(subnet), GossipKind::SyncCommittee(subnet), GossipKind::BlobSidecar(subnet), GossipKind::DataColumnSidecar(subnet)][which];
            let topic = GossipTopic { fork_digest: ForkDigest(digest), kind };
            prop_assert_eq!(topic.to_string().parse::<GossipTopic>(), Ok(topic));
        }

        #[test]
        fn garbage_never_panics(text in "\\PC{0,64}") {
            let _ = text.parse::<GossipTopic>();
        }
    }
}
