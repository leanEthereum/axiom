//! Gossip validation vectors: a chain, then messages each expected to pass, be ignored, or be rejected.

use std::{collections::HashMap, marker::PhantomData};

use axiom_fork_choice::{BlockNode, ExecutionStatus, Store};
use axiom_gossip::{ChainView, GossipError, GossipFork, GossipValidator, Seen, SeenPartialHeader};
use axiom_ssz::{Root, Ssz};
use axiom_state_transition::{Fork, KnownVerdict, State, Verification};
use axiom_types::{
    Epoch, Preset, SubnetId,
    accessors::ForkState,
    fulu::{Checkpoint, PartialDataColumnHeader, ProposerSlashing, SignedVoluntaryExit},
    gloas::{ExecutionPayloadBid, ExecutionPayloadEnvelope, SignedExecutionPayloadEnvelope},
};
use axiom_yaml::Yaml;

use crate::{Case, Failure, forks::SpecFork};

/// The verdict of one gossip rule set on one message.
pub type Verdict = Result<(), GossipError>;

/// The signed block of a fork, as its gossip rules name it.
type SignedBlockOf<F, P> = <<F as SpecFork>::State<P> as GossipFork>::SignedBeaconBlock;

/// The topic each message file prefix belongs to.
///
/// A case may mix topics, such as preferences and envelopes before the bid they enable.
/// See the message file table of the gossip validation test format.
const TOPICS: &[(&str, &str)] = &[
    ("block", "beacon_block"),
    ("aggregate", "beacon_aggregate_and_proof"),
    ("attestation", "beacon_attestation"),
    ("single_attestation", "beacon_attestation"),
    ("proposer_slashing", "proposer_slashing"),
    ("attester_slashing", "attester_slashing"),
    ("voluntary_exit", "voluntary_exit"),
    ("contribution", "sync_committee_contribution_and_proof"),
    ("sync_committee_message", "sync_committee"),
    ("bls_to_execution_change", "bls_to_execution_change"),
    ("blob_sidecar", "blob_sidecar"),
    ("data_column_sidecar", "data_column_sidecar"),
    ("partial_data_column_sidecar", "partial_data_column_sidecar"),
    ("execution_payload_envelope", "execution_payload"),
    ("execution_payload_bid", "execution_payload_bid"),
    ("proposer_preferences", "proposer_preferences"),
    ("payload_attestation_message", "payload_attestation_message"),
];

/// One message of a gossip case, with what the vector says about how it arrived.
#[derive(Clone, Copy, Debug)]
pub struct GossipMessage<'a> {
    /// The case directory.
    case: &'a Case,
    /// The message's entry in the case metadata.
    entry: &'a Yaml,
}

impl GossipMessage<'_> {
    /// Decodes the message file.
    ///
    /// # Errors
    ///
    /// Fails when the entry names no file, or the file does not decode.
    pub fn decode<T: Ssz>(&self) -> Result<T, Failure> {
        self.decode_field("message")
    }

    /// Decodes the file another field of the entry names, such as a partial column's group.
    ///
    /// # Errors
    ///
    /// Fails when the entry lacks the field, or the file does not decode.
    pub fn decode_field<T: Ssz>(&self, key: &str) -> Result<T, Failure> {
        self.case.ssz(self.file(key)?)
    }

    /// When the message arrived, in milliseconds since the Unix epoch.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.number("current_time_ms")
    }

    /// The subnet the message arrived on.
    #[must_use]
    pub fn subnet(&self) -> SubnetId {
        SubnetId(self.number("subnet_id"))
    }

    /// A number of the entry, zero when absent.
    #[must_use]
    pub fn number(&self, key: &str) -> u64 {
        self.entry
            .get(key)
            .and_then(Yaml::as_u64)
            .unwrap_or_default()
    }

    /// The topic the message travels on, read from its file's prefix.
    fn topic(&self) -> Result<&'static str, Failure> {
        let file = self.file("message")?;
        let prefix = file.split("_0x").next().unwrap_or_default();
        TOPICS
            .iter()
            .find(|(known, _)| *known == prefix)
            .map(|(_, topic)| *topic)
            .ok_or_else(|| Failure(format!("message {file} has an unknown prefix")))
    }

    /// The file a field of the entry names.
    fn file(&self, key: &str) -> Result<&str, Failure> {
        self.entry
            .get(key)
            .and_then(Yaml::as_str)
            .ok_or_else(|| Failure(format!("message without a {key}")))
    }
}

/// The chain a gossip case builds before its messages arrive.
#[derive(Debug)]
struct Chain<P: Preset> {
    /// The fork choice store, holding the imported blocks and their states.
    store: Store<P>,
    /// Blocks seen but not imported, because they failed or are still queued.
    unimported: HashMap<Root, BlockNode>,
    /// Payload validity of blocks, as the vector sets it.
    payload_statuses: HashMap<Root, ExecutionStatus>,
    /// The bid each block carries, from Gloas on.
    bids: HashMap<Root, ExecutionPayloadBid>,
    /// The payload envelopes that arrived and verified, by block root, from Gloas on.
    payloads: HashMap<Root, ExecutionPayloadEnvelope<P>>,
}

/// Builds the chain a gossip case describes, then checks each message's verdict.
#[derive(Debug)]
pub(super) struct GossipCase<'c, P: Preset, F: SpecFork> {
    /// The case directory.
    case: &'c Case,
    /// The case metadata.
    meta: Yaml,
    /// The preset and the fork.
    marker: PhantomData<(P, F)>,
}

impl<'c, P: Preset, F: SpecFork> GossipCase<'c, P, F> {
    /// A case ready to run.
    ///
    /// # Errors
    ///
    /// Fails when the metadata does not parse.
    pub(super) fn new(case: &'c Case) -> Result<Self, Failure> {
        Ok(Self {
            case,
            meta: case.yaml("meta.yaml")?,
            marker: PhantomData,
        })
    }

    /// Runs every message of the case.
    ///
    /// # Errors
    ///
    /// Fails when a verdict differs from the expected one.
    pub(super) fn run(&self) -> Result<(), Failure> {
        // Phase 1: replay the chain, keeping failed and pending blocks out of the store.
        let mut chain = self.replay()?;
        let mut view = ChainView::new(&mut chain.store, &chain.unimported, &chain.payload_statuses);
        view.bids = chain.bids;
        view.payloads = chain.payloads;
        if let Some(finalized) = self.meta.get("finalized_checkpoint") {
            view.finalized = self.finalized(finalized)?;
        }

        // Phase 2: validate each message in order, updating the seen state on success.
        let mut seen = self.preloaded_seen()?;
        let messages = self
            .meta
            .get("messages")
            .and_then(Yaml::as_sequence)
            .unwrap_or_default();
        for (number, entry) in messages.iter().enumerate() {
            let mut validator = GossipValidator::new(&mut view, &mut seen);
            let message = GossipMessage {
                case: self.case,
                entry,
            };
            let verdict = Self::validate(&mut validator, &message)?;
            Self::compare(number, entry, verdict)?;
        }
        Ok(())
    }

    /// Imports the case's blocks into a store anchored at the first.
    fn replay(&self) -> Result<Chain<P>, Failure> {
        let config = self.case.config::<P>(F::FORK)?;
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
        let anchor = self.case.ssz::<SignedBlockOf<F, P>>(anchor_name)?;
        let (anchor_block, _) = F::State::<P>::split_block(&anchor);
        let anchor_header = F::State::<P>::block_header(anchor_block);
        let anchor_state = State::new(self.case.ssz::<F::State<P>>("state")?.into_any());
        let store = Store::anchored(
            config.clone(),
            anchor_state,
            &anchor_header,
            F::State::<P>::execution_block_hash(anchor_block),
        )
        .map_err(|error| Failure(format!("anchor rejected: {error}")))?;
        let mut chain = Chain {
            store,
            unimported: HashMap::new(),
            payload_statuses: HashMap::new(),
            bids: HashMap::new(),
            payloads: HashMap::new(),
        };

        for entry in blocks {
            let name = entry
                .get("block")
                .and_then(Yaml::as_str)
                .ok_or_else(|| Failure::new("block entry without a name"))?;
            let signed = self.case.ssz::<SignedBlockOf<F, P>>(name)?;
            let (block, _) = F::State::<P>::split_block(&signed);
            let header = F::State::<P>::block_header(block);
            let root = header.hash_tree_root();
            if let Some(status) = entry.get("payload_status").and_then(Yaml::as_str) {
                chain
                    .payload_statuses
                    .insert(root, Self::execution_status(status)?);
            }
            if let Some(bid) = F::State::<P>::payload_bid(block) {
                chain.bids.insert(root, bid.clone());
            }
            // Only Gloas blocks have their payload arrive apart, in an envelope.
            if let Some(envelope) = entry.get("payload").and_then(Yaml::as_str) {
                let signed = self
                    .case
                    .ssz::<SignedExecutionPayloadEnvelope<P>>(envelope)?;
                chain.payloads.insert(root, signed.message);
            }
            if chain.store.blocks().contains(&root) {
                continue;
            }
            let node = BlockNode {
                slot: header.slot,
                parent_root: header.parent_root,
                proposer_index: header.proposer_index,
                execution_block_hash: F::State::<P>::execution_block_hash(block),
                status: ExecutionStatus::Optimistic,
            };
            let flag = |key: &str| entry.get(key).and_then(Yaml::as_bool).unwrap_or(false);
            if flag("failed") || flag("pending") {
                chain.unimported.insert(root, node);
                continue;
            }
            let mut state = chain
                .store
                .block_state(&header.parent_root)
                .cloned()
                .ok_or_else(|| Failure(format!("parent of {name} is unknown")))?;
            state
                .state_transition(&config, &signed, Verification::Skip, &KnownVerdict(true))
                .map_err(|error| Failure(format!("{name} failed to import: {error}")))?;
            let imported = BlockNode {
                status: ExecutionStatus::Valid,
                ..node
            };
            chain.store.insert_validated_node(root, imported, state);
        }
        Ok(chain)
    }

    /// The seen state the case starts from: empty, or with partial column headers it names.
    fn preloaded_seen(&self) -> Result<Seen, Failure> {
        let mut seen = Seen::default();
        let preloaded = self
            .meta
            .get("seen_partial_data_column_headers")
            .and_then(Yaml::as_sequence)
            .unwrap_or_default();
        for entry in preloaded {
            let root = entry
                .get("block_root")
                .and_then(Yaml::as_hex_array::<32>)
                .map(Root)
                .ok_or_else(|| Failure::new("preloaded header without a block root"))?;
            let name = entry
                .get("header")
                .and_then(Yaml::as_str)
                .ok_or_else(|| Failure::new("preloaded header without a file"))?;
            // Only Fulu defines the header; Gloas reads the commitments from the bid.
            let header = self.case.ssz::<PartialDataColumnHeader<P>>(name)?;
            seen.partial_data_column_headers
                .insert(root, SeenPartialHeader::of(&header));
        }
        Ok(seen)
    }

    /// Validates one message under its topic's rules.
    ///
    /// Topics every fork shares run here on the fork's types.
    /// The fork's own topics run through its marker.
    fn validate(
        validator: &mut GossipValidator<'_, '_, P>,
        message: &GossipMessage<'_>,
    ) -> Result<Verdict, Failure> {
        let now = message.now_ms();
        Ok(match message.topic()? {
            "beacon_block" => validator.beacon_block::<F::State<P>>(&message.decode()?, now),
            "beacon_aggregate_and_proof" => {
                validator.aggregate_and_proof::<F::State<P>>(&message.decode()?, now)
            }
            "beacon_attestation" => validator.beacon_attestation::<F::State<P>>(
                &message.decode()?,
                now,
                message.subnet(),
            ),
            "voluntary_exit" => validator
                .voluntary_exit::<F::State<P>>(&message.decode::<SignedVoluntaryExit>()?, now),
            "proposer_slashing" => {
                validator.proposer_slashing(&message.decode::<ProposerSlashing>()?)
            }
            "attester_slashing" => validator.attester_slashing(
                &message.decode::<<F::State<P> as GossipFork>::AttesterSlashing>()?,
            ),
            other => return F::gossip(other, message, validator),
        })
    }

    /// Compares a verdict with the one the vector expects.
    fn compare(number: usize, entry: &Yaml, verdict: Verdict) -> Result<(), Failure> {
        let actual = match verdict {
            Ok(()) => "valid",
            Err(GossipError::Ignore { .. }) => "ignore",
            Err(GossipError::Reject { .. }) => "reject",
        };
        let expected = entry
            .get("expected")
            .and_then(Yaml::as_str)
            .unwrap_or_default();
        if actual == expected {
            return Ok(());
        }
        let reason = entry
            .get("reason")
            .and_then(Yaml::as_str)
            .unwrap_or_default();
        Err(Failure(format!(
            "message {number}: expected {expected} ({reason}), got {}",
            verdict.map_or_else(|error| error.to_string(), |()| "valid".to_owned())
        )))
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
            let signed = self.case.ssz::<SignedBlockOf<F, P>>(name)?;
            F::State::<P>::block_header(F::State::<P>::split_block(&signed).0).hash_tree_root()
        };
        Ok(Checkpoint { epoch, root })
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
