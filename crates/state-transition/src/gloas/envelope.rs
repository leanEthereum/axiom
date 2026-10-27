//! Execution payload envelopes: the payload a builder reveals after its bid was included.

use axiom_bls::PublicKey;
use axiom_ssz::Ssz;
use axiom_types::{
    BlsSignature, BuilderIndex, Bytes32, ChainConfig, Domain, ForkName, Hash32, KzgCommitment,
    Preset, Root, Slot,
    accessors::{BuilderState, CoreState},
    constants::{BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_BUILDER},
    gloas::{
        BeaconState, ExecutionPayload, NewPayloadRequest, SignedExecutionPayloadEnvelope,
        VersionedHashes,
    },
    phase0::SigningData,
};
use thiserror::Error;

use crate::{
    BlockError, CachedState, ExecutionEngine, Fork, SignatureBatch, StateError, Verification,
};

/// An envelope that does not deliver the payload its block's bid committed to.
///
/// Each variant names the assertion of the spec that failed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The state is of a fork without envelopes.
    #[error("a {0} state takes no execution payload envelope")]
    WrongFork(ForkName),
    /// The envelope names another block than the state's latest.
    #[error("envelope names block {claimed}, the latest block is {expected}")]
    BlockRootMismatch {
        /// The block root the envelope names.
        claimed: Root,
        /// Root of the latest block, with the state's root filled in.
        expected: Root,
    },
    /// The envelope names another parent than the latest block's.
    #[error("envelope names parent {claimed}, the latest block's parent is {expected}")]
    ParentRootMismatch {
        /// The parent root the envelope names.
        claimed: Root,
        /// Parent root of the latest block.
        expected: Root,
    },
    /// The envelope comes from another builder than the bid's.
    #[error("envelope is from builder {claimed}, the bid is from {committed}")]
    BuilderMismatch {
        /// The builder the envelope names.
        claimed: BuilderIndex,
        /// The builder of the bid.
        committed: BuilderIndex,
    },
    /// The payload's randomness is not the bid's.
    #[error("payload randomness {claimed} is not the bid's {committed}")]
    RandaoMismatch {
        /// The randomness of the payload.
        claimed: Bytes32,
        /// The randomness of the bid.
        committed: Bytes32,
    },
    /// The payload's gas limit is not the bid's.
    #[error("payload gas limit {claimed} is not the bid's {committed}")]
    GasLimitMismatch {
        /// The gas limit of the payload.
        claimed: u64,
        /// The gas limit of the bid.
        committed: u64,
    },
    /// The payload's block hash is not the bid's.
    #[error("payload block hash {claimed} is not the bid's {committed}")]
    BlockHashMismatch {
        /// The block hash of the payload.
        claimed: Hash32,
        /// The block hash of the bid.
        committed: Hash32,
    },
    /// The envelope's execution requests are not those the bid committed to.
    #[error("execution requests have root {actual}, the bid committed to {committed}")]
    RequestsRootMismatch {
        /// Root of the envelope's requests.
        actual: Root,
        /// Root the bid committed to.
        committed: Root,
    },
    /// The payload names another slot than the state's.
    #[error("payload slot number {claimed} is not state slot {state}")]
    SlotMismatch {
        /// The slot number the payload carries.
        claimed: u64,
        /// The state's slot.
        state: Slot,
    },
    /// The payload does not build on the latest execution block.
    #[error("payload parent {claimed} is not the latest block hash {expected}")]
    ParentHashMismatch {
        /// The parent hash the payload names.
        claimed: Hash32,
        /// The latest execution block hash of the state.
        expected: Hash32,
    },
    /// The payload's timestamp does not match the slot.
    #[error("payload timestamp {claimed} is not the slot time {expected}")]
    TimestampMismatch {
        /// The timestamp the payload carries, in seconds.
        claimed: u64,
        /// Start of the slot, in seconds since the Unix epoch.
        expected: u64,
    },
    /// The payload's withdrawals are not those its block fixed.
    #[error("payload withdrawals have root {actual}, the block fixed {expected}")]
    WithdrawalsMismatch {
        /// Root of the payload's withdrawals.
        actual: Root,
        /// Root of the withdrawals the state expects.
        expected: Root,
    },
    /// The bid committed to more blobs than a payload request can carry.
    #[error("{count} blob commitments exceed the request limit of {limit}")]
    TooManyBlobs {
        /// Commitments in the bid.
        count: usize,
        /// Versioned hashes a request holds.
        limit: u64,
    },
    /// The signer's key does not decompress.
    #[error("key of builder {0} does not decompress")]
    MalformedBuilderKey(BuilderIndex),
    /// The envelope's signature is malformed or does not verify.
    #[error("envelope signature: {0}")]
    Signature(#[source] BlockError),
    /// The execution engine rejected the payload.
    #[error("the execution engine rejected payload {0}")]
    PayloadInvalid(Hash32),
    /// A state invariant broke while checking.
    #[error("state invariant broke: {0}")]
    State(#[from] StateError),
}

/// A signed envelope of a fork that reveals payloads apart from their blocks.
///
/// Forks from Gloas on share the envelope rule and differ only in the requests the payload carries.
/// Each fork's envelope exposes the fields the rule reads, and builds its own engine request.
pub trait RevealedPayload {
    /// The state of the envelope's fork, which the envelope is checked against.
    type State: Fork + BuilderState;

    /// What the execution engine validates for the envelope's payload.
    type Request;

    /// The fields the envelope rule reads, every one of a type the forks share.
    fn parts(&self) -> EnvelopeParts<'_, <Self::State as CoreState>::Preset>;

    /// The root the builder signs: the unsigned envelope's, under a domain.
    fn signing_root(&self, domain: Domain) -> Root;

    /// The engine's request for the payload, with the hashes of the bid's blob commitments.
    fn new_payload_request(
        &self,
        versioned_hashes: VersionedHashes<<Self::State as CoreState>::Preset>,
    ) -> Self::Request;
}

/// The fields of a signed envelope that the envelope rule reads.
#[derive(Clone, Copy, Debug)]
pub struct EnvelopeParts<'a, P: Preset> {
    /// The revealed payload.
    pub payload: &'a ExecutionPayload<P>,

    /// Root of the payload's execution requests, which the bid committed to.
    pub requests_root: Root,

    /// The builder revealing the payload.
    pub builder_index: BuilderIndex,

    /// Block whose bid the payload honours.
    pub beacon_block_root: Root,

    /// Parent of that block, see EIP-4788.
    pub parent_beacon_block_root: Root,

    /// The builder's signature.
    pub signature: &'a BlsSignature,
}

impl<P: Preset> RevealedPayload for SignedExecutionPayloadEnvelope<P> {
    type State = BeaconState<P>;
    type Request = NewPayloadRequest<P>;

    fn parts(&self) -> EnvelopeParts<'_, P> {
        let envelope = &self.message;
        EnvelopeParts {
            payload: &envelope.payload,
            requests_root: envelope.execution_requests.hash_tree_root(),
            builder_index: envelope.builder_index,
            beacon_block_root: envelope.beacon_block_root,
            parent_beacon_block_root: envelope.parent_beacon_block_root,
            signature: &self.signature,
        }
    }

    fn signing_root(&self, domain: Domain) -> Root {
        SigningData::signing_root(&self.message, domain)
    }

    fn new_payload_request(&self, versioned_hashes: VersionedHashes<P>) -> NewPayloadRequest<P> {
        let envelope = &self.message;
        NewPayloadRequest {
            execution_payload: envelope.payload.clone(),
            versioned_hashes,
            parent_beacon_block_root: envelope.parent_beacon_block_root,
            execution_requests: envelope.execution_requests.clone(),
        }
    }
}

/// A signed execution payload envelope, checked against the state after its block.
///
/// # Overview
///
/// Gloas splits a slot into two inputs to the state transition.
/// The block arrives first and commits to a payload by its bid.
/// The envelope arrives later, carrying the payload itself.
///
/// The envelope changes no state.
/// It is valid when it delivers exactly what the bid promised, and the engine accepts it.
/// Its effects reach the state through the next block, which reports its execution requests.
///
/// See EIP-7732 and `verify_execution_payload_envelope` in the Gloas fork choice spec.
#[derive(Clone, Copy, Debug)]
pub struct PayloadEnvelope<'a, V>(pub &'a V);

impl<V: RevealedPayload> PayloadEnvelope<'_, V> {
    /// Checks the envelope against the state its block produced.
    ///
    /// # Algorithm
    ///
    /// 1. The builder of the bid, or the proposer for a self-built payload, signed it.
    /// 2. It names the latest block and that block's parent.
    /// 3. Its builder, randomness, gas limit, block hash, and requests match the bid.
    /// 4. Its payload is for this slot, extends the latest execution block, and has the slot's time.
    /// 5. Its withdrawals are those the block fixed.
    /// 6. The execution engine accepts it.
    ///
    /// # Errors
    ///
    /// Fails at the first broken rule.
    pub fn verify<E: ExecutionEngine<V::Request>>(
        &self,
        state: &mut CachedState<'_, V::State>,
        config: &ChainConfig,
        verification: Verification,
        engine: &E,
    ) -> Result<(), EnvelopeError> {
        let parts = self.0.parts();

        self.check_signature(state, &parts, verification)?;
        let beacon = state.beacon();
        Self::check_block(beacon, &parts)?;
        Self::check_bid(beacon, &parts)?;
        Self::check_payload(beacon, &parts, config)?;

        // Phase 6: the engine's verdict.
        let commitments = &beacon.latest_execution_payload_bid().blob_kzg_commitments;
        let versioned_hashes = commitments
            .iter()
            .map(KzgCommitment::versioned_hash)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| EnvelopeError::TooManyBlobs {
                count: commitments.len(),
                limit: <<V::State as CoreState>::Preset as Preset>::MAX_BLOB_COMMITMENTS_PER_BLOCK,
            })?;
        let request = self.0.new_payload_request(versioned_hashes);
        if !engine.verify_and_notify_new_payload(&request) {
            return Err(EnvelopeError::PayloadInvalid(parts.payload.block_hash));
        }
        Ok(())
    }

    /// Checks that the bid's builder, or the proposer when self-built, signed the envelope.
    fn check_signature(
        &self,
        state: &mut CachedState<'_, V::State>,
        parts: &EnvelopeParts<'_, <V::State as CoreState>::Preset>,
        verification: Verification,
    ) -> Result<(), EnvelopeError> {
        let mut signatures = SignatureBatch::new(verification);
        if signatures.is_enabled() {
            let key = Self::signer_key(state, parts.builder_index)?;
            let beacon = state.beacon();
            let domain = beacon.domain(DOMAIN_BEACON_BUILDER, beacon.current_epoch());
            let root = self.0.signing_root(domain);
            signatures
                .push(key, root, parts.signature)
                .map_err(EnvelopeError::Signature)?;
            signatures.verify().map_err(EnvelopeError::Signature)?;
        }

        Ok(())
    }

    /// Checks that the envelope names the latest block and its parent.
    fn check_block(
        beacon: &V::State,
        parts: &EnvelopeParts<'_, <V::State as CoreState>::Preset>,
    ) -> Result<(), EnvelopeError> {
        let mut header = beacon.latest_block_header().clone();
        header.state_root = beacon.state_root();
        let block_root = header.hash_tree_root();
        if parts.beacon_block_root != block_root {
            return Err(EnvelopeError::BlockRootMismatch {
                claimed: parts.beacon_block_root,
                expected: block_root,
            });
        }
        if parts.parent_beacon_block_root != header.parent_root {
            return Err(EnvelopeError::ParentRootMismatch {
                claimed: parts.parent_beacon_block_root,
                expected: header.parent_root,
            });
        }

        Ok(())
    }

    /// Checks the envelope against the bid: builder, randomness, gas limit, hash, and requests.
    fn check_bid(
        beacon: &V::State,
        parts: &EnvelopeParts<'_, <V::State as CoreState>::Preset>,
    ) -> Result<(), EnvelopeError> {
        let payload = parts.payload;
        let bid = beacon.latest_execution_payload_bid();
        if parts.builder_index != bid.builder_index {
            return Err(EnvelopeError::BuilderMismatch {
                claimed: parts.builder_index,
                committed: bid.builder_index,
            });
        }
        if payload.prev_randao != bid.prev_randao {
            return Err(EnvelopeError::RandaoMismatch {
                claimed: payload.prev_randao,
                committed: bid.prev_randao,
            });
        }
        if payload.gas_limit != bid.gas_limit {
            return Err(EnvelopeError::GasLimitMismatch {
                claimed: payload.gas_limit,
                committed: bid.gas_limit,
            });
        }
        if payload.block_hash != bid.block_hash {
            return Err(EnvelopeError::BlockHashMismatch {
                claimed: payload.block_hash,
                committed: bid.block_hash,
            });
        }
        if parts.requests_root != bid.execution_requests_root {
            return Err(EnvelopeError::RequestsRootMismatch {
                actual: parts.requests_root,
                committed: bid.execution_requests_root,
            });
        }

        Ok(())
    }

    /// Checks the payload's slot, parent, time, and withdrawals against the state.
    fn check_payload(
        beacon: &V::State,
        parts: &EnvelopeParts<'_, <V::State as CoreState>::Preset>,
        config: &ChainConfig,
    ) -> Result<(), EnvelopeError> {
        let payload = parts.payload;
        let slot = beacon.slot();
        if payload.slot_number != slot.0 {
            return Err(EnvelopeError::SlotMismatch {
                claimed: payload.slot_number,
                state: slot,
            });
        }
        let latest_block_hash = beacon.latest_block_hash();
        if payload.parent_hash != latest_block_hash {
            return Err(EnvelopeError::ParentHashMismatch {
                claimed: payload.parent_hash,
                expected: latest_block_hash,
            });
        }
        // Timing: genesis time plus the slot's whole milliseconds, truncated to seconds.
        let slot_ms = slot
            .0
            .checked_mul(config.slot_duration_ms)
            .ok_or(StateError::Overflow {
                quantity: "slot time in milliseconds",
            })?;
        let expected_timestamp = beacon.genesis_time() + slot_ms / 1000;
        if payload.timestamp != expected_timestamp {
            return Err(EnvelopeError::TimestampMismatch {
                claimed: payload.timestamp,
                expected: expected_timestamp,
            });
        }

        // Phase 5: the withdrawals its block fixed.
        let withdrawals_root = payload.withdrawals.hash_tree_root();
        let expected_withdrawals = beacon.payload_expected_withdrawals().hash_tree_root();
        if withdrawals_root != expected_withdrawals {
            return Err(EnvelopeError::WithdrawalsMismatch {
                actual: withdrawals_root,
                expected: expected_withdrawals,
            });
        }

        Ok(())
    }

    /// The key of the envelope's signer: the bid's builder, or the proposer when self-built.
    ///
    /// See `verify_execution_payload_envelope_signature` in the Gloas beacon chain spec.
    fn signer_key(
        state: &mut CachedState<'_, V::State>,
        index: BuilderIndex,
    ) -> Result<PublicKey, EnvelopeError> {
        if index == BUILDER_INDEX_SELF_BUILD {
            let proposer = state.beacon().latest_block_header().proposer_index;
            return Ok(state.public_key(proposer)?);
        }
        let builders = state.beacon().builders();
        let builder = builders
            .get(index.as_usize())
            .ok_or(StateError::UnknownBuilder {
                index,
                registry_size: builders.len(),
            })?;
        PublicKey::from_bytes(&builder.pubkey.0)
            .map_err(|_| EnvelopeError::MalformedBuilderKey(index))
    }
}
