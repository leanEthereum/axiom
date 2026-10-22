//! Execution payload envelopes: the payload a builder reveals after its bid was included.

use axiom_bls::PublicKey;
use axiom_ssz::Ssz;
use axiom_types::{
    BuilderIndex, Bytes32, ChainConfig, ForkName, Hash32, KzgCommitment, Preset, Root, Slot,
    accessors::{BuilderState, CoreState},
    constants::{BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_BUILDER},
    gloas::{BeaconState, NewPayloadRequest, SignedExecutionPayloadEnvelope},
    phase0::SigningData,
};
use thiserror::Error;

use crate::{BlockError, CachedState, ExecutionEngine, SignatureBatch, StateError, Verification};

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
pub struct PayloadEnvelope<'a, P: Preset>(pub &'a SignedExecutionPayloadEnvelope<P>);

impl<P: Preset> PayloadEnvelope<'_, P> {
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
    pub fn verify<E: ExecutionEngine<NewPayloadRequest<P>>>(
        self,
        state: &mut CachedState<'_, BeaconState<P>>,
        config: &ChainConfig,
        verification: Verification,
        engine: &E,
    ) -> Result<(), EnvelopeError> {
        let envelope = &self.0.message;
        let payload = &envelope.payload;

        self.check_signature(state, verification)?;
        let beacon = state.beacon();
        self.check_block(beacon)?;
        self.check_bid(beacon)?;
        self.check_payload(beacon, config)?;

        // Phase 6: the engine's verdict.
        let commitments = &beacon.latest_execution_payload_bid.blob_kzg_commitments;
        let versioned_hashes = commitments
            .iter()
            .map(KzgCommitment::versioned_hash)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| EnvelopeError::TooManyBlobs {
                count: commitments.len(),
                limit: P::MAX_BLOB_COMMITMENTS_PER_BLOCK,
            })?;
        let request = NewPayloadRequest {
            execution_payload: payload.clone(),
            versioned_hashes,
            parent_beacon_block_root: envelope.parent_beacon_block_root,
            execution_requests: envelope.execution_requests.clone(),
        };
        if !engine.verify_and_notify_new_payload(&request) {
            return Err(EnvelopeError::PayloadInvalid(payload.block_hash));
        }
        Ok(())
    }

    /// Checks that the bid's builder, or the proposer when self-built, signed the envelope.
    fn check_signature(
        self,
        state: &mut CachedState<'_, BeaconState<P>>,
        verification: Verification,
    ) -> Result<(), EnvelopeError> {
        let envelope = &self.0.message;
        let mut signatures = SignatureBatch::new(verification);
        if signatures.is_enabled() {
            let key = self.signer_key(state)?;
            let beacon = state.beacon();
            let domain = beacon.domain(DOMAIN_BEACON_BUILDER, beacon.current_epoch());
            let root = SigningData::signing_root(envelope, domain);
            signatures
                .push(key, root, &self.0.signature)
                .map_err(EnvelopeError::Signature)?;
            signatures.verify().map_err(EnvelopeError::Signature)?;
        }

        Ok(())
    }

    /// Checks that the envelope names the latest block and its parent.
    fn check_block(self, beacon: &BeaconState<P>) -> Result<(), EnvelopeError> {
        let envelope = &self.0.message;
        let mut header = beacon.latest_block_header.clone();
        header.state_root = beacon.hash_tree_root();
        let block_root = header.hash_tree_root();
        if envelope.beacon_block_root != block_root {
            return Err(EnvelopeError::BlockRootMismatch {
                claimed: envelope.beacon_block_root,
                expected: block_root,
            });
        }
        if envelope.parent_beacon_block_root != header.parent_root {
            return Err(EnvelopeError::ParentRootMismatch {
                claimed: envelope.parent_beacon_block_root,
                expected: header.parent_root,
            });
        }

        Ok(())
    }

    /// Checks the envelope against the bid: builder, randomness, gas limit, hash, and requests.
    fn check_bid(self, beacon: &BeaconState<P>) -> Result<(), EnvelopeError> {
        let envelope = &self.0.message;
        let payload = &envelope.payload;
        let bid = &beacon.latest_execution_payload_bid;
        if envelope.builder_index != bid.builder_index {
            return Err(EnvelopeError::BuilderMismatch {
                claimed: envelope.builder_index,
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
        let requests_root = envelope.execution_requests.hash_tree_root();
        if requests_root != bid.execution_requests_root {
            return Err(EnvelopeError::RequestsRootMismatch {
                actual: requests_root,
                committed: bid.execution_requests_root,
            });
        }

        Ok(())
    }

    /// Checks the payload's slot, parent, time, and withdrawals against the state.
    fn check_payload(
        self,
        beacon: &BeaconState<P>,
        config: &ChainConfig,
    ) -> Result<(), EnvelopeError> {
        let payload = &self.0.message.payload;
        if payload.slot_number != beacon.slot.0 {
            return Err(EnvelopeError::SlotMismatch {
                claimed: payload.slot_number,
                state: beacon.slot,
            });
        }
        if payload.parent_hash != beacon.latest_block_hash {
            return Err(EnvelopeError::ParentHashMismatch {
                claimed: payload.parent_hash,
                expected: beacon.latest_block_hash,
            });
        }
        // Timing: genesis time plus the slot's whole milliseconds, truncated to seconds.
        let slot_ms =
            beacon
                .slot
                .0
                .checked_mul(config.slot_duration_ms)
                .ok_or(StateError::Overflow {
                    quantity: "slot time in milliseconds",
                })?;
        let expected_timestamp = beacon.genesis_time + slot_ms / 1000;
        if payload.timestamp != expected_timestamp {
            return Err(EnvelopeError::TimestampMismatch {
                claimed: payload.timestamp,
                expected: expected_timestamp,
            });
        }

        // Phase 5: the withdrawals its block fixed.
        let withdrawals_root = payload.withdrawals.hash_tree_root();
        let expected_withdrawals = beacon.payload_expected_withdrawals.hash_tree_root();
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
        self,
        state: &mut CachedState<'_, BeaconState<P>>,
    ) -> Result<PublicKey, EnvelopeError> {
        let index = self.0.message.builder_index;
        if index == BUILDER_INDEX_SELF_BUILD {
            let proposer = state.beacon().latest_block_header.proposer_index;
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
