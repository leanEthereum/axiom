//! The execution payload of a built block: the fields consensus checks, and stand-ins for the rest.

use axiom_ssz::Ssz;
use axiom_types::{
    Bytes32, Gwei, Hash32, Preset, Root, Slot,
    capella::{self, Withdrawal},
    constants::{BUILDER_INDEX_SELF_BUILD, G2_POINT_AT_INFINITY},
    deneb, gloas,
};

use crate::chain_builder::ChainBuilderError;

/// The gas limit every built payload declares.
///
/// The beacon chain never bounds it; only the execution engine judges it.
/// The test engine accepts every payload, so any value passes.
const GAS_LIMIT: u64 = 30_000_000;

/// What the consensus rules check of a payload, fixed by the state at its slot.
///
/// Every other field keeps its default, as the test engine accepts every payload.
/// See `process_execution_payload` in the Capella, Deneb, and Electra specs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PayloadParts {
    /// The slot the payload is built for.
    pub(crate) slot: Slot,
    /// Hash of the execution block it extends.
    pub(crate) parent_hash: Hash32,
    /// The current epoch's randomness, before the block's reveal mixes in.
    pub(crate) prev_randao: Bytes32,
    /// Start of the slot, in seconds since the Unix epoch.
    pub(crate) timestamp: u64,
}

impl PayloadParts {
    /// A stand-in for the execution block hash, unique per slot and never zero.
    ///
    /// The engine computes the true hash; consensus only needs it to differ from its parent.
    /// A SHA-256 digest of the slot is unique per slot and never zero in practice.
    pub(crate) fn block_hash(self) -> Hash32 {
        Hash32(Root::sha256(&self.slot.0.to_le_bytes()).0)
    }

    /// The Capella payload, carrying the withdrawals the state expects.
    pub(crate) fn capella<P: Preset>(
        self,
        withdrawals: Vec<Withdrawal>,
    ) -> Result<capella::ExecutionPayload<P>, ChainBuilderError> {
        Ok(capella::ExecutionPayload {
            parent_hash: self.parent_hash,
            prev_randao: self.prev_randao,
            block_number: self.slot.0,
            gas_limit: GAS_LIMIT,
            timestamp: self.timestamp,
            block_hash: self.block_hash(),
            withdrawals: Self::withdrawals_list::<P>(withdrawals)?,
            ..capella::ExecutionPayload::default()
        })
    }

    /// The Deneb payload, which Electra and Fulu keep: Capella's, with no blob gas used.
    pub(crate) fn deneb<P: Preset>(
        self,
        withdrawals: Vec<Withdrawal>,
    ) -> Result<deneb::ExecutionPayload<P>, ChainBuilderError> {
        Ok(deneb::ExecutionPayload {
            parent_hash: self.parent_hash,
            prev_randao: self.prev_randao,
            block_number: self.slot.0,
            gas_limit: GAS_LIMIT,
            timestamp: self.timestamp,
            block_hash: self.block_hash(),
            withdrawals: Self::withdrawals_list::<P>(withdrawals)?,
            ..deneb::ExecutionPayload::default()
        })
    }

    /// The self-built Gloas bid committing to this payload, with no blobs and no requests.
    ///
    /// A self-built bid is free and unsigned: zero value, the point at infinity as signature.
    /// See `process_execution_payload_bid` in the Gloas beacon chain spec.
    pub(crate) fn self_built_bid(
        self,
        parent_block_root: Root,
    ) -> gloas::SignedExecutionPayloadBid {
        let bid = gloas::ExecutionPayloadBid {
            parent_block_hash: self.parent_hash,
            parent_block_root,
            block_hash: self.block_hash(),
            prev_randao: self.prev_randao,
            gas_limit: GAS_LIMIT,
            builder_index: BUILDER_INDEX_SELF_BUILD,
            slot: self.slot,
            value: Gwei::ZERO,
            execution_payment: Gwei::ZERO,
            execution_requests_root: gloas::ExecutionRequests::default().hash_tree_root(),
            ..gloas::ExecutionPayloadBid::default()
        };
        gloas::SignedExecutionPayloadBid {
            message: bid,
            signature: G2_POINT_AT_INFINITY,
        }
    }

    /// The Gloas envelope message revealing this payload.
    ///
    /// The withdrawals are those the block fixed in the state.
    /// See `verify_execution_payload_envelope` in the Gloas beacon chain spec.
    pub(crate) fn envelope<P: Preset>(
        self,
        withdrawals: gloas::Withdrawals,
        beacon_block_root: Root,
        parent_beacon_block_root: Root,
    ) -> gloas::ExecutionPayloadEnvelope<P> {
        let payload = gloas::ExecutionPayload {
            parent_hash: self.parent_hash,
            prev_randao: self.prev_randao,
            block_number: self.slot.0,
            gas_limit: GAS_LIMIT,
            timestamp: self.timestamp,
            block_hash: self.block_hash(),
            withdrawals,
            slot_number: self.slot.0,
            ..gloas::ExecutionPayload::default()
        };
        gloas::ExecutionPayloadEnvelope {
            payload,
            execution_requests: gloas::ExecutionRequests::default(),
            builder_index: BUILDER_INDEX_SELF_BUILD,
            beacon_block_root,
            parent_beacon_block_root,
        }
    }

    /// The withdrawals as a bounded payload list.
    fn withdrawals_list<P: Preset>(
        withdrawals: Vec<Withdrawal>,
    ) -> Result<capella::Withdrawals<P>, ChainBuilderError> {
        let count = withdrawals.len();
        withdrawals
            .try_into()
            .map_err(|_| ChainBuilderError::TooManyWithdrawals {
                count,
                limit: P::MAX_WITHDRAWALS_PER_PAYLOAD as usize,
            })
    }
}
