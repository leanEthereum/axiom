//! Block processing: applying one block's contents to the state at its slot.

mod eth1_data;
mod execution_payload;
mod header;
mod operations;
mod randao;
mod sync_aggregate;
mod withdrawals;

use axiom_bls::PublicKey;
use axiom_ssz::Ssz;
use axiom_types::{
    BeaconBlock, BeaconBlockBody, BlsSignature, ChainConfig, Domain, Gwei, Preset, Root,
    SignedBeaconBlock, SigningData, ValidatorIndex, constants::DOMAIN_BEACON_PROPOSER,
};
pub use withdrawals::ExpectedWithdrawals;

use crate::{BlockError, ExecutionEngine, SignatureBatch, State, Verification};

/// A block operation: one kind of message a block carries.
///
/// Every operation checks its own validity, then mutates the state.
/// See `process_operations` in the Fulu beacon chain spec.
pub trait Operation<P: Preset> {
    /// Checks the operation against the state, then applies it.
    ///
    /// # Errors
    ///
    /// Fails when the operation is invalid, which invalidates the whole block.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError>;
}

/// Applies a block to a state, collecting signatures for one batch check at the end.
///
/// # Overview
///
/// The steps run in the spec's order, each its own method.
///
/// ```text
/// header -> withdrawals -> execution payload -> randao -> eth1 data -> operations -> sync aggregate
/// ```
///
/// A step that fails leaves the state half-updated.
/// The caller discards that state, since an invalid block has no post-state.
#[derive(Debug)]
pub struct BlockProcessor<'a, P: Preset> {
    /// The state being transitioned.
    state: &'a mut State<P>,
    /// The chain configuration.
    config: &'a ChainConfig,
    /// Signatures checked together at the end.
    signatures: SignatureBatch,
    /// Total active balance, fixed for the whole block.
    ///
    /// Activity changes only at epoch boundaries, and effective balances only in epoch processing.
    total_active_balance: Gwei,
}

impl<'a, P: Preset> BlockProcessor<'a, P> {
    /// A processor for a state already advanced to the block's slot.
    pub fn new(
        state: &'a mut State<P>,
        config: &'a ChainConfig,
        verification: Verification,
    ) -> Self {
        let total_active_balance = state.beacon().total_active_balance();
        Self {
            state,
            config,
            signatures: SignatureBatch::new(verification),
            total_active_balance,
        }
    }

    /// Runs every step of block processing.
    ///
    /// See `process_block` in the Fulu beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails at the first broken rule.
    pub fn process_block(
        &mut self,
        block: &BeaconBlock<P>,
        engine: &impl ExecutionEngine<P>,
    ) -> Result<(), BlockError> {
        self.process_block_header(block)?;
        self.process_withdrawals(&block.body.execution_payload)?;
        self.process_execution_payload(&block.body, engine)?;
        self.process_randao(&block.body)?;
        self.process_eth1_data(&block.body)?;
        self.process_operations(&block.body)?;
        self.process_sync_aggregate(&block.body.sync_aggregate)
    }

    /// Applies every operation of a body, in the spec's order.
    ///
    /// # Errors
    ///
    /// Fails at the first invalid operation.
    pub fn process_operations(&mut self, body: &BeaconBlockBody<P>) -> Result<(), BlockError> {
        // Fulu retired deposits from the deposit contract; they arrive as requests instead.
        if !body.deposits.is_empty() {
            return Err(BlockError::DepositsNotAllowed);
        }
        self.apply_all(&body.proposer_slashings)?;
        self.apply_all(&body.attester_slashings)?;
        self.apply_all(&body.attestations)?;
        self.apply_all(&body.voluntary_exits)?;
        self.apply_all(&body.bls_to_execution_changes)?;
        self.apply_all(&body.execution_requests.deposits)?;
        self.apply_all(&body.execution_requests.withdrawals)?;
        self.apply_all(&body.execution_requests.consolidations)
    }

    /// Applies one operation.
    ///
    /// # Errors
    ///
    /// Fails when the operation is invalid.
    pub fn apply<O: Operation<P>>(&mut self, operation: &O) -> Result<(), BlockError> {
        operation.apply(self)
    }

    /// Checks every collected signature, which completes the block.
    ///
    /// # Errors
    ///
    /// Fails when any signature does not verify.
    pub fn finish(self) -> Result<(), BlockError> {
        self.signatures.verify()
    }

    /// Queues the check of the proposer's signature over the block.
    ///
    /// See `verify_block_signature` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the proposer does not exist or the signature is malformed.
    pub fn verify_block_signature(
        &mut self,
        signed_block: &SignedBeaconBlock<P>,
    ) -> Result<(), BlockError> {
        let block = &signed_block.message;
        let domain = self
            .state
            .beacon
            .domain(DOMAIN_BEACON_PROPOSER, self.state.beacon.current_epoch());
        self.verify_signature(block.proposer_index, block, domain, &signed_block.signature)
    }

    /// Applies a list of operations in order.
    fn apply_all<O: Operation<P>>(&mut self, operations: &[O]) -> Result<(), BlockError> {
        operations
            .iter()
            .try_for_each(|operation| operation.apply(self))
    }

    /// Queues a check that a validator signed an object in a domain.
    fn verify_signature<T: Ssz>(
        &mut self,
        signer: ValidatorIndex,
        object: &T,
        domain: Domain,
        signature: &BlsSignature,
    ) -> Result<(), BlockError> {
        if !self.signatures.is_enabled() {
            return Ok(());
        }
        let key = self.state.public_key(signer)?;
        self.signatures
            .push(key, SigningData::signing_root(object, domain), signature)
    }

    /// Queues a check of a signature over a precomputed root.
    fn verify_root(
        &mut self,
        key: PublicKey,
        root: Root,
        signature: &BlsSignature,
    ) -> Result<(), BlockError> {
        self.signatures.push(key, root, signature)
    }
}
