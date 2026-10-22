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
    BeaconBlock, BeaconBlockBody, BlsSignature, ChainConfig, Domain, IndexedAttestation, Preset,
    Root, SignedBeaconBlock, SigningData, ValidatorIndex,
    constants::{DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER},
};
pub use execution_payload::PayloadExecution;
use randao::RandaoReveal;
pub use withdrawals::ExpectedWithdrawals;

use crate::{
    ActiveBalance, BlockError, ExecutionEngine, SignatureBatch, State, StateError, Verification,
    registry::Registry,
};

/// One part of a block that processing checks, then applies to the state.
///
/// The header, the payload's withdrawals, the payload, the randao reveal, the eth1 vote,
/// every kind of operation, and the sync aggregate each implement it.
/// See `process_block` and `process_operations` in the Fulu beacon chain spec.
pub trait Operation<P: Preset> {
    /// Checks the part against the state, then applies it.
    ///
    /// # Errors
    ///
    /// Fails when the part is invalid, which invalidates the whole block.
    fn apply(&self, processor: &mut BlockProcessor<'_, P>) -> Result<(), BlockError>;
}

/// Applies a block to a state, collecting signatures for one batch check at the end.
///
/// # Overview
///
/// The parts apply in the spec's order, each its own operation.
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
    total_active_balance: ActiveBalance,
}

impl<'a, P: Preset> BlockProcessor<'a, P> {
    /// A processor for a state already advanced to the block's slot.
    pub fn new(
        state: &'a mut State<P>,
        config: &'a ChainConfig,
        verification: Verification,
    ) -> Self {
        let total_active_balance = ActiveBalance::of(state.beacon());
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
        let body = &block.body;
        self.apply(&block.header())?;
        self.apply(body.execution_payload.withdrawals.as_slice())?;
        self.apply(&PayloadExecution::new(body, engine))?;
        self.apply(&RandaoReveal(body.randao_reveal))?;
        self.apply(&body.eth1_data)?;
        self.process_operations(body)?;
        self.apply(&body.sync_aggregate)
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
    pub fn apply<O: Operation<P> + ?Sized>(&mut self, operation: &O) -> Result<(), BlockError> {
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

    /// Queues the check of an indexed attestation: sorted unique signers, and their aggregate signature.
    ///
    /// See `is_valid_indexed_attestation` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the indices are empty, unsorted, repeated, or unknown, or the signature is malformed.
    pub fn verify_indexed_attestation(
        &mut self,
        attestation: &IndexedAttestation<P>,
    ) -> Result<(), BlockError> {
        let indices = &attestation.attesting_indices;
        let strictly_increasing = indices.windows(2).all(|pair| pair[0] < pair[1]);
        if indices.is_empty() || !strictly_increasing {
            return Err(BlockError::InvalidAttestingIndices);
        }
        // Every index must name a validator, signatures checked or not.
        let registry_size = self.state.beacon.validators.len() as u64;
        if let Some(unknown) = indices.iter().find(|index| index.0 >= registry_size) {
            return Err(StateError::UnknownValidator(*unknown).into());
        }

        if !self.signatures.is_enabled() {
            return Ok(());
        }
        let keys = indices
            .iter()
            .map(|index| self.state.public_key(*index))
            .collect::<Result<Vec<_>, _>>()?;
        let key = PublicKey::aggregate(&keys).map_err(|_| BlockError::InvalidSignature)?;
        let domain = self
            .state
            .beacon
            .domain(DOMAIN_BEACON_ATTESTER, attestation.data.target.epoch);
        let root = SigningData::signing_root(&attestation.data, domain);
        self.verify_root(key, root, &attestation.signature)
    }

    /// The state's registry, under the block's total active balance.
    const fn registry(&mut self) -> Registry<'_, P> {
        Registry::new(self.state, self.config, self.total_active_balance)
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
