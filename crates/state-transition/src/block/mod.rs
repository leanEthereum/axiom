//! Block processing: applying one block's contents to the state at its slot.

use axiom_bls::PublicKey;
use axiom_ssz::Ssz;
use axiom_types::{
    BlsSignature, ChainConfig, Domain, Root, ValidatorIndex,
    accessors::CoreState,
    constants::{DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER},
    phase0::{AttestationData, BeaconBlockHeader, SigningData},
};

use crate::{
    ActiveBalance, BlockError, CachedState, Fork, PayloadEngine, Registry, SignatureBatch,
    StateError, Verification,
};

/// One part of a block that processing checks, then applies to the state.
///
/// # Overview
///
/// A part whose rule no fork rewrote implements this for every state that has its fields.
/// A fork that rewrites the rule of a part it keeps wraps the part in a type of its own.
/// Each fork's block processing then names the version it runs, part by part.
pub trait Operation<S> {
    /// Checks the part against the state, then applies it.
    ///
    /// # Errors
    ///
    /// Fails when the part is invalid, which invalidates the whole block.
    fn apply(&self, processor: &mut BlockProcessor<'_, S>) -> Result<(), BlockError>;
}

/// Applies a block to a state, collecting signatures for one batch check at the end.
///
/// # Overview
///
/// The processor holds what every fork's block processing shares.
/// That is the state, the configuration, the signature batch, and the block's total active balance.
/// Each fork's rules decide which parts apply, in which order.
///
/// A step that fails leaves the state half-updated.
/// The caller discards that state, since an invalid block has no post-state.
#[derive(Debug)]
pub struct BlockProcessor<'a, S: ?Sized> {
    /// The state being transitioned, with its caches.
    pub(crate) state: CachedState<'a, S>,
    /// The chain configuration.
    pub(crate) config: &'a ChainConfig,
    /// Signatures checked together at the end.
    pub(crate) signatures: SignatureBatch,
    /// Total active balance, fixed for the whole block.
    ///
    /// Activity changes only at epoch boundaries, and effective balances only in epoch processing.
    pub(crate) total_active_balance: ActiveBalance,
}

impl<'a, S: CoreState + ?Sized> BlockProcessor<'a, S> {
    /// A processor for a state already advanced to the block's slot.
    ///
    /// The verification setting governs only this processor's signature batch.
    #[must_use]
    pub fn new(
        state: CachedState<'a, S>,
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

    /// The state being transitioned, with its caches.
    pub const fn state(&mut self) -> &mut CachedState<'a, S> {
        &mut self.state
    }

    /// Checks every collected signature, which completes the block.
    ///
    /// # Errors
    ///
    /// Fails when any signature does not verify.
    pub fn finish(self) -> Result<(), BlockError> {
        self.signatures.verify()
    }

    /// Queues the check of the proposer's signature over a block, given by its header.
    ///
    /// The header has the block's root, so the signing root is the same.
    /// See `verify_block_signature` in the phase0 beacon chain spec.
    ///
    /// # Errors
    ///
    /// Fails when the proposer does not exist or the signature is malformed.
    pub fn verify_block_signature(
        &mut self,
        header: &BeaconBlockHeader,
        signature: &BlsSignature,
    ) -> Result<(), BlockError> {
        let state = self.state.beacon();
        let domain = state.domain(DOMAIN_BEACON_PROPOSER, state.current_epoch());
        self.verify_signature(header.proposer_index, header, domain, signature)
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
        indices: &[ValidatorIndex],
        data: &AttestationData,
        signature: &BlsSignature,
    ) -> Result<(), BlockError> {
        if indices.is_empty() {
            return Err(BlockError::EmptyAttestingIndices);
        }
        if let Some(position) = indices.windows(2).position(|pair| pair[0] >= pair[1]) {
            // The pair at a window's position ends one place later.
            return Err(BlockError::UnsortedAttestingIndices {
                position: position + 1,
                index: indices[position + 1],
            });
        }
        // Every index must name a validator, signatures checked or not.
        let registry_size = self.state.beacon().validators().len();
        if let Some(unknown) = indices
            .iter()
            .find(|index| index.as_usize() >= registry_size)
        {
            return Err(StateError::UnknownValidator {
                index: *unknown,
                registry_size,
            }
            .into());
        }

        if !self.signatures.is_enabled() {
            return Ok(());
        }
        let keys = indices
            .iter()
            .map(|index| self.state.public_key(*index))
            .collect::<Result<Vec<_>, _>>()?;
        let key = PublicKey::aggregate(&keys).map_err(BlockError::InvalidAggregateKey)?;
        let domain = self
            .state
            .beacon()
            .domain(DOMAIN_BEACON_ATTESTER, data.target.epoch);
        let root = SigningData::signing_root(data, domain);
        self.verify_root(key, root, signature)
    }

    /// Queues a check that a validator signed an object in a domain.
    ///
    /// # Errors
    ///
    /// Fails when the validator does not exist, or its key or the signature is malformed.
    pub fn verify_signature<T: Ssz>(
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
    ///
    /// # Errors
    ///
    /// Fails when the signature is malformed.
    pub fn verify_root(
        &mut self,
        key: PublicKey,
        root: Root,
        signature: &BlsSignature,
    ) -> Result<(), BlockError> {
        self.signatures.push(key, root, signature)
    }

    /// Whether signatures are checked, so callers can skip building keys they will not use.
    #[must_use]
    pub fn checks_signatures(&self) -> bool {
        self.signatures.is_enabled()
    }
}

impl<S: Fork> BlockProcessor<'_, S> {
    /// Runs every step of the fork's block processing.
    ///
    /// # Errors
    ///
    /// Fails at the first broken rule.
    pub fn process_block<E: PayloadEngine<S::Preset>>(
        &mut self,
        block: &S::Block,
        engine: &E,
    ) -> Result<(), BlockError> {
        let header = S::block_header(block);
        S::process_block(self, block, &header, engine)
    }

    /// Applies one operation.
    ///
    /// # Errors
    ///
    /// Fails when the operation is invalid.
    pub fn apply<O: Operation<S> + ?Sized>(&mut self, operation: &O) -> Result<(), BlockError> {
        operation.apply(self)
    }

    /// Applies a list of operations in order.
    ///
    /// # Errors
    ///
    /// Fails at the first invalid operation.
    pub fn apply_all<O: Operation<S>>(&mut self, operations: &[O]) -> Result<(), BlockError> {
        operations
            .iter()
            .try_for_each(|operation| operation.apply(self))
    }

    /// Proposer of the block's slot, by the rules of the state's fork.
    ///
    /// # Errors
    ///
    /// Fails when the epoch has no active validator.
    pub fn proposer(&self) -> Result<ValidatorIndex, StateError> {
        S::beacon_proposer_index(self.state.beacon())
    }

    /// The state's registry, under the block's total active balance.
    pub const fn registry(&mut self) -> Registry<'_, S> {
        Registry::new(
            self.state.reborrow(),
            self.config,
            self.total_active_balance,
        )
    }
}
