//! Running a built block against its pre-state, to learn the post-state and its root.

use axiom_state_transition::{KnownVerdict, State, TransitionError, Verification};
use axiom_types::{BlsSignature, ChainConfig, Preset, Root, combined};

use crate::ProductionError;

/// The pre-state of a block at its slot, and the rules to apply the block with.
///
/// # Overview
///
/// A block commits to its post-state's root, which depends on the whole block.
/// So the block is applied once with a zero root; the mismatch reports the true one.
/// The block is then rebuilt with that root, which changes nothing the state saw.
///
/// Signatures are not checked: the proposer has not signed yet, and the pools checked the rest.
/// The engine's verdict is taken as valid: the engine built the payload itself.
#[derive(Clone, Copy, Debug)]
pub struct Trial<'a, P: Preset> {
    /// The state at the block's slot.
    state: &'a State<P>,
    /// The chain configuration.
    config: &'a ChainConfig,
}

impl<'a, P: Preset> Trial<'a, P> {
    /// A trial on a state already advanced to the block's slot.
    #[must_use]
    pub const fn new(state: &'a State<P>, config: &'a ChainConfig) -> Self {
        Self { state, config }
    }

    /// The state at the block's slot.
    #[must_use]
    pub const fn state(&self) -> &'a State<P> {
        self.state
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &'a ChainConfig {
        self.config
    }

    /// Applies a block built by a function of its state root, and rebuilds it with the true root.
    ///
    /// # Returns
    ///
    /// The block with its true state root, and the post-state.
    ///
    /// # Errors
    ///
    /// Fails when the block is invalid on the pre-state.
    pub fn settle<B>(
        &self,
        build: impl Fn(Root) -> Result<B, ProductionError>,
        combine: impl Fn(&B) -> combined::BeaconBlock<P>,
    ) -> Result<(B, State<P>), ProductionError> {
        let draft = build(Root::ZERO)?;
        let (root, post) = self.apply(&combine(&draft))?;
        Ok((build(root)?, post))
    }

    /// Applies a block whose state root is zero, returning the true root and the post-state.
    ///
    /// # Errors
    ///
    /// Fails when the block is invalid on the pre-state.
    pub fn apply(
        &self,
        block: &combined::BeaconBlock<P>,
    ) -> Result<(Root, State<P>), ProductionError> {
        let slot = block.slot();
        let mut post = self.state.clone();
        let signed =
            combined::SignedBeaconBlock::from_parts(block.clone(), BlsSignature::default());
        // Why: the transition checks the claimed root last, and reports the one it computed.
        let outcome = post.state_transition(
            self.config,
            &signed,
            Verification::Skip,
            &KnownVerdict(true),
        );
        match outcome {
            Err(TransitionError::StateRootMismatch { computed, .. }) => Ok((computed, post)),
            Ok(()) => Ok((Root::ZERO, post)),
            Err(source) => Err(ProductionError::Invalid { slot, source }),
        }
    }
}
