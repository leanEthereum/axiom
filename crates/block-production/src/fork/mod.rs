//! How each fork assembles its block from the parts every fork shares.

mod altair;
mod bellatrix;
mod capella;
mod deneb;
mod electra;
mod fulu;
mod gloas;
mod phase0;

use axiom_operation_pool::PoolFork;
use axiom_state_transition::State;
use axiom_types::{
    Root,
    accessors::{ExecutionHeaderState, ForkState},
    capella::Withdrawal,
};

use crate::{BodyParts, Built, ExecutionChoice, ParentPayload, ProductionError, Trial};

/// The block assembly rules of one fork, implemented on that fork's state.
///
/// # Overview
///
/// The producer gathers the parts every fork shares, then dispatches once on the fork.
/// The fork's implementation puts the parts in its own containers.
/// It decides what its block may carry on the execution side, and settles the state root.
pub trait BlockFork: PoolFork {
    /// Whether the deposit contract's deposits are all bridged, which ends the eth1 vote.
    ///
    /// See `get_eth1_vote` in the Electra validator spec.
    fn bridge_closed(_state: &Self) -> bool {
        false
    }

    /// The withdrawals a payload of the state's slot must carry, none before Capella.
    ///
    /// A Gloas payload's withdrawals depend on whether it builds on its parent's payload.
    /// See `prepare_execution_payload` in the Capella, Electra, and Gloas validator specs.
    ///
    /// # Errors
    ///
    /// Fails when the state is of another fork, or a withdrawal cannot be computed.
    fn withdrawals_due(
        _trial: &Trial<'_, Self::Preset>,
        _parent: &ParentPayload,
    ) -> Result<Vec<Withdrawal>, ProductionError> {
        Ok(Vec::new())
    }

    /// The state the operations are packed on, when it differs from the slot's state.
    ///
    /// A fork whose block applies something before its operations returns that state.
    ///
    /// # Errors
    ///
    /// Fails when the execution input does not fit the fork.
    fn packing_state(
        _trial: &Trial<'_, Self::Preset>,
        _execution: &ExecutionChoice<Self::Preset>,
    ) -> Result<Option<State<Self::Preset>>, ProductionError> {
        Ok(None)
    }

    /// Assembles the block, settles its state root, and returns it with the post-state.
    ///
    /// # Errors
    ///
    /// Fails when the execution input does not fit the fork, or the block is invalid.
    fn build(
        trial: &Trial<'_, Self::Preset>,
        parts: &BodyParts<Self>,
        execution: ExecutionChoice<Self::Preset>,
    ) -> Result<Built<Self::Preset>, ProductionError>;
}

/// A builder's header, revealed into the post-state a stand-in payload produced.
///
/// The trial runs a stand-in payload with the header's fields but no transactions.
/// The state records two things that differ from the true block's:
///
/// - the payload's header, which payload processing stores;
/// - the body's root, which the block header stores.
///
/// A blinded body has the root of the full body, since a header has its payload's root.
/// See `process_execution_payload` and `process_block_header` in the Bellatrix spec.
#[derive(Clone, Debug)]
struct BuilderHeader<S: ExecutionHeaderState>(S::ExecutionPayloadHeader);

impl<S: ExecutionHeaderState + ForkState> BuilderHeader<S> {
    /// Writes the header and the true body root into the post-state, and returns its new root.
    fn commit(self, post: &mut State<S::Preset>, body_root: Root) -> Root {
        if let Some(state) = S::from_any_mut(post.beacon_mut()) {
            *state.latest_execution_payload_header_mut() = self.0;
            state.latest_block_header_mut().body_root = body_root;
        }
        post.hash_tree_root()
    }
}
