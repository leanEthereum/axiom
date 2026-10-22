//! Proposer reorgs: building on the parent of a late, weak head, and keeping the engine off it.

use axiom_block_production::ProductionError;
use axiom_fork_choice::{ForkChoiceError, ForkChoiceNode};
use axiom_state_transition::State;
use axiom_types::{ChainConfig, Hash32, Preset, Root, Slot, ValidatorIndex};
use tracing::{debug, info};

use crate::{Chain, ChainError, ExecutionHead, Head, ProposerError};

/// Whether the node's proposers orphan a late head that drew few votes.
///
/// # Overview
///
/// A block published after the attestation deadline draws few votes.
/// The next proposer may then build on its parent, and its boost outweighs the late block.
/// That makes late publication a losing strategy, which keeps blocks timely.
///
/// The rule protects liveness against a proposer that withholds its block to gain an edge.
/// It cannot undo a block the honest majority saw in time:
///
/// - the head must hold under 20% of a committee's weight,
/// - its parent must hold over 160%.
///
/// The spec's configuration sets both thresholds and the cutoff.
/// See `get_proposer_head` in the phase0 fork choice spec, and the honest validator guide.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProposerReorgs {
    /// Build on the parent of a late, weak head, as the fork choice allows.
    #[default]
    Enabled,
    /// Always build on the head.
    Disabled,
}

/// A block the engine follows: its consensus root and the execution hashes it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EngineTarget {
    /// Root of the block whose payload is the engine's head.
    pub(crate) root: Root,
    /// The head, safe, and finalized payload hashes.
    pub(crate) execution: ExecutionHead,
}

impl EngineTarget {
    /// The head itself, as the engine follows it without an override.
    pub(crate) const fn of(head: Head) -> Self {
        Self {
            root: head.root,
            execution: head.execution,
        }
    }
}

impl ProposerReorgs {
    /// The node a proposal at a slot extends.
    ///
    /// At the slot itself the late block rule decides.
    /// In the slot before, the engine override rule decides, so a prepared payload matches.
    ///
    /// Whenever the rule cannot be evaluated, the proposal extends the head.
    /// That covers a head at the anchor, whose parent the store never held.
    ///
    /// # Errors
    ///
    /// Fails when the fork choice cannot pick a head.
    pub(crate) fn parent<P: Preset>(
        self,
        chain: &mut Chain<P>,
        slot: Slot,
    ) -> Result<ForkChoiceNode, ChainError> {
        let head = chain.head_node()?;
        if self == Self::Disabled {
            return Ok(head);
        }
        let current = chain.store().current_slot();
        let decided = if current == slot {
            chain.proposer_head(slot)
        } else if current + 1 == slot && chain.head().slot + 1 == slot {
            chain
                .forkchoice_override()
                .map(|parent| parent.unwrap_or(head))
        } else {
            Ok(head)
        };
        let parent = match decided {
            Ok(node) => node,
            // A head that still holds the boost arrived in this slot, on time.
            Err(ChainError::ForkChoice(ForkChoiceError::HeadStillBoosted(_))) => head,
            Err(error) => {
                debug!(%slot, %error, "no reorg decision; building on the head");
                head
            }
        };
        if parent != head {
            info!(%slot, weak_head = %head.root, parent = %parent.root, "proposing on the parent of a late head");
        }
        Ok(parent)
    }

    /// The execution head the engine should follow, while the next proposer may orphan the head.
    ///
    /// Gloas payloads come apart from their blocks, so the engine head needs no override there.
    ///
    /// # Returns
    ///
    /// The next slot's proposer and the parent's execution head, when the override applies.
    /// The caller points the engine there only if that proposer is one of its own.
    ///
    /// # Errors
    ///
    /// Fails when the fork choice lacks the head, its parent, or a state.
    pub(crate) fn engine_override<P: Preset>(
        self,
        chain: &mut Chain<P>,
    ) -> Result<Option<(ValidatorIndex, EngineTarget)>, ProposerError> {
        let head = chain.head();
        let proposal_slot = head.slot + 1;
        let config = chain.config().clone();
        if self == Self::Disabled
            || config
                .fork_at(proposal_slot.epoch::<P>())
                .separates_payloads()
        {
            return Ok(None);
        }
        let Some(parent) = chain.forkchoice_override()? else {
            return Ok(None);
        };
        let parent_state = chain
            .store()
            .block_state(&parent.root)
            .ok_or(ChainError::MissingState(parent.root))?;
        let proposer = Self::proposer_at(parent_state, &config, proposal_slot)?;
        let target = EngineTarget {
            root: parent.root,
            execution: ExecutionHead {
                head: parent_state
                    .beacon()
                    .latest_execution_block_hash()
                    .unwrap_or(Hash32::ZERO),
                ..head.execution
            },
        };
        debug!(head = %head.root, parent = %parent.root, %proposer, "engine update may follow the parent");
        Ok(Some((proposer, target)))
    }

    /// The proposer of a slot, as a state before it elects them.
    ///
    /// The parent's shuffling is the head's here: the override needs a stable shuffling.
    fn proposer_at<P: Preset>(
        state: &State<P>,
        config: &ChainConfig,
        slot: Slot,
    ) -> Result<ValidatorIndex, ProductionError> {
        let mut advanced = state.clone();
        advanced
            .process_slots(config, slot)
            .map_err(|source| ProductionError::Slots { slot, source })?;
        advanced
            .beacon_proposer_index()
            .map_err(|source| ProductionError::Proposer { slot, source })
    }
}
