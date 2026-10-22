//! The tiebreak between the payload variants of the previous slot's block.

use axiom_types::{Preset, Root, Slot};

use crate::{ForkChoiceNode, NodePayload, Store};

/// The rules that settle a block's payload before the votes on it can exist.
///
/// Both head walks read them: the one recounting every vote, and the one on the weight tree.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PayloadTiebreak<'a, P: Preset> {
    /// The store.
    store: &'a Store<P>,
}

impl<'a, P: Preset> PayloadTiebreak<'a, P> {
    /// The tiebreak rules of a store.
    pub(crate) const fn new(store: &'a Store<P>) -> Self {
        Self { store }
    }

    /// Whether a node of a block at a slot decides the payload of the previous slot's block.
    ///
    /// Votes that settle that payload by weight cannot have arrived yet.
    /// See `is_previous_slot_payload_decision` in the Gloas fork choice spec.
    pub(crate) fn is_previous_slot_decision(self, payload: NodePayload, block_slot: Slot) -> bool {
        payload != NodePayload::Pending && block_slot + 1 == self.store.current_slot()
    }

    /// The tiebreak between the variants of one block at a slot.
    ///
    /// For the previous slot's block, the full variant wins only if the payload should extend.
    /// Otherwise the empty variant wins, so a missing payload is never built on by default.
    /// See `get_payload_status_tiebreaker` in the Gloas fork choice spec.
    pub(crate) fn tiebreaker(self, node: ForkChoiceNode, block_slot: Slot) -> u8 {
        if !self.is_previous_slot_decision(node.payload, block_slot) {
            return node.payload.code();
        }
        match node.payload {
            NodePayload::Empty => 1,
            NodePayload::Full if self.should_extend_payload(node.root) => 2,
            NodePayload::Full | NodePayload::Pending => 0,
        }
    }

    /// Whether the chain should go on with the payload of the previous slot's block.
    ///
    /// # Overview
    ///
    /// A payload the committee saw on time, with its data, is extended.
    /// Otherwise it is still extended unless the boosted proposal builds on the empty variant.
    ///
    /// This protects an honest builder from a proposer that withholds the boost.
    /// The builder revealed on time, so its payload stays canonical.
    ///
    /// See `should_extend_payload` in the Gloas fork choice spec.
    pub(crate) fn should_extend_payload(self, root: Root) -> bool {
        let store = self.store;
        let Some(block) = store.blocks.get(&root) else {
            return false;
        };
        if !block.is_payload_verified() {
            return false;
        }
        let committee_backs_it = store.ptc.payload_timeliness(&root, block, true)
            && store.ptc.payload_data_availability(&root, block, true);
        let boost_root = store.proposer_boost_root();
        committee_backs_it
            || boost_root == Root::ZERO
            || store.blocks.get(&boost_root).is_none_or(|boosted| {
                boosted.parent_root != root
                    || store.blocks.parent_payload(&boost_root) == Some(NodePayload::Full)
            })
    }
}
