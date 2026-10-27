//! Where each fork's state and block body keep what light client data proves.

use axiom_ssz::{GeneralizedIndex, Ssz};
use axiom_types::{Bytes32, ChainConfig, ForkName, Preset, Slot};

use crate::branch::Branch;

/// Generalized index of the execution payload in a Capella through Fulu block body.
///
/// See `EXECUTION_PAYLOAD_GINDEX` in the Capella light client sync protocol.
pub(crate) const EXECUTION_PAYLOAD_GINDEX: GeneralizedIndex = GeneralizedIndex::new(25);

/// The generalized indices a light client proves, for blocks and states of one fork.
///
/// # Overview
///
/// A light client header or update describes a block, and the block's fork fixes the tree shapes.
/// The spec picks each index by comparing the block's epoch with fork epochs.
/// Here the block's fork is found once, and this table answers every question about it.
///
/// See the `*_gindex_at_slot` helpers of the Altair, Electra, and Gloas light client sync protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The finalized checkpoint root in the state.
    pub finalized_root: GeneralizedIndex,
    /// The current sync committee in the state.
    pub current_sync_committee: GeneralizedIndex,
    /// The next sync committee in the state.
    pub next_sync_committee: GeneralizedIndex,
    /// How the block body commits to its execution.
    pub execution: Execution,
}

impl Layout {
    /// The layout of a fork's states and bodies.
    ///
    /// Phase0 has no sync committees, so it shares Altair's row; no light client data proves into it.
    /// Electra pushed the state past 32 fields, and Gloas made it progressive, see EIP-7688.
    /// Hstar appends fields to Gloas's progressive state and body, which moves no existing index.
    #[must_use]
    pub const fn of(fork: ForkName) -> Self {
        let (finalized_root, current_sync_committee, next_sync_committee) = match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb => (105, 54, 55),
            ForkName::Electra | ForkName::Fulu => (169, 86, 87),
            ForkName::Gloas | ForkName::Hstar => (735, 2945, 2946),
        };
        let execution = match fork {
            ForkName::Phase0 | ForkName::Altair | ForkName::Bellatrix => Execution::Absent,
            ForkName::Capella => Execution::Capella,
            ForkName::Deneb | ForkName::Electra | ForkName::Fulu => Execution::Deneb,
            ForkName::Gloas | ForkName::Hstar => Execution::Bid,
        };
        Self {
            finalized_root: GeneralizedIndex::new(finalized_root),
            current_sync_committee: GeneralizedIndex::new(current_sync_committee),
            next_sync_committee: GeneralizedIndex::new(next_sync_committee),
            execution,
        }
    }

    /// The layout of the fork in force at a slot.
    #[must_use]
    pub fn at<P: Preset>(config: &ChainConfig, slot: Slot) -> Self {
        Self::of(config.fork_at(slot.epoch::<P>()))
    }
}

/// How a block body commits to execution, as light client headers prove it.
///
/// A closed set: each variant is one shape of execution data the spec's helpers branch on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Execution {
    /// No execution data in light client headers, phase0 through Bellatrix.
    ///
    /// Bellatrix bodies hold a payload, but light client data leaves it out.
    /// See `block_to_light_client_header` in the Capella light client full node spec.
    Absent,
    /// The body holds a Capella execution payload.
    Capella,
    /// The body holds a Deneb execution payload, Deneb through Fulu.
    Deneb,
    /// The body holds a signed execution payload bid, see EIP-7732.
    Bid,
}

impl Execution {
    /// The execution payload in the block body, when the body holds one.
    #[must_use]
    pub const fn payload_gindex(self) -> Option<GeneralizedIndex> {
        match self {
            Self::Absent | Self::Bid => None,
            Self::Capella | Self::Deneb => Some(EXECUTION_PAYLOAD_GINDEX),
        }
    }

    /// The branch from a body's execution payload to the body root, empty when it holds none.
    pub(crate) fn payload_proof<B: Ssz>(self, body: &B) -> Vec<Bytes32> {
        self.payload_gindex()
            .and_then(|gindex| body.prove(gindex))
            .map(|(_, proof)| Branch::nodes_of(&proof))
            .unwrap_or_default()
    }

    /// The block hash inside the execution payload header, when the body holds a payload.
    ///
    /// Capella headers have 15 fields and Deneb headers 17, so the trees differ in depth.
    #[must_use]
    pub const fn payload_block_hash_gindex(self) -> Option<GeneralizedIndex> {
        match self {
            Self::Absent | Self::Bid => None,
            Self::Capella => Some(GeneralizedIndex::new(28)),
            Self::Deneb => Some(GeneralizedIndex::new(44)),
        }
    }

    /// The execution block hash a Gloas header carries, in the block body.
    ///
    /// Before Gloas it is the payload's own block hash; from Gloas, the bid's parent block hash.
    /// See the `EXECUTION_BLOCK_HASH_GINDEX` constants of the Gloas light client sync protocol.
    #[must_use]
    pub const fn block_hash_gindex(self) -> Option<GeneralizedIndex> {
        match self {
            Self::Absent => None,
            Self::Capella => Some(GeneralizedIndex::new(412)),
            Self::Deneb => Some(GeneralizedIndex::new(812)),
            Self::Bid => Some(GeneralizedIndex::new(2856)),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::Ssz;
    use axiom_types::{BlsPubkey, Minimal, hstar};

    use super::*;

    #[test]
    fn body_indices_nest_the_block_hash_inside_the_payload() {
        // The payload sits at 25 in the body; the block hash at 28 or 44 in the payload header.
        // Nesting multiplies by the inner tree's width: 25 * 16 + 12 = 412, 25 * 32 + 12 = 812.
        for execution in [Execution::Capella, Execution::Deneb] {
            let outer = execution.payload_gindex().unwrap();
            let inner = execution.payload_block_hash_gindex().unwrap();
            assert_eq!(
                Some(outer.concat(inner)),
                execution.block_hash_gindex(),
                "{execution:?}"
            );
        }
    }

    #[test]
    fn state_indices_move_at_electra_and_gloas() {
        // Altair through Deneb share the 32-leaf state; the finalized root sits at 105.
        assert_eq!(Layout::of(ForkName::Deneb).finalized_root.get(), 105);
        // Electra doubles the width, so 105 becomes 169 one level deeper.
        assert_eq!(Layout::of(ForkName::Fulu).finalized_root.get(), 169);
        // Gloas makes the state progressive, which moves every index again.
        assert_eq!(Layout::of(ForkName::Gloas).next_sync_committee.get(), 2946);
        // Bellatrix bodies hold a payload, yet light client headers ignore it.
        assert_eq!(Layout::of(ForkName::Bellatrix).execution, Execution::Absent);
    }

    #[test]
    fn hstar_proves_at_gloas_indices() {
        // Invariant: a progressive container places each field by its position alone.
        // Hstar appends two state fields, so Gloas's sync committee index still holds.
        //
        // Fixture state: an Hstar state whose next sync committee has aggregate key 0x07.
        let mut state = hstar::BeaconState::<Minimal>::default();
        state.next_sync_committee.aggregate_pubkey = BlsPubkey([7; 48]);
        let layout = Layout::of(ForkName::Hstar);

        // The node at Gloas's index is that committee's root.
        let (node, _) = state.prove(layout.next_sync_committee).unwrap();
        assert_eq!(node, state.next_sync_committee.hash_tree_root());
    }
}
