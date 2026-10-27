//! Hstar's light client data, which keeps Gloas's format.
//!
//! Hstar appends fields to Gloas's progressive state and body, so every proof stays where it was.
//! See EIP-8450.

use axiom_ssz::Ssz;
use axiom_types::{Preset, gloas::LightClientHeader, hstar};

use crate::{Execution, Gloas, LightClientBlock, branch::Branch};

impl<P: Preset> LightClientBlock<P> for hstar::BeaconBlock<P> {
    type Fork = Gloas;

    /// The bid's parent block hash, proven into the body as for Gloas.
    ///
    /// See `block_to_light_client_header` in the Gloas light client full node spec.
    fn light_client_header(&self) -> LightClientHeader {
        let nodes = Execution::Bid
            .block_hash_gindex()
            .and_then(|gindex| self.body.prove(gindex))
            .map(|(_, proof)| Branch::nodes_of(&proof))
            .unwrap_or_default();
        LightClientHeader {
            beacon: self.header(),
            execution_block_hash: self
                .body
                .signed_execution_payload_bid
                .message
                .parent_block_hash,
            // Invariant: index 2856 sits eleven levels deep, the branch's fixed length.
            execution_branch: Branch::pad(&nodes).unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Hash32, Minimal};

    use super::*;
    use crate::Header;

    #[test]
    fn an_hstar_header_proves_its_hash_like_a_gloas_one() {
        // Fixture state: an Hstar block whose bid builds on execution block 0x0a...
        let mut block = hstar::BeaconBlock::<Minimal>::default();
        block
            .body
            .signed_execution_payload_bid
            .message
            .parent_block_hash = Hash32([0x0a; 32]);

        let header = block.light_client_header();

        // The branch reaches the body root from the hash, at Gloas's index.
        assert_eq!(header.execution_block_hash, Hash32([0x0a; 32]));
        assert!(Header::<Minimal>::is_valid(&header, Execution::Bid));
        assert_eq!(header.beacon.body_root, block.body.hash_tree_root());
    }
}
