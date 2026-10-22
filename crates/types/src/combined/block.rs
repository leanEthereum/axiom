//! A beacon block of any fork.

use axiom_ssz::{DecodeError, Root, Ssz};

use crate::{
    ChainConfig, ForkName, Hash32, KzgCommitment, Preset, Slot, ValidatorIndex, altair, bellatrix,
    capella, deneb, electra, fulu, gloas, phase0,
    vote::{CommitteeVote, ConflictingVotes},
};

/// The execution blocks a beacon block links: the one it builds on and the one it commits to.
///
/// Before Gloas both come from the block's payload, and both are zero before the merge.
/// From Gloas on they come from the builder's bid.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecutionHashes {
    /// The execution block the beacon block builds on.
    pub parent_block_hash: Hash32,
    /// The execution block the beacon block commits to.
    pub block_hash: Hash32,
}

/// A beacon block of whichever fork it belongs to.
///
/// Fulu kept Electra's block, so those two variants hold the same type.
/// Code that runs a fork's rules matches once and works on the concrete block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeaconBlock<P: Preset> {
    /// A phase0 block.
    Phase0(phase0::BeaconBlock<P>),
    /// An Altair block.
    Altair(altair::BeaconBlock<P>),
    /// A Bellatrix block.
    Bellatrix(bellatrix::BeaconBlock<P>),
    /// A Capella block.
    Capella(capella::BeaconBlock<P>),
    /// A Deneb block.
    Deneb(deneb::BeaconBlock<P>),
    /// An Electra block.
    Electra(electra::BeaconBlock<P>),
    /// A Fulu block, the same type as an Electra block.
    Fulu(fulu::BeaconBlock<P>),
    /// A Gloas block.
    Gloas(gloas::BeaconBlock<P>),
}

impl<P: Preset> BeaconBlock<P> {
    /// The fork the block belongs to.
    #[must_use]
    pub const fn fork_name(&self) -> ForkName {
        match self {
            Self::Phase0(_) => ForkName::Phase0,
            Self::Altair(_) => ForkName::Altair,
            Self::Bellatrix(_) => ForkName::Bellatrix,
            Self::Capella(_) => ForkName::Capella,
            Self::Deneb(_) => ForkName::Deneb,
            Self::Electra(_) => ForkName::Electra,
            Self::Fulu(_) => ForkName::Fulu,
            Self::Gloas(_) => ForkName::Gloas,
        }
    }

    /// Slot the block is proposed in.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        match self {
            Self::Phase0(block) => block.slot,
            Self::Altair(block) => block.slot,
            Self::Bellatrix(block) => block.slot,
            Self::Capella(block) => block.slot,
            Self::Deneb(block) => block.slot,
            Self::Electra(block) | Self::Fulu(block) => block.slot,
            Self::Gloas(block) => block.slot,
        }
    }

    /// The proposer.
    #[must_use]
    pub const fn proposer_index(&self) -> ValidatorIndex {
        match self {
            Self::Phase0(block) => block.proposer_index,
            Self::Altair(block) => block.proposer_index,
            Self::Bellatrix(block) => block.proposer_index,
            Self::Capella(block) => block.proposer_index,
            Self::Deneb(block) => block.proposer_index,
            Self::Electra(block) | Self::Fulu(block) => block.proposer_index,
            Self::Gloas(block) => block.proposer_index,
        }
    }

    /// Root of the parent block.
    #[must_use]
    pub const fn parent_root(&self) -> Root {
        match self {
            Self::Phase0(block) => block.parent_root,
            Self::Altair(block) => block.parent_root,
            Self::Bellatrix(block) => block.parent_root,
            Self::Capella(block) => block.parent_root,
            Self::Deneb(block) => block.parent_root,
            Self::Electra(block) | Self::Fulu(block) => block.parent_root,
            Self::Gloas(block) => block.parent_root,
        }
    }

    /// Root of the post-state.
    #[must_use]
    pub const fn state_root(&self) -> Root {
        match self {
            Self::Phase0(block) => block.state_root,
            Self::Altair(block) => block.state_root,
            Self::Bellatrix(block) => block.state_root,
            Self::Capella(block) => block.state_root,
            Self::Deneb(block) => block.state_root,
            Self::Electra(block) | Self::Fulu(block) => block.state_root,
            Self::Gloas(block) => block.state_root,
        }
    }

    /// Merkle commitment to the block, its block root.
    #[must_use]
    pub fn hash_tree_root(&self) -> Root {
        match self {
            Self::Phase0(block) => block.hash_tree_root(),
            Self::Altair(block) => block.hash_tree_root(),
            Self::Bellatrix(block) => block.hash_tree_root(),
            Self::Capella(block) => block.hash_tree_root(),
            Self::Deneb(block) => block.hash_tree_root(),
            Self::Electra(block) | Self::Fulu(block) => block.hash_tree_root(),
            Self::Gloas(block) => block.hash_tree_root(),
        }
    }

    /// The execution blocks the block links.
    #[must_use]
    pub const fn execution_hashes(&self) -> ExecutionHashes {
        let (parent_block_hash, block_hash) = match self {
            Self::Phase0(_) | Self::Altair(_) => (Hash32::ZERO, Hash32::ZERO),
            Self::Bellatrix(block) => {
                let payload = &block.body.execution_payload;
                (payload.parent_hash, payload.block_hash)
            }
            Self::Capella(block) => {
                let payload = &block.body.execution_payload;
                (payload.parent_hash, payload.block_hash)
            }
            Self::Deneb(block) => {
                let payload = &block.body.execution_payload;
                (payload.parent_hash, payload.block_hash)
            }
            Self::Electra(block) | Self::Fulu(block) => {
                let payload = &block.body.execution_payload;
                (payload.parent_hash, payload.block_hash)
            }
            Self::Gloas(block) => {
                let bid = &block.body.signed_execution_payload_bid.message;
                (bid.parent_block_hash, bid.block_hash)
            }
        };
        ExecutionHashes {
            parent_block_hash,
            block_hash,
        }
    }

    /// Whether the block carries a payload other than the empty one.
    ///
    /// A Bellatrix block before the merge carries the empty payload.
    /// See `is_merge_transition_block` in the Bellatrix beacon chain spec.
    #[must_use]
    pub fn carries_execution_payload(&self) -> bool {
        match self {
            Self::Phase0(_) | Self::Altair(_) | Self::Gloas(_) => false,
            Self::Bellatrix(block) => block.body.execution_payload != Default::default(),
            Self::Capella(block) => block.body.execution_payload != Default::default(),
            Self::Deneb(block) => block.body.execution_payload != Default::default(),
            Self::Electra(block) | Self::Fulu(block) => {
                block.body.execution_payload != Default::default()
            }
        }
    }

    /// Commitments to the blobs the block's payload carries, from Deneb until Gloas.
    ///
    /// From Gloas on the commitments sit in the bid, and the envelope's data is sampled.
    #[must_use]
    pub fn blob_kzg_commitments(&self) -> &[KzgCommitment] {
        match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Gloas(_) => &[],
            Self::Deneb(block) => &block.body.blob_kzg_commitments,
            Self::Electra(block) | Self::Fulu(block) => &block.body.blob_kzg_commitments,
        }
    }

    /// The votes the block carries, reduced to the fields every fork shares.
    #[must_use]
    pub fn committee_votes(&self) -> Vec<CommitteeVote> {
        match self {
            Self::Phase0(block) => block.body.attestations.iter().map(phase0::Attestation::committee_vote).collect(),
            Self::Altair(block) => block.body.attestations.iter().map(phase0::Attestation::committee_vote).collect(),
            Self::Bellatrix(block) => block.body.attestations.iter().map(phase0::Attestation::committee_vote).collect(),
            Self::Capella(block) => block.body.attestations.iter().map(phase0::Attestation::committee_vote).collect(),
            Self::Deneb(block) => block.body.attestations.iter().map(phase0::Attestation::committee_vote).collect(),
            Self::Electra(block) | Self::Fulu(block) => block.body.attestations.iter().map(electra::Attestation::committee_vote).collect(),
            Self::Gloas(block) => block.body.attestations.iter().map(gloas::Attestation::committee_vote).collect(),
        }
    }

    /// The attester slashings the block carries, reduced to the fields every fork shares.
    #[must_use]
    pub fn conflicting_votes(&self) -> Vec<ConflictingVotes> {
        match self {
            Self::Phase0(block) => block.body.attester_slashings.iter().map(phase0::AttesterSlashing::conflicting_votes).collect(),
            Self::Altair(block) => block.body.attester_slashings.iter().map(phase0::AttesterSlashing::conflicting_votes).collect(),
            Self::Bellatrix(block) => block.body.attester_slashings.iter().map(phase0::AttesterSlashing::conflicting_votes).collect(),
            Self::Capella(block) => block.body.attester_slashings.iter().map(phase0::AttesterSlashing::conflicting_votes).collect(),
            Self::Deneb(block) => block.body.attester_slashings.iter().map(phase0::AttesterSlashing::conflicting_votes).collect(),
            Self::Electra(block) | Self::Fulu(block) => block.body.attester_slashings.iter().map(electra::AttesterSlashing::conflicting_votes).collect(),
            Self::Gloas(block) => block.body.attester_slashings.iter().map(gloas::AttesterSlashing::conflicting_votes).collect(),
        }
    }

    /// The block's SSZ encoding, which does not record the fork.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Phase0(block) => block.encode(),
            Self::Altair(block) => block.encode(),
            Self::Bellatrix(block) => block.encode(),
            Self::Capella(block) => block.encode(),
            Self::Deneb(block) => block.encode(),
            Self::Electra(block) | Self::Fulu(block) => block.encode(),
            Self::Gloas(block) => block.encode(),
        }
    }

    /// Decodes a block of a known fork.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not the encoding of a block of that fork.
    pub fn decode(bytes: &[u8], fork: ForkName) -> Result<Self, DecodeError> {
        Ok(match fork {
            ForkName::Phase0 => Self::Phase0(Ssz::decode(bytes)?),
            ForkName::Altair => Self::Altair(Ssz::decode(bytes)?),
            ForkName::Bellatrix => Self::Bellatrix(Ssz::decode(bytes)?),
            ForkName::Capella => Self::Capella(Ssz::decode(bytes)?),
            ForkName::Deneb => Self::Deneb(Ssz::decode(bytes)?),
            ForkName::Electra => Self::Electra(Ssz::decode(bytes)?),
            ForkName::Fulu => Self::Fulu(Ssz::decode(bytes)?),
            ForkName::Gloas => Self::Gloas(Ssz::decode(bytes)?),
        })
    }

    /// Decodes a block of the fork its own slot falls in.
    ///
    /// Every fork encodes the slot first, so it can be read before the fork is known.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are too short to hold a slot, or do not decode as that fork's block.
    pub fn decode_at(bytes: &[u8], config: &ChainConfig) -> Result<Self, DecodeError> {
        let slot = Slot::decode_at(bytes, 0)?;
        Self::decode(bytes, config.fork_at(slot.epoch::<P>()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Epoch, Minimal};

    #[test]
    fn fulu_block_keeps_its_fork_beside_the_electra_shape() {
        // Fixture state: Electra from epoch 1 and Fulu from epoch 2, minimal preset of 8 slots.
        let config = ChainConfig {
            altair_fork_epoch: Epoch(0),
            bellatrix_fork_epoch: Epoch(0),
            capella_fork_epoch: Epoch(0),
            deneb_fork_epoch: Epoch(0),
            electra_fork_epoch: Epoch(1),
            fulu_fork_epoch: Epoch(2),
            ..ChainConfig::minimal()
        };
        // Slot 16 is the first slot of epoch 2, so Fulu.
        let block = fulu::BeaconBlock::<Minimal> {
            slot: Slot(16),
            ..Default::default()
        };

        let decoded = BeaconBlock::<Minimal>::decode_at(&block.encode(), &config).unwrap();

        assert_eq!(decoded, BeaconBlock::Fulu(block.clone()));
        assert_eq!(decoded.fork_name(), ForkName::Fulu);
        assert_eq!(decoded.hash_tree_root(), block.hash_tree_root());
    }
}
