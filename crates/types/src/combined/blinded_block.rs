//! A blinded beacon block of any fork that has one.

use axiom_ssz::{CapacityError, DecodeError, Root, Ssz};
use thiserror::Error;

use crate::{
    ForkName, KzgCommitment, Preset, Slot, ValidatorIndex, bellatrix, bellatrix::UnblindError,
    capella, deneb, electra, fulu, phase0::BeaconBlockHeader,
};

/// A blinded block that cannot be decoded or unblinded.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum BlindedBlockError {
    /// The fork has no blinded block, being before the merge or after enshrined builders.
    #[error("fork {fork} has no blinded block")]
    NoBlindedBlock {
        /// The fork asked for.
        fork: ForkName,
    },
    /// The bytes are not the encoding of a blinded block of the fork.
    #[error("blinded block does not decode: {0}")]
    Decode(#[from] DecodeError),
    /// The payload belongs to another fork than the block.
    #[error("a {payload} payload cannot unblind a {block} block")]
    ForkMismatch {
        /// Fork of the blinded block.
        block: ForkName,
        /// Fork of the offered payload.
        payload: ForkName,
    },
    /// The payload is not the one the block's header commits to.
    #[error("blinded block does not unblind: {0}")]
    Unblind(#[from] UnblindError),
    /// A payload body list holds more items than its bound.
    #[error("payload body overflows: {0}")]
    BodyCapacity(#[from] CapacityError),
    /// A payload body of a fork with withdrawals lacks them.
    #[error("payload body of a {fork} block lacks its withdrawals")]
    MissingWithdrawals {
        /// The block's fork.
        fork: ForkName,
    },
}

/// A blinded beacon block of whichever fork it belongs to.
///
/// Only Bellatrix to Fulu have one: the builder API sells payloads in exactly those forks.
/// Fulu kept Electra's blinded block, so those two variants hold the same type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlindedBeaconBlock<P: Preset> {
    /// A blinded Bellatrix block.
    Bellatrix(bellatrix::BlindedBeaconBlock<P>),
    /// A blinded Capella block.
    Capella(capella::BlindedBeaconBlock<P>),
    /// A blinded Deneb block.
    Deneb(deneb::BlindedBeaconBlock<P>),
    /// A blinded Electra block.
    Electra(electra::BlindedBeaconBlock<P>),
    /// A blinded Fulu block, the same type as a blinded Electra block.
    Fulu(fulu::BlindedBeaconBlock<P>),
}

impl<P: Preset> BlindedBeaconBlock<P> {
    /// The fork the block belongs to.
    #[must_use]
    pub const fn fork_name(&self) -> ForkName {
        match self {
            Self::Bellatrix(_) => ForkName::Bellatrix,
            Self::Capella(_) => ForkName::Capella,
            Self::Deneb(_) => ForkName::Deneb,
            Self::Electra(_) => ForkName::Electra,
            Self::Fulu(_) => ForkName::Fulu,
        }
    }

    /// Slot the block is proposed in.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        match self {
            Self::Bellatrix(block) => block.slot,
            Self::Capella(block) => block.slot,
            Self::Deneb(block) => block.slot,
            Self::Electra(block) | Self::Fulu(block) => block.slot,
        }
    }

    /// The proposer.
    #[must_use]
    pub const fn proposer_index(&self) -> ValidatorIndex {
        match self {
            Self::Bellatrix(block) => block.proposer_index,
            Self::Capella(block) => block.proposer_index,
            Self::Deneb(block) => block.proposer_index,
            Self::Electra(block) | Self::Fulu(block) => block.proposer_index,
        }
    }

    /// Root of the parent block.
    #[must_use]
    pub const fn parent_root(&self) -> Root {
        match self {
            Self::Bellatrix(block) => block.parent_root,
            Self::Capella(block) => block.parent_root,
            Self::Deneb(block) => block.parent_root,
            Self::Electra(block) | Self::Fulu(block) => block.parent_root,
        }
    }

    /// The block's header, the same one the full block has.
    #[must_use]
    pub fn header(&self) -> BeaconBlockHeader {
        match self {
            Self::Bellatrix(block) => block.header(),
            Self::Capella(block) => block.header(),
            Self::Deneb(block) => block.header(),
            Self::Electra(block) | Self::Fulu(block) => block.header(),
        }
    }

    /// Merkle commitment to the block, the root of the full block too.
    #[must_use]
    pub fn hash_tree_root(&self) -> Root {
        match self {
            Self::Bellatrix(block) => block.hash_tree_root(),
            Self::Capella(block) => block.hash_tree_root(),
            Self::Deneb(block) => block.hash_tree_root(),
            Self::Electra(block) | Self::Fulu(block) => block.hash_tree_root(),
        }
    }

    /// Commitments to the blobs the payload carries, from Deneb on.
    #[must_use]
    pub fn blob_kzg_commitments(&self) -> &[KzgCommitment] {
        match self {
            Self::Bellatrix(_) | Self::Capella(_) => &[],
            Self::Deneb(block) => &block.body.blob_kzg_commitments,
            Self::Electra(block) | Self::Fulu(block) => &block.body.blob_kzg_commitments,
        }
    }

    /// The block's SSZ encoding, which does not record the fork.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Bellatrix(block) => block.encode(),
            Self::Capella(block) => block.encode(),
            Self::Deneb(block) => block.encode(),
            Self::Electra(block) | Self::Fulu(block) => block.encode(),
        }
    }

    /// Decodes a blinded block of a known fork.
    ///
    /// # Errors
    ///
    /// Fails when the fork has no blinded block, or the bytes do not encode one of that fork.
    pub fn decode(bytes: &[u8], fork: ForkName) -> Result<Self, BlindedBlockError> {
        Ok(match fork {
            ForkName::Phase0 | ForkName::Altair | ForkName::Gloas | ForkName::Hstar => {
                return Err(BlindedBlockError::NoBlindedBlock { fork });
            }
            ForkName::Bellatrix => Self::Bellatrix(Ssz::decode(bytes)?),
            ForkName::Capella => Self::Capella(Ssz::decode(bytes)?),
            ForkName::Deneb => Self::Deneb(Ssz::decode(bytes)?),
            ForkName::Electra => Self::Electra(Ssz::decode(bytes)?),
            ForkName::Fulu => Self::Fulu(Ssz::decode(bytes)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Minimal;

    #[test]
    fn decode_reads_the_fork_it_is_given() {
        // Fixture state: a Deneb blinded block at slot 6 committing to one blob.
        let mut block = deneb::BlindedBeaconBlock::<Minimal> {
            slot: Slot(6),
            ..deneb::BlindedBeaconBlock::default()
        };
        block
            .body
            .blob_kzg_commitments
            .push(KzgCommitment([3; 48]))
            .unwrap();

        let decoded =
            BlindedBeaconBlock::<Minimal>::decode(&block.encode(), ForkName::Deneb).unwrap();

        assert_eq!(decoded, BlindedBeaconBlock::Deneb(block));
        assert_eq!(decoded.blob_kzg_commitments(), &[KzgCommitment([3; 48])]);
    }

    #[test]
    fn decode_refuses_a_fork_without_blinded_blocks() {
        // Gloas enshrines builders, so the builder API has no blinded block to sell.
        assert_eq!(
            BlindedBeaconBlock::<Minimal>::decode(&[], ForkName::Gloas),
            Err(BlindedBlockError::NoBlindedBlock {
                fork: ForkName::Gloas
            })
        );
    }
}
