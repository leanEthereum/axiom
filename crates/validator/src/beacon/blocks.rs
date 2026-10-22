//! Blocks a beacon node produces for a proposer, and the signed proposals it publishes.

use axiom_ssz::Ssz;
use axiom_types::{
    BlsSignature, ForkName, Preset, Root, Slot,
    combined::{self, BlindedBlockError},
    deneb, electra, fulu,
    phase0::BeaconBlockHeader,
};

/// An unsigned block, in the shape its fork's produce route returns.
///
/// From Deneb to Fulu the block travels with its blobs and proofs.
/// Before Deneb, and from Gloas on, the block travels alone.
/// A block on a builder's payload is blinded: it holds the payload's header.
/// See `produceBlockV3` and `produceBlockV4` in the beacon API.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "one block per proposal, signed and published once"
)]
pub enum ProducedBlock<P: Preset> {
    /// A block alone.
    Block(combined::BeaconBlock<P>),
    /// A Deneb block with its blobs and blob proofs.
    Deneb(deneb::BlockContents<P>),
    /// An Electra block with its blobs and blob proofs.
    Electra(electra::BlockContents<P>),
    /// A Fulu block with its blobs and cell proofs.
    Fulu(fulu::BlockContents<P>),
    /// A block whose payload a builder reveals once the proposer has signed.
    Blinded(combined::BlindedBeaconBlock<P>),
}

impl<P: Preset> ProducedBlock<P> {
    /// Decodes a produce route's SSZ body, in the shape of a fork, blinded or full.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not that fork's body, or the fork has no blinded block.
    pub fn decode(bytes: &[u8], fork: ForkName, blinded: bool) -> Result<Self, BlindedBlockError> {
        if blinded {
            return Ok(Self::Blinded(combined::BlindedBeaconBlock::decode(
                bytes, fork,
            )?));
        }
        Ok(match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Gloas => Self::Block(combined::BeaconBlock::decode(bytes, fork)?),
            ForkName::Deneb => Self::Deneb(Ssz::decode(bytes)?),
            ForkName::Electra => Self::Electra(Ssz::decode(bytes)?),
            ForkName::Fulu => Self::Fulu(Ssz::decode(bytes)?),
        })
    }

    /// The SSZ body, as the produce route sends it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Block(block) => block.encode(),
            Self::Deneb(contents) => contents.encode(),
            Self::Electra(contents) => contents.encode(),
            Self::Fulu(contents) => contents.encode(),
            Self::Blinded(block) => block.encode(),
        }
    }

    /// Whether the block holds a payload header in place of its payload.
    #[must_use]
    pub const fn is_blinded(&self) -> bool {
        matches!(self, Self::Blinded(_))
    }

    /// The fork of the block.
    #[must_use]
    pub const fn fork(&self) -> ForkName {
        match self {
            Self::Block(block) => block.fork_name(),
            Self::Deneb(_) => ForkName::Deneb,
            Self::Electra(_) => ForkName::Electra,
            Self::Fulu(_) => ForkName::Fulu,
            Self::Blinded(block) => block.fork_name(),
        }
    }

    /// The slot of the block.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        match self {
            Self::Block(block) => block.slot(),
            Self::Deneb(contents) => contents.block.slot,
            Self::Electra(contents) => contents.block.slot,
            Self::Fulu(contents) => contents.block.slot,
            Self::Blinded(block) => block.slot(),
        }
    }

    /// The block's header, whose root is the block's root and what the proposer signs.
    #[must_use]
    pub fn header(&self) -> BeaconBlockHeader {
        // The header commits to the body by root, so no block is copied to build it.
        match self {
            Self::Block(block) => block.header(),
            Self::Blinded(block) => block.header(),
            Self::Deneb(contents) => {
                let block = &contents.block;
                BeaconBlockHeader {
                    slot: block.slot,
                    proposer_index: block.proposer_index,
                    parent_root: block.parent_root,
                    state_root: block.state_root,
                    body_root: block.body.hash_tree_root(),
                }
            }
            Self::Electra(electra::BlockContents { block, .. })
            | Self::Fulu(fulu::BlockContents { block, .. }) => BeaconBlockHeader {
                slot: block.slot,
                proposer_index: block.proposer_index,
                parent_root: block.parent_root,
                state_root: block.state_root,
                body_root: block.body.hash_tree_root(),
            },
        }
    }

    /// The proposal, once the proposer has signed the block.
    #[must_use]
    pub fn sign(self, signature: BlsSignature) -> SignedProposal<P> {
        match self {
            Self::Block(block) => {
                SignedProposal::Block(combined::SignedBeaconBlock::from_parts(block, signature))
            }
            Self::Deneb(contents) => SignedProposal::Deneb(contents.into_signed(signature)),
            Self::Electra(contents) => SignedProposal::Electra(contents.into_signed(signature)),
            Self::Fulu(contents) => SignedProposal::Fulu(contents.into_signed(signature)),
            Self::Blinded(block) => SignedProposal::Blinded(
                combined::SignedBlindedBeaconBlock::from_parts(block, signature),
            ),
        }
    }
}

/// A signed block with what travels beside it, in the shape the publish route takes.
///
/// A blinded block goes to its own route, for the builder to reveal its payload.
/// See `publishBlockV2` and `publishBlindedBlockV2` in the beacon API.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "one proposal per slot, published once"
)]
pub enum SignedProposal<P: Preset> {
    /// A signed block alone.
    Block(combined::SignedBeaconBlock<P>),
    /// A signed Deneb block with its blobs.
    Deneb(deneb::SignedBlockContents<P>),
    /// A signed Electra block with its blobs.
    Electra(electra::SignedBlockContents<P>),
    /// A signed Fulu block with its blobs and cell proofs.
    Fulu(fulu::SignedBlockContents<P>),
    /// A signed blinded block.
    Blinded(combined::SignedBlindedBeaconBlock<P>),
}

impl<P: Preset> SignedProposal<P> {
    /// Decodes a publish route's SSZ body, in the shape of a fork, blinded or full.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not that fork's body, or the fork has no blinded block.
    pub fn decode(bytes: &[u8], fork: ForkName, blinded: bool) -> Result<Self, BlindedBlockError> {
        if blinded {
            return Ok(Self::Blinded(combined::SignedBlindedBeaconBlock::decode(
                bytes, fork,
            )?));
        }
        Ok(match fork {
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Gloas => Self::Block(combined::SignedBeaconBlock::decode(bytes, fork)?),
            ForkName::Deneb => Self::Deneb(Ssz::decode(bytes)?),
            ForkName::Electra => Self::Electra(Ssz::decode(bytes)?),
            ForkName::Fulu => Self::Fulu(Ssz::decode(bytes)?),
        })
    }

    /// The SSZ body of the publish route.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Block(block) => block.encode(),
            Self::Deneb(contents) => contents.encode(),
            Self::Electra(contents) => contents.encode(),
            Self::Fulu(contents) => contents.encode(),
            Self::Blinded(block) => block.encode(),
        }
    }

    /// Whether the block is blinded, so it goes to the blinded publish route.
    #[must_use]
    pub const fn is_blinded(&self) -> bool {
        matches!(self, Self::Blinded(_))
    }

    /// The fork of the block.
    #[must_use]
    pub const fn fork(&self) -> ForkName {
        match self {
            Self::Block(block) => block.fork_name(),
            Self::Deneb(_) => ForkName::Deneb,
            Self::Electra(_) => ForkName::Electra,
            Self::Fulu(_) => ForkName::Fulu,
            Self::Blinded(block) => block.fork_name(),
        }
    }

    /// The signed block alone, when it is not blinded.
    #[must_use]
    pub fn block(&self) -> Option<combined::SignedBeaconBlock<P>> {
        Some(match self {
            Self::Blinded(_) => return None,
            Self::Block(block) => block.clone(),
            Self::Deneb(contents) => {
                combined::SignedBeaconBlock::Deneb(contents.signed_block.clone())
            }
            Self::Electra(contents) => {
                combined::SignedBeaconBlock::Electra(contents.signed_block.clone())
            }
            Self::Fulu(contents) => {
                combined::SignedBeaconBlock::Fulu(contents.signed_block.clone())
            }
        })
    }

    /// Root of the block.
    #[must_use]
    pub fn block_root(&self) -> Root {
        match self {
            Self::Blinded(block) => block.block_root(),
            other => other.block().map_or(Root::ZERO, |block| block.block_root()),
        }
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, ValidatorIndex};

    use super::*;

    #[test]
    fn a_signed_deneb_proposal_keeps_its_header_root() {
        // Fixture state: a produced Deneb block at slot 4 by validator 2, with no blobs.
        let mut contents = deneb::BlockContents::<Minimal>::default();
        contents.block.slot = Slot(4);
        contents.block.proposer_index = ValidatorIndex(2);
        let produced = ProducedBlock::Deneb(contents);
        let header = produced.header();

        // Round trip through the produce route's bytes.
        let decoded =
            ProducedBlock::<Minimal>::decode(&produced.encode(), ForkName::Deneb, false).unwrap();
        assert_eq!(decoded, produced);

        // Signing keeps the block, so the signed root is the header's root.
        let signed = produced.sign(BlsSignature([1; 96]));
        assert_eq!(signed.fork(), ForkName::Deneb);
        assert_eq!(signed.block_root(), header.hash_tree_root());
        let republished =
            SignedProposal::<Minimal>::decode(&signed.encode(), ForkName::Deneb, false).unwrap();
        assert_eq!(republished, signed);
    }

    #[test]
    fn a_signed_blinded_proposal_goes_to_the_blinded_route() {
        // Fixture state: a blinded Electra block at slot 9 by validator 5.
        let mut block = electra::BlindedBeaconBlock::<Minimal>::default();
        block.slot = Slot(9);
        block.proposer_index = ValidatorIndex(5);
        let produced = ProducedBlock::Blinded(combined::BlindedBeaconBlock::Electra(block));
        let header = produced.header();

        // The produce route flags the body as blinded, so it decodes as one.
        let decoded =
            ProducedBlock::<Minimal>::decode(&produced.encode(), ForkName::Electra, true).unwrap();
        assert_eq!(decoded, produced);
        assert!(decoded.is_blinded());

        // Signing keeps the header, and the proposal carries no full block.
        let signed = produced.sign(BlsSignature([3; 96]));
        assert!(signed.is_blinded());
        assert_eq!(signed.fork(), ForkName::Electra);
        assert_eq!(signed.block_root(), header.hash_tree_root());
        assert_eq!(signed.block(), None);
        let republished =
            SignedProposal::<Minimal>::decode(&signed.encode(), ForkName::Electra, true).unwrap();
        assert_eq!(republished, signed);
    }

    #[test]
    fn a_fork_without_blinded_blocks_refuses_a_blinded_body() {
        // Phase0 has no execution payload, so nothing can be blinded.
        let error = ProducedBlock::<Minimal>::decode(&[], ForkName::Phase0, true).unwrap_err();
        assert_eq!(
            error,
            BlindedBlockError::NoBlindedBlock {
                fork: ForkName::Phase0
            }
        );
    }
}
