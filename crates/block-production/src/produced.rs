//! A produced block, in the shape the block production route returns for its fork.

use axiom_ssz::{Ssz, U256};
use axiom_state_transition::State;
use axiom_types::{
    ForkName, Gwei, Preset, Root, Slot, altair, bellatrix, capella, combined, deneb, electra, fulu,
    gloas, hstar, phase0,
};

/// An unsigned block, with what a validator needs beside it to publish.
///
/// From Deneb to Fulu a full block travels with its blobs and proofs.
/// A self-built block from Gloas on travels with its payload envelope.
/// A block on a builder's payload is blinded until the builder reveals it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProducedBlock<P: Preset> {
    /// A phase0 block.
    Phase0(phase0::BeaconBlock<P>),
    /// An Altair block.
    Altair(altair::BeaconBlock<P>),
    /// A Bellatrix block.
    Bellatrix(bellatrix::BeaconBlock<P>),
    /// A Capella block.
    Capella(capella::BeaconBlock<P>),
    /// A Deneb block and its blobs.
    Deneb(deneb::BlockContents<P>),
    /// An Electra block and its blobs.
    Electra(electra::BlockContents<P>),
    /// A Fulu block and its blobs, with cell proofs.
    Fulu(fulu::BlockContents<P>),
    /// A self-built Gloas block, its envelope, and its blobs.
    GloasContents(gloas::BlockContents<P>),
    /// A Gloas block committing to a builder's bid.
    Gloas(gloas::BeaconBlock<P>),
    /// A self-built Hstar block, its envelope, and its blobs.
    HstarContents(hstar::BlockContents<P>),
    /// An Hstar block committing to a builder's bid.
    Hstar(hstar::BeaconBlock<P>),
    /// A block on a builder's payload, which the builder reveals after signing.
    Blinded(combined::BlindedBeaconBlock<P>),
}

impl<P: Preset> ProducedBlock<P> {
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
            Self::GloasContents(_) | Self::Gloas(_) => ForkName::Gloas,
            Self::HstarContents(_) | Self::Hstar(_) => ForkName::Hstar,
            Self::Blinded(block) => block.fork_name(),
        }
    }

    /// Whether the block holds a header in place of its payload.
    #[must_use]
    pub const fn is_blinded(&self) -> bool {
        matches!(self, Self::Blinded(_))
    }

    /// The block alone, without blobs, as the proposer signs it.
    ///
    /// A blinded block has no full form yet, so it has none.
    #[must_use]
    pub fn block(&self) -> Option<combined::BeaconBlock<P>> {
        let block = match self {
            Self::Phase0(block) => combined::BeaconBlock::Phase0(block.clone()),
            Self::Altair(block) => combined::BeaconBlock::Altair(block.clone()),
            Self::Bellatrix(block) => combined::BeaconBlock::Bellatrix(block.clone()),
            Self::Capella(block) => combined::BeaconBlock::Capella(block.clone()),
            Self::Deneb(contents) => combined::BeaconBlock::Deneb(contents.block.clone()),
            Self::Electra(contents) => combined::BeaconBlock::Electra(contents.block.clone()),
            Self::Fulu(contents) => combined::BeaconBlock::Fulu(contents.block.clone()),
            Self::GloasContents(contents) => combined::BeaconBlock::Gloas(contents.block.clone()),
            Self::Gloas(block) => combined::BeaconBlock::Gloas(block.clone()),
            Self::HstarContents(contents) => combined::BeaconBlock::Hstar(contents.block.clone()),
            Self::Hstar(block) => combined::BeaconBlock::Hstar(block.clone()),
            Self::Blinded(_) => return None,
        };
        Some(block)
    }

    /// Slot of the block.
    #[must_use]
    pub fn slot(&self) -> Slot {
        match self {
            Self::Blinded(block) => block.slot(),
            other => other.block().map_or(Slot(0), |block| block.slot()),
        }
    }

    /// Root of the block, which the proposer signs.
    #[must_use]
    pub fn block_root(&self) -> Root {
        match self {
            Self::Blinded(block) => block.hash_tree_root(),
            other => other
                .block()
                .map_or(Root::ZERO, |block| block.hash_tree_root()),
        }
    }

    /// The SSZ encoding the block production route returns.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Phase0(block) => block.encode(),
            Self::Altair(block) => block.encode(),
            Self::Bellatrix(block) => block.encode(),
            Self::Capella(block) => block.encode(),
            Self::Deneb(contents) => contents.encode(),
            Self::Electra(contents) => contents.encode(),
            Self::Fulu(contents) => contents.encode(),
            Self::GloasContents(contents) => contents.encode(),
            Self::Gloas(block) => block.encode(),
            Self::HstarContents(contents) => contents.encode(),
            Self::Hstar(block) => block.encode(),
            Self::Blinded(block) => block.encode(),
        }
    }
}

/// A block assembled by its fork, and the state after it.
#[derive(Clone, Debug)]
pub struct Built<P: Preset> {
    /// The block, with what travels beside it.
    pub block: ProducedBlock<P>,
    /// The state the block leads to.
    pub post: State<P>,
}

/// A produced block and what it earns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal<P: Preset> {
    /// The block, with what travels beside it.
    pub block: ProducedBlock<P>,
    /// What the block's consensus rewards pay the proposer.
    pub consensus_value: Gwei,
    /// What the payload pays the proposer, in wei.
    pub execution_value: U256,
}
