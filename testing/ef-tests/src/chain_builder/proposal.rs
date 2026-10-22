//! What the builder proposes for one slot.

use axiom_types::{Preset, combined, gloas};

/// The signed block of one slot, with the envelope that follows it once payloads separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proposal<P: Preset> {
    /// A block that carries its own payload, or none before the merge.
    Coupled(combined::SignedBeaconBlock<P>),
    /// A Gloas block that bids for its payload, and the envelope that reveals it.
    ///
    /// See EIP-7732.
    Separated {
        /// The block, with its self-built bid.
        block: combined::SignedBeaconBlock<P>,
        /// The proposer's envelope, revealing the payload the bid commits to.
        envelope: Box<gloas::SignedExecutionPayloadEnvelope<P>>,
    },
}

impl<P: Preset> Proposal<P> {
    /// The signed block.
    #[must_use]
    pub const fn block(&self) -> &combined::SignedBeaconBlock<P> {
        match self {
            Self::Coupled(block) | Self::Separated { block, .. } => block,
        }
    }

    /// The envelope, when the block's payload travels on its own.
    #[must_use]
    pub const fn envelope(&self) -> Option<&gloas::SignedExecutionPayloadEnvelope<P>> {
        match self {
            Self::Coupled(_) => None,
            Self::Separated { envelope, .. } => Some(envelope),
        }
    }
}
