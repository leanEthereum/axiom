//! An execution payload of any fork whose block carries one.

use crate::{ForkName, Preset, bellatrix, capella, deneb, electra, fulu};

/// An execution payload of whichever fork it belongs to.
///
/// Phase0 and Altair have no payload, and Gloas moves it into a separate envelope.
/// Deneb, Electra, and Fulu share one payload type, so the variant records the fork.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionPayload<P: Preset> {
    /// A Bellatrix payload.
    Bellatrix(bellatrix::ExecutionPayload<P>),
    /// A Capella payload.
    Capella(capella::ExecutionPayload<P>),
    /// A Deneb payload.
    Deneb(deneb::ExecutionPayload<P>),
    /// An Electra payload, the same type as a Deneb payload.
    Electra(electra::ExecutionPayload<P>),
    /// A Fulu payload, the same type as a Deneb payload.
    Fulu(fulu::ExecutionPayload<P>),
}

impl<P: Preset> ExecutionPayload<P> {
    /// The fork the payload belongs to.
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
}
