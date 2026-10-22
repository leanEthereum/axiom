//! Packet number spaces, per RFC 9000, section 12.3.

use crate::tls::Level;

/// One of the three independent packet number spaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Space {
    /// Initial packets.
    Initial,
    /// Handshake packets.
    Handshake,
    /// 1-RTT packets, the application data space.
    Data,
}

impl Space {
    /// Every space, in handshake order.
    pub(crate) const ALL: [Self; 3] = [Self::Initial, Self::Handshake, Self::Data];

    /// The position of the space in per-space arrays.
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Initial => 0,
            Self::Handshake => 1,
            Self::Data => 2,
        }
    }

    /// The space whose packets carry a TLS level.
    pub(crate) const fn from_level(level: Level) -> Self {
        match level {
            Level::Initial => Self::Initial,
            Level::Handshake => Self::Handshake,
            Level::Application => Self::Data,
        }
    }

    /// The TLS level whose bytes this space's CRYPTO frames carry.
    pub(crate) const fn level(self) -> Level {
        match self {
            Self::Initial => Level::Initial,
            Self::Handshake => Level::Handshake,
            Self::Data => Level::Application,
        }
    }
}
