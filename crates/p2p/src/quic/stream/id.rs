//! Stream ids and the two facts their low bits encode, per RFC 9000, section 2.1.
//!
//! ```text
//! bits  initiator  direction
//! 0x0   client     bidirectional
//! 0x1   server     bidirectional
//! 0x2   client     unidirectional
//! 0x3   server     unidirectional
//! ```

use std::fmt;

/// Which endpoint of a connection a value concerns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// The endpoint that dialed.
    Client,
    /// The endpoint that accepted.
    Server,
}

impl Side {
    /// The other endpoint.
    #[must_use]
    pub const fn peer(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

/// A stream id: a counter shifted left by two, with the initiator and direction bits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u64);

impl StreamId {
    /// The n-th bidirectional stream an endpoint opens, counting from zero.
    #[must_use]
    pub const fn bidi(initiator: Side, index: u64) -> Self {
        let bit = match initiator {
            Side::Client => 0,
            Side::Server => 1,
        };
        Self(index << 2 | bit)
    }

    /// The endpoint that opened the stream.
    #[must_use]
    pub const fn initiator(self) -> Side {
        if self.0 & 0x1 == 0 {
            Side::Client
        } else {
            Side::Server
        }
    }

    /// Whether data flows one way only.
    #[must_use]
    pub const fn is_unidirectional(self) -> bool {
        self.0 & 0x2 != 0
    }

    /// The stream's position among the streams of its type, counting from zero.
    #[must_use]
    pub const fn index(self) -> u64 {
        self.0 >> 2
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stream {}", self.0)
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_bits() {
        // Stream 0 is the client's first bidirectional stream, 1 the server's.
        assert_eq!(StreamId::bidi(Side::Client, 0), StreamId(0));
        assert_eq!(StreamId::bidi(Side::Server, 0), StreamId(1));
        // The client's third one is 8.
        assert_eq!(StreamId::bidi(Side::Client, 2), StreamId(8));
        assert_eq!(StreamId(8).index(), 2);

        // Stream 7 is server-initiated and unidirectional.
        assert_eq!(StreamId(7).initiator(), Side::Server);
        assert!(StreamId(7).is_unidirectional());
        assert!(!StreamId(5).is_unidirectional());
        assert_eq!(Side::Client.peer(), Side::Server);
    }
}
