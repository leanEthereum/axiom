//! The 12-byte frame header every yamux frame starts with.

use std::fmt;

use super::YamuxError;

/// Bytes of a frame header.
pub const HEADER_LEN: usize = 12;

/// The only protocol version defined.
const VERSION: u8 = 0;

/// The identifier of one logical stream within a session.
///
/// The client opens odd identifiers, the server even ones, so the two never collide.
/// Identifier zero names the session itself, for pings and go-away frames.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u32);

impl StreamId {
    /// The session-level identifier.
    pub const SESSION: Self = Self(0);
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stream {}", self.0)
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// What a frame carries, and so what its length field means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    /// Stream data; the length counts the bytes that follow the header.
    Data,
    /// A credit to the sender's window; the length is the credit.
    WindowUpdate,
    /// A keep-alive or RTT probe; the length is an opaque value echoed back.
    Ping,
    /// Session shutdown; the length is an error code.
    GoAway,
}

impl FrameType {
    /// The type byte on the wire.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::WindowUpdate => 1,
            Self::Ping => 2,
            Self::GoAway => 3,
        }
    }
}

/// The flag bits of a frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags(pub u16);

impl Flags {
    /// No flag set.
    pub const NONE: Self = Self(0);
    /// Opens a stream, or marks a ping as a request.
    pub const SYN: Self = Self(0x1);
    /// Accepts a stream, or marks a ping as a response.
    pub const ACK: Self = Self(0x2);
    /// Half-closes a stream: the sender writes no more.
    pub const FIN: Self = Self(0x4);
    /// Aborts a stream at once.
    pub const RST: Self = Self(0x8);

    /// Whether every bit of another flag set is present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The union of two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// A decoded frame header.
///
/// ```text
/// byte  0        1        2..4         4..8            8..12
///     ┌────────┬────────┬────────────┬───────────────┬───────────────┐
///     │version │ type   │ flags BE   │ stream id BE  │ length BE     │
///     └────────┴────────┴────────────┴───────────────┴───────────────┘
///
/// open stream 1 with 3 data bytes:
///   00 00 00 01 00 00 00 01 00 00 00 03
///   v0 data SYN   stream 1    length 3
/// ```
///
/// See `libp2p/specs/yamux/README.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// What the frame carries.
    pub frame_type: FrameType,
    /// Flag bits.
    pub flags: Flags,
    /// The addressed stream, or zero for the session.
    pub stream_id: StreamId,
    /// Payload length, window credit, ping value, or error code, by type.
    pub length: u32,
}

impl Header {
    /// The 12-byte wire form.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = VERSION;
        out[1] = self.frame_type.code();
        out[2..4].copy_from_slice(&self.flags.0.to_be_bytes());
        out[4..8].copy_from_slice(&self.stream_id.0.to_be_bytes());
        out[8..12].copy_from_slice(&self.length.to_be_bytes());
        out
    }

    /// Parses a 12-byte wire form.
    pub const fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self, YamuxError> {
        // A future version would change the layout, so refuse to guess.
        if bytes[0] != VERSION {
            return Err(YamuxError::InvalidVersion(bytes[0]));
        }
        let frame_type = match bytes[1] {
            0 => FrameType::Data,
            1 => FrameType::WindowUpdate,
            2 => FrameType::Ping,
            3 => FrameType::GoAway,
            other => return Err(YamuxError::InvalidFrameType(other)),
        };
        Ok(Self {
            frame_type,
            flags: Flags(u16::from_be_bytes([bytes[2], bytes[3]])),
            stream_id: StreamId(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])),
            length: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn header_layout() {
        // The overview example: open stream 1 carrying 3 bytes.
        let header = Header {
            frame_type: FrameType::Data,
            flags: Flags::SYN,
            stream_id: StreamId(1),
            length: 3,
        };
        let bytes = header.encode();
        assert_eq!(bytes, [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 3]);
        assert_eq!(Header::decode(&bytes), Ok(header));

        // A ping response with opaque value 0x01020304 on the session id.
        //
        //     type 2, flags ACK (0x0002), stream 0, length 0x01020304
        let pong = Header {
            frame_type: FrameType::Ping,
            flags: Flags::ACK,
            stream_id: StreamId::SESSION,
            length: 0x0102_0304,
        };
        assert_eq!(pong.encode(), [0, 2, 0, 2, 0, 0, 0, 0, 1, 2, 3, 4]);

        // A go-away with code 1, protocol error.
        let go_away = Header {
            frame_type: FrameType::GoAway,
            flags: Flags::NONE,
            stream_id: StreamId::SESSION,
            length: 1,
        };
        assert_eq!(go_away.encode(), [0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn rejects_unknown_version_and_type() {
        assert_eq!(Header::decode(&[1; 12]), Err(YamuxError::InvalidVersion(1)));
        let mut bytes = [0; 12];
        bytes[1] = 4;
        assert_eq!(Header::decode(&bytes), Err(YamuxError::InvalidFrameType(4)));
    }

    #[test]
    fn flag_algebra() {
        let both = Flags::SYN.union(Flags::FIN);
        assert_eq!(both, Flags(0x5));
        assert!(both.contains(Flags::SYN));
        assert!(!both.contains(Flags::ACK));
    }

    proptest! {
        #[test]
        fn round_trip(code in 0u8..4, flags: u16, id: u32, length: u32) {
            let mut bytes = [0u8; 12];
            bytes[1] = code;
            bytes[2..4].copy_from_slice(&flags.to_be_bytes());
            bytes[4..8].copy_from_slice(&id.to_be_bytes());
            bytes[8..].copy_from_slice(&length.to_be_bytes());
            let header = Header::decode(&bytes).unwrap();
            prop_assert_eq!(header.encode(), bytes);
        }
    }
}
