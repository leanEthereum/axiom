//! Reassembly of handshake messages from CRYPTO frame data, one encryption level at a time.

use super::{Level, ProtocolError, message::Message};

/// Longest handshake message accepted: above any public certificate chain, and bounded.
const MAX_MESSAGE_LEN: usize = 1 << 16;

/// Bytes received at the current level and not yet framed into messages.
///
/// QUIC frames and TLS records deliver each level's stream in order, but cut anywhere.
/// The buffer joins the pieces and yields whole messages.
#[derive(Debug)]
pub(crate) struct HandshakeBuffer {
    /// The level the state machine reads at.
    level: Level,
    /// Bytes received and not yet consumed.
    pending: Vec<u8>,
}

impl HandshakeBuffer {
    /// An empty buffer reading at a level.
    pub(crate) const fn new(level: Level) -> Self {
        Self {
            level,
            pending: Vec::new(),
        }
    }

    /// The level the state machine reads at.
    pub(crate) const fn level(&self) -> Level {
        self.level
    }

    /// Appends bytes received at a level, which must be the current one.
    pub(crate) fn push(&mut self, level: Level, bytes: &[u8]) -> Result<(), ProtocolError> {
        if level != self.level {
            return Err(ProtocolError::WrongLevel {
                expected: self.level,
                found: level,
            });
        }
        self.pending.extend_from_slice(bytes);
        Ok(())
    }

    /// The next whole message, or nothing until more bytes arrive.
    pub(crate) fn next_message(&mut self) -> Result<Option<Message>, ProtocolError> {
        let Some(header) = self.pending.first_chunk::<{ Message::HEADER_LEN }>() else {
            return Ok(None);
        };
        let length =
            usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
        if length > MAX_MESSAGE_LEN {
            return Err(ProtocolError::MessageTooLong {
                length,
                max: MAX_MESSAGE_LEN,
            });
        }
        let total = Message::HEADER_LEN + length;
        if self.pending.len() < total {
            return Ok(None);
        }
        let raw: Vec<u8> = self.pending.drain(..total).collect();
        Ok(Some(Message::from_raw(raw)))
    }

    /// Moves to the next level once keys change.
    ///
    /// Data left at the old level is an error, per RFC 8446, section 5.1, and RFC 9001, section 4.1.3.
    /// The peer sent it after a message that should have ended that level.
    pub(crate) const fn advance(&mut self, level: Level) -> Result<(), ProtocolError> {
        if !self.pending.is_empty() {
            return Err(ProtocolError::DataAfterKeyChange {
                level: self.level,
                count: self.pending.len(),
            });
        }
        self.level = level;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::HandshakeType;

    #[test]
    fn messages_are_joined_across_pieces() {
        // A 2-byte Finished body split as 14 00 | 00 02 aa | bb, then the start of another.
        let mut buffer = HandshakeBuffer::new(Level::Handshake);
        buffer.push(Level::Handshake, &[0x14, 0x00]).unwrap();
        assert_eq!(buffer.next_message(), Ok(None));
        buffer.push(Level::Handshake, &[0x00, 0x02, 0xaa]).unwrap();
        assert_eq!(buffer.next_message(), Ok(None));
        buffer.push(Level::Handshake, &[0xbb, 0x0b]).unwrap();
        let message = buffer.next_message().unwrap().unwrap();
        assert_eq!(message.kind(), HandshakeType::FINISHED);
        assert_eq!(message.body(), [0xaa, 0xbb]);
        assert_eq!(buffer.next_message(), Ok(None));

        // The leftover 0x0b blocks a level change.
        assert_eq!(
            buffer.advance(Level::Application),
            Err(ProtocolError::DataAfterKeyChange {
                level: Level::Handshake,
                count: 1
            })
        );
    }

    #[test]
    fn levels_and_lengths_are_enforced() {
        let mut buffer = HandshakeBuffer::new(Level::Initial);
        assert_eq!(
            buffer.push(Level::Handshake, &[1]),
            Err(ProtocolError::WrongLevel {
                expected: Level::Initial,
                found: Level::Handshake
            })
        );
        // A header announcing 2^16 + 1 bytes.
        buffer
            .push(Level::Initial, &[0x01, 0x01, 0x00, 0x01])
            .unwrap();
        assert_eq!(
            buffer.next_message(),
            Err(ProtocolError::MessageTooLong {
                length: 65_537,
                max: 65_536
            })
        );
    }
}
