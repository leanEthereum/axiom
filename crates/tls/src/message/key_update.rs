//! The KeyUpdate message, per RFC 8446, section 4.6.3.

use super::HandshakeType;
use crate::{ProtocolError, codec::Reader};

/// A notice that the sender now protects its records with its next traffic secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyUpdate {
    /// Whether the receiver must answer with its own KeyUpdate.
    pub(crate) update_requested: bool,
}

impl KeyUpdate {
    /// Parses a body of one byte: 0 for update_not_requested, 1 for update_requested.
    pub(crate) fn parse(body: &[u8]) -> Result<Self, ProtocolError> {
        let mut reader = Reader::new(body);
        let request = reader.u8()?;
        reader.finish()?;
        match request {
            0 => Ok(Self {
                update_requested: false,
            }),
            1 => Ok(Self {
                update_requested: true,
            }),
            other => Err(ProtocolError::InvalidKeyUpdate(other)),
        }
    }

    /// The framed message.
    pub(crate) fn encode(self) -> Vec<u8> {
        HandshakeType::KEY_UPDATE.frame(|body| body.u8(u8::from(self.update_requested)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_byte_is_zero_or_one() {
        let raw = KeyUpdate {
            update_requested: true,
        }
        .encode();
        assert_eq!(raw, [24, 0, 0, 1, 1]);
        assert_eq!(
            KeyUpdate::parse(&raw[4..]),
            Ok(KeyUpdate {
                update_requested: true
            })
        );
        // Mutation: the value 2.
        assert_eq!(
            KeyUpdate::parse(&[2]),
            Err(ProtocolError::InvalidKeyUpdate(2))
        );
    }
}
