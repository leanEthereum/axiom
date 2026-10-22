//! The Finished message, per RFC 8446, section 4.4.4.

use super::HandshakeType;
use crate::tls::{TlsError, codec::Reader};

/// The MAC over the transcript that ends each side's flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Finished {
    /// The verify data: as long as the suite's hash, 32 bytes for SHA-256.
    pub(crate) verify_data: [u8; 32],
}

impl Finished {
    /// Parses a body of exactly 32 bytes.
    pub(crate) fn parse(body: &[u8]) -> Result<Self, TlsError> {
        let mut reader = Reader::new(body);
        let verify_data = reader.array()?;
        reader.finish()?;
        Ok(Self { verify_data })
    }

    /// The framed message.
    pub(crate) fn encode(verify_data: &[u8; 32]) -> Vec<u8> {
        HandshakeType::FINISHED.frame(|body| body.bytes(verify_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_data_is_exactly_32_bytes() {
        let raw = Finished::encode(&[9; 32]);
        assert_eq!(raw[..4], [20, 0, 0, 32]);
        assert_eq!(
            Finished::parse(&raw[4..]),
            Ok(Finished {
                verify_data: [9; 32]
            })
        );
        assert_eq!(
            Finished::parse(&[9; 33]),
            Err(TlsError::TrailingBytes { count: 1 })
        );
    }
}
