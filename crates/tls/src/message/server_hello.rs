//! The ServerHello, per RFC 8446, section 4.1.3.

use super::{HandshakeType, LEGACY_VERSION, TLS13};
use crate::{
    CipherSuite, NamedGroup, ProtocolError,
    codec::{Reader, Width},
    extension::{ExtensionType, Extensions},
};

/// The random of a HelloRetryRequest: SHA-256 of "HelloRetryRequest", per RFC 8446, section 4.1.3.
pub(crate) const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// A ServerHello.
///
/// ```text
/// legacy_version: u16, random: [32], legacy_session_id_echo <0..32>,
/// cipher_suite: u16, legacy_compression_method: u8 = 0, extensions <6..2^16-1>
/// ```
///
/// A TLS 1.2 server may omit the extensions block entirely, per RFC 5246, section 7.4.1.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerHello<'a> {
    /// The legacy version field; 0x0303 in TLS 1.3.
    pub(crate) legacy_version: u16,
    /// The server random.
    pub(crate) random: [u8; 32],
    /// The echo of the client's session id.
    pub(crate) session_id: &'a [u8],
    /// The selected suite code point.
    pub(crate) cipher_suite: u16,
    /// The extensions.
    pub(crate) extensions: Extensions<'a>,
}

impl<'a> ServerHello<'a> {
    /// Parses a body, refusing a HelloRetryRequest and a non-null compression method.
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut reader = Reader::new(body);
        let legacy_version = reader.u16()?;
        let random = reader.array()?;
        // A HelloRetryRequest shares the message type and is told apart by its random alone.
        if random == HELLO_RETRY_REQUEST_RANDOM {
            return Err(ProtocolError::HelloRetryRequest);
        }
        let session_id = reader.vector(Width::U8, 0, 32, 1)?.rest();
        let cipher_suite = reader.u16()?;
        if reader.u8()? != 0 {
            return Err(ProtocolError::InvalidCompression);
        }
        let extensions = if reader.is_empty() {
            Extensions::default()
        } else {
            Extensions::read(&mut reader, 0)?
        };
        reader.finish()?;
        Ok(Self {
            legacy_version,
            random,
            session_id,
            cipher_suite,
            extensions,
        })
    }

    /// The framed TLS 1.3 ServerHello this stack sends: one suite and one key share.
    ///
    /// The session id echoes the client's, as RFC 8446, section 4.1.3, requires.
    pub(crate) fn encode(
        random: &[u8; 32],
        session_id: &[u8],
        suite: CipherSuite,
        group: NamedGroup,
        key_share: &[u8],
    ) -> Vec<u8> {
        HandshakeType::SERVER_HELLO.frame(|body| {
            body.u16(LEGACY_VERSION);
            body.bytes(random);
            body.vector(Width::U8, |id| id.bytes(session_id));
            body.u16(suite.code());
            body.u8(0);
            body.vector(Width::U16, |block| {
                // The order of RFC 8448, section 3, so the trace reproduces byte for byte.
                Extensions::write(block, ExtensionType::KEY_SHARE, |share| {
                    Extensions::write_key_share(share, group.0, key_share);
                });
                Extensions::write(block, ExtensionType::SUPPORTED_VERSIONS, |version| {
                    version.u16(TLS13);
                });
            });
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;

    #[test]
    fn encoding_parses_back() {
        let message = Message::from_raw(ServerHello::encode(
            &[5; 32],
            &[],
            CipherSuite::ChaCha20Poly1305Sha256,
            NamedGroup::X25519,
            &[6; 32],
        ));
        let hello = ServerHello::parse(message.body()).unwrap();
        assert_eq!(hello.random, [5; 32]);
        assert_eq!(hello.cipher_suite, 0x1303);
        assert_eq!(hello.extensions.selected_version(), Ok(0x0304));
        assert_eq!(
            hello.extensions.server_key_share(),
            Ok((0x001d, &[6; 32][..]))
        );
    }

    #[test]
    fn hello_retry_request_is_refused() {
        // The same message with the retry random in place of the server random.
        let mut raw = ServerHello::encode(
            &[5; 32],
            &[],
            CipherSuite::Aes128GcmSha256,
            NamedGroup::X25519,
            &[6; 32],
        );
        raw[6..38].copy_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
        assert_eq!(
            ServerHello::parse(&raw[4..]),
            Err(ProtocolError::HelloRetryRequest)
        );
    }
}
