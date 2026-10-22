//! The ServerHello, per RFC 8446, section 4.1.3.

use super::{HandshakeType, LEGACY_VERSION, TLS13, X25519};
use crate::tls::{
    CipherSuite, TlsError,
    codec::{Reader, Width},
    extension::{ExtensionType, Extensions},
};

/// The random of a HelloRetryRequest: SHA-256 of "HelloRetryRequest", per RFC 8446, section 4.1.3.
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// A ServerHello.
///
/// ```text
/// legacy_version: u16, random: [32], legacy_session_id_echo <0..32>,
/// cipher_suite: u16, legacy_compression_method: u8 = 0, extensions <6..2^16-1>
/// ```
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
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self, TlsError> {
        let mut reader = Reader::new(body);
        let legacy_version = reader.u16()?;
        let random = reader.array()?;
        // A HelloRetryRequest shares the message type and is told apart by its random alone.
        if random == HELLO_RETRY_REQUEST_RANDOM {
            return Err(TlsError::HelloRetryRequest);
        }
        let session_id = reader.vector(Width::U8, 0, 32, 1)?.rest();
        let cipher_suite = reader.u16()?;
        if reader.u8()? != 0 {
            return Err(TlsError::InvalidCompression);
        }
        let extensions = Extensions::read(&mut reader, 6)?;
        reader.finish()?;
        Ok(Self {
            legacy_version,
            random,
            session_id,
            cipher_suite,
            extensions,
        })
    }

    /// The framed ServerHello this stack sends: TLS 1.3, one suite, and an X25519 share.
    pub(crate) fn encode(random: &[u8; 32], suite: CipherSuite, key_share: &[u8; 32]) -> Vec<u8> {
        HandshakeType::SERVER_HELLO.frame(|body| {
            body.u16(LEGACY_VERSION);
            body.bytes(random);
            // QUIC clients send no session id, so the echo is empty, per RFC 9001, section 8.4.
            body.vector(Width::U8, |_| {});
            body.u16(suite.code());
            body.u8(0);
            body.vector(Width::U16, |block| {
                Extensions::write(block, ExtensionType::SUPPORTED_VERSIONS, |version| {
                    version.u16(TLS13);
                });
                Extensions::write(block, ExtensionType::KEY_SHARE, |share| {
                    Extensions::write_key_share(share, X25519, key_share);
                });
            });
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::message::Message;

    #[test]
    fn encoding_parses_back() {
        let message = Message::from_raw(ServerHello::encode(
            &[5; 32],
            CipherSuite::ChaCha20Poly1305Sha256,
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
        let mut raw = ServerHello::encode(&[5; 32], CipherSuite::Aes128GcmSha256, &[6; 32]);
        raw[6..38].copy_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
        assert_eq!(
            ServerHello::parse(&raw[4..]),
            Err(TlsError::HelloRetryRequest)
        );
    }
}
