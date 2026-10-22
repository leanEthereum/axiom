//! The ClientHello, per RFC 8446, section 4.1.2.

use super::{ECDSA_SECP256R1_SHA256, HandshakeType, LEGACY_VERSION, TLS13, X25519};
use crate::tls::{
    ALPN, CipherSuite, TlsError,
    codec::{Reader, Width},
    extension::{ExtensionType, Extensions},
};

/// A ClientHello.
///
/// ```text
/// legacy_version: u16, random: [32], legacy_session_id <0..32>,
/// cipher_suites <2..2^16-2>, legacy_compression_methods <1..2^8-1>, extensions <8..2^16-1>
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientHello<'a> {
    /// The legacy version field; 0x0303 in TLS 1.3.
    pub(crate) legacy_version: u16,
    /// The client random.
    pub(crate) random: [u8; 32],
    /// The legacy session id.
    pub(crate) session_id: &'a [u8],
    /// The offered suite code points, in preference order.
    pub(crate) cipher_suites: Vec<u16>,
    /// The extensions.
    pub(crate) extensions: Extensions<'a>,
}

impl<'a> ClientHello<'a> {
    /// Parses a body, refusing compression other than the null method.
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self, TlsError> {
        let mut reader = Reader::new(body);
        let legacy_version = reader.u16()?;
        let random = reader.array()?;
        let session_id = reader.vector(Width::U8, 0, 32, 1)?.rest();
        let mut suites = reader.vector(Width::U16, 2, 0xfffe, 2)?;
        let mut cipher_suites = Vec::new();
        while !suites.is_empty() {
            cipher_suites.push(suites.u16()?);
        }
        // RFC 8446, section 4.1.2: exactly one byte, the null method 0.
        if reader.vector(Width::U8, 1, 0xff, 1)?.rest() != [0] {
            return Err(TlsError::InvalidCompression);
        }
        let extensions = Extensions::read(&mut reader, 8)?;
        reader.finish()?;
        Ok(Self {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            extensions,
        })
    }

    /// The framed ClientHello this stack sends.
    ///
    /// It offers both suites, TLS 1.3 only, one X25519 share, and ECDSA P-256 signatures.
    /// It names no server, sends no session id, and offers no pre-shared key.
    pub(crate) fn encode(
        random: &[u8; 32],
        key_share: &[u8; 32],
        transport_parameters: &[u8],
    ) -> Vec<u8> {
        HandshakeType::CLIENT_HELLO.frame(|body| {
            body.u16(LEGACY_VERSION);
            body.bytes(random);
            body.vector(Width::U8, |_| {});
            body.vector(Width::U16, |suites| {
                for suite in CipherSuite::ALL {
                    suites.u16(suite.code());
                }
            });
            body.vector(Width::U8, |methods| methods.u8(0));
            body.vector(Width::U16, |block| {
                Extensions::write(block, ExtensionType::SUPPORTED_VERSIONS, |versions| {
                    versions.vector(Width::U8, |list| list.u16(TLS13));
                });
                Extensions::write(block, ExtensionType::SUPPORTED_GROUPS, |groups| {
                    groups.vector(Width::U16, |list| list.u16(X25519));
                });
                Extensions::write(block, ExtensionType::SIGNATURE_ALGORITHMS, |schemes| {
                    schemes.vector(Width::U16, |list| list.u16(ECDSA_SECP256R1_SHA256));
                });
                Extensions::write(block, ExtensionType::KEY_SHARE, |shares| {
                    shares.vector(Width::U16, |list| {
                        Extensions::write_key_share(list, X25519, key_share);
                    });
                });
                Extensions::write_alpn(block, ALPN);
                Extensions::write(
                    block,
                    ExtensionType::QUIC_TRANSPORT_PARAMETERS,
                    |parameters| {
                        parameters.bytes(transport_parameters);
                    },
                );
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
        let raw = ClientHello::encode(&[1; 32], &[2; 32], &[3, 4]);
        let message = Message::from_raw(raw);
        assert_eq!(message.kind(), HandshakeType::CLIENT_HELLO);
        let hello = ClientHello::parse(message.body()).unwrap();
        assert_eq!(hello.legacy_version, 0x0303);
        assert_eq!(hello.random, [1; 32]);
        assert_eq!(hello.session_id, &[] as &[u8]);
        assert_eq!(hello.cipher_suites, [0x1301, 0x1303]);
        assert_eq!(
            hello.extensions.supported_versions(),
            Ok(Some(vec![0x0304]))
        );
        assert_eq!(
            hello.extensions.client_key_shares(),
            Ok(Some(vec![(0x001d, &[2; 32][..])]))
        );
        assert_eq!(
            hello
                .extensions
                .get(ExtensionType::QUIC_TRANSPORT_PARAMETERS),
            Some(&[3, 4][..])
        );
        // No server_name, type 0, per the libp2p TLS spec.
        assert_eq!(hello.extensions.get(ExtensionType(0)), None);
    }

    #[test]
    fn compression_must_be_null() {
        // Mutation: the compression list 01 00 becomes 01 01.
        let raw = ClientHello::encode(&[1; 32], &[2; 32], &[]);
        let mut body = raw[4..].to_vec();
        // version 2, random 32, session id 1, suites 2 + 4, then the compression length.
        body[2 + 32 + 1 + 6 + 1] = 0x01;
        assert_eq!(ClientHello::parse(&body), Err(TlsError::InvalidCompression));
    }
}
