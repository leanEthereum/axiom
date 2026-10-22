//! The ClientHello, per RFC 8446, section 4.1.2.

use super::{HandshakeType, LEGACY_VERSION};
use crate::{
    NamedGroup, ProtocolError, SignatureScheme,
    codec::{Reader, Width, Writer},
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

/// What a client proposes in its hello.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Offer<'a> {
    /// The client random.
    pub(crate) random: &'a [u8; 32],
    /// The legacy session id: 32 random bytes over TCP, empty over QUIC.
    pub(crate) session_id: &'a [u8],
    /// The suite code points, TLS 1.3 then TLS 1.2.
    pub(crate) suites: &'a [u16],
    /// The protocol versions, newest first.
    pub(crate) versions: &'a [u16],
    /// The key exchange groups.
    pub(crate) groups: &'a [NamedGroup],
    /// One public key share per group.
    pub(crate) shares: &'a [(NamedGroup, Vec<u8>)],
    /// The signature schemes accepted from the server.
    pub(crate) schemes: &'a [SignatureScheme],
    /// The DNS name of the server, if it has one.
    pub(crate) server_name: Option<&'a str>,
    /// The application protocols, in preference order.
    pub(crate) alpn: &'a [Vec<u8>],
    /// QUIC transport parameters, over QUIC only.
    pub(crate) quic_parameters: Option<&'a [u8]>,
    /// Whether TLS 1.2 is offered too, which adds its own extensions.
    pub(crate) tls12: bool,
}

impl<'a> ClientHello<'a> {
    /// Parses a body, refusing compression other than the null method.
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self, ProtocolError> {
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
            return Err(ProtocolError::InvalidCompression);
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

    /// The framed ClientHello of an offer.
    ///
    /// It never offers a pre-shared key, early data, or a session ticket.
    pub(crate) fn encode(offer: &Offer<'_>) -> Vec<u8> {
        HandshakeType::CLIENT_HELLO.frame(|body| {
            body.u16(LEGACY_VERSION);
            body.bytes(offer.random);
            body.vector(Width::U8, |id| id.bytes(offer.session_id));
            body.vector(Width::U16, |suites| {
                for &suite in offer.suites {
                    suites.u16(suite);
                }
            });
            body.vector(Width::U8, |methods| methods.u8(0));
            body.vector(Width::U16, |block| Self::write_extensions(block, offer));
        })
    }

    /// Writes the extensions of an offer.
    fn write_extensions(block: &mut Writer, offer: &Offer<'_>) {
        if let Some(host) = offer.server_name {
            Extensions::write_server_name(block, host.as_bytes());
        }
        Extensions::write(block, ExtensionType::SUPPORTED_VERSIONS, |versions| {
            versions.vector(Width::U8, |list| {
                for &version in offer.versions {
                    list.u16(version);
                }
            });
        });
        Extensions::write(block, ExtensionType::SUPPORTED_GROUPS, |groups| {
            groups.vector(Width::U16, |list| {
                for group in offer.groups {
                    list.u16(group.0);
                }
            });
        });
        Extensions::write(block, ExtensionType::SIGNATURE_ALGORITHMS, |schemes| {
            schemes.vector(Width::U16, |list| {
                for scheme in offer.schemes {
                    list.u16(scheme.0);
                }
            });
        });
        Extensions::write(block, ExtensionType::KEY_SHARE, |shares| {
            shares.vector(Width::U16, |list| {
                for (group, share) in offer.shares {
                    Extensions::write_key_share(list, group.0, share);
                }
            });
        });
        if !offer.alpn.is_empty() {
            Extensions::write_alpn(block, offer.alpn);
        }
        if offer.tls12 {
            // RFC 8422, section 5.1.2: only the uncompressed point format.
            Extensions::write(block, ExtensionType::EC_POINT_FORMATS, |formats| {
                formats.vector(Width::U8, |list| list.u8(0));
            });
            Extensions::write(block, ExtensionType::EXTENDED_MASTER_SECRET, |_| {});
            // RFC 5746, section 3.4: an empty renegotiated_connection marks a first handshake.
            Extensions::write(block, ExtensionType::RENEGOTIATION_INFO, |info| {
                info.vector(Width::U8, |_| {});
            });
        }
        if let Some(parameters) = offer.quic_parameters {
            Extensions::write(block, ExtensionType::QUIC_TRANSPORT_PARAMETERS, |body| {
                body.bytes(parameters)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;

    /// A QUIC offer: one suite pair, TLS 1.3 only, one X25519 share, no server name.
    fn quic_offer<'a>(shares: &'a [(NamedGroup, Vec<u8>)], alpn: &'a [Vec<u8>]) -> Offer<'a> {
        Offer {
            random: &[1; 32],
            session_id: &[],
            suites: &[0x1301, 0x1303],
            versions: &[0x0304],
            groups: &[NamedGroup::X25519],
            shares,
            schemes: &[SignatureScheme::ECDSA_SECP256R1_SHA256],
            server_name: None,
            alpn,
            quic_parameters: Some(&[3, 4]),
            tls12: false,
        }
    }

    #[test]
    fn encoding_parses_back() {
        let shares = [(NamedGroup::X25519, vec![2; 32])];
        let alpn = [b"libp2p".to_vec()];
        let raw = ClientHello::encode(&quic_offer(&shares, &alpn));
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
        // No server_name and no TLS 1.2 extensions, as the libp2p TLS spec has it.
        assert_eq!(hello.extensions.get(ExtensionType::SERVER_NAME), None);
        assert_eq!(
            hello.extensions.get(ExtensionType::RENEGOTIATION_INFO),
            None
        );
    }

    #[test]
    fn tcp_offer_carries_name_and_tls12_extensions() {
        let shares = [(NamedGroup::X25519, vec![2; 32])];
        let offer = Offer {
            session_id: &[7; 32],
            server_name: Some("example.com"),
            versions: &[0x0304, 0x0303],
            quic_parameters: None,
            tls12: true,
            ..quic_offer(&shares, &[])
        };
        let message = Message::from_raw(ClientHello::encode(&offer));
        let hello = ClientHello::parse(message.body()).unwrap();
        assert_eq!(hello.session_id, &[7; 32]);
        // 00 0e: list length, 00: host_name, 00 0b: name length, then the name.
        let mut server_name = vec![0x00, 0x0e, 0x00, 0x00, 0x0b];
        server_name.extend_from_slice(b"example.com");
        assert_eq!(
            hello.extensions.get(ExtensionType::SERVER_NAME),
            Some(&server_name[..])
        );
        assert_eq!(
            hello.extensions.get(ExtensionType::RENEGOTIATION_INFO),
            Some(&[0][..])
        );
        assert_eq!(
            hello.extensions.get(ExtensionType::EXTENDED_MASTER_SECRET),
            Some(&[][..])
        );
        assert_eq!(hello.extensions.alpn(), Ok(None));
    }

    #[test]
    fn compression_must_be_null() {
        // Mutation: the compression list 01 00 becomes 01 01.
        let shares = [(NamedGroup::X25519, vec![2; 32])];
        let raw = ClientHello::encode(&quic_offer(&shares, &[]));
        let mut body = raw[4..].to_vec();
        // version 2, random 32, session id 1, suites 2 + 4, then the compression length.
        body[2 + 32 + 1 + 6 + 1] = 0x01;
        assert_eq!(
            ClientHello::parse(&body),
            Err(ProtocolError::InvalidCompression)
        );
    }
}
