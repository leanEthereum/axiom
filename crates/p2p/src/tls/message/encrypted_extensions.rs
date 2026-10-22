//! The EncryptedExtensions message, per RFC 8446, section 4.3.1.

use super::HandshakeType;
use crate::tls::{
    ALPN, TlsError,
    codec::{Reader, Width},
    extension::{ExtensionType, Extensions},
};

/// The server's extensions that need no key share: here ALPN and the transport parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncryptedExtensions<'a> {
    /// The extensions.
    pub(crate) extensions: Extensions<'a>,
}

impl<'a> EncryptedExtensions<'a> {
    /// Parses a body.
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self, TlsError> {
        let mut reader = Reader::new(body);
        let extensions = Extensions::read(&mut reader, 0)?;
        reader.finish()?;
        Ok(Self { extensions })
    }

    /// The framed message this stack sends: the libp2p protocol and the transport parameters.
    pub(crate) fn encode(transport_parameters: &[u8]) -> Vec<u8> {
        HandshakeType::ENCRYPTED_EXTENSIONS.frame(|body| {
            body.vector(Width::U16, |block| {
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
