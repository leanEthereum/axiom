//! The EncryptedExtensions message, per RFC 8446, section 4.3.1.

use super::HandshakeType;
use crate::{
    ProtocolError,
    codec::{Reader, Width},
    extension::{ExtensionType, Extensions},
};

/// The server's extensions that need no key share: ALPN, the server name, and QUIC parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncryptedExtensions<'a> {
    /// The extensions.
    pub(crate) extensions: Extensions<'a>,
}

impl<'a> EncryptedExtensions<'a> {
    /// Parses a body.
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut reader = Reader::new(body);
        let extensions = Extensions::read(&mut reader, 0)?;
        reader.finish()?;
        Ok(Self { extensions })
    }

    /// The framed message: the selected protocol, the server name acknowledgment, and QUIC parameters.
    pub(crate) fn encode(
        protocol: Option<&[u8]>,
        server_name: bool,
        quic_parameters: Option<&[u8]>,
    ) -> Vec<u8> {
        HandshakeType::ENCRYPTED_EXTENSIONS.frame(|body| {
            body.vector(Width::U16, |block| {
                // RFC 6066, section 3: the acknowledgment of a used server name is empty.
                if server_name {
                    Extensions::write(block, ExtensionType::SERVER_NAME, |_| {});
                }
                if let Some(protocol) = protocol {
                    Extensions::write_alpn(block, &[protocol]);
                }
                if let Some(parameters) = quic_parameters {
                    Extensions::write(block, ExtensionType::QUIC_TRANSPORT_PARAMETERS, |body| {
                        body.bytes(parameters);
                    });
                }
            });
        })
    }
}
