//! The CertificateRequest message, per RFC 8446, section 4.3.2.

use super::{ECDSA_SECP256R1_SHA256, HandshakeType};
use crate::tls::{
    TlsError,
    codec::{Reader, Width},
    extension::{ExtensionType, Extensions},
};

/// A request for the client's certificate.
///
/// ```text
/// certificate_request_context <0..2^8-1>, extensions <2..2^16-1>
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateRequest<'a> {
    /// The context, empty during the handshake.
    pub(crate) context: &'a [u8],
    /// The extensions; signature_algorithms is required.
    pub(crate) extensions: Extensions<'a>,
}

impl<'a> CertificateRequest<'a> {
    /// Parses a body.
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self, TlsError> {
        let mut reader = Reader::new(body);
        let context = reader.vector(Width::U8, 0, 0xff, 1)?.rest();
        let extensions = Extensions::read(&mut reader, 2)?;
        reader.finish()?;
        Ok(Self {
            context,
            extensions,
        })
    }

    /// The framed request this stack sends: an empty context, and ECDSA P-256 signatures only.
    pub(crate) fn encode() -> Vec<u8> {
        HandshakeType::CERTIFICATE_REQUEST.frame(|body| {
            body.vector(Width::U8, |_| {});
            body.vector(Width::U16, |block| {
                Extensions::write(block, ExtensionType::SIGNATURE_ALGORITHMS, |schemes| {
                    schemes.vector(Width::U16, |list| list.u16(ECDSA_SECP256R1_SHA256));
                });
            });
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_parses_back() {
        let raw = CertificateRequest::encode();
        let request = CertificateRequest::parse(&raw[4..]).unwrap();
        assert_eq!(request.context, &[] as &[u8]);
        assert_eq!(
            request.extensions.signature_algorithms(),
            Ok(Some(vec![0x0403]))
        );
    }
}
