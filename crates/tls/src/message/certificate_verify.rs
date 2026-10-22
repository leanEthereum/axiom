//! The CertificateVerify message, per RFC 8446, section 4.4.3.

use super::HandshakeType;
use crate::{
    ProtocolError, SignatureScheme,
    codec::{Reader, Width},
};

/// The 64 spaces that open the signed content.
const PAD: [u8; 64] = [0x20; 64];

/// A signature over the transcript by the certificate key.
///
/// ```text
/// algorithm: u16, signature <0..2^16-1>
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateVerify<'a> {
    /// The signature scheme.
    pub(crate) scheme: SignatureScheme,
    /// The signature, DER for ECDSA.
    pub(crate) signature: &'a [u8],
}

impl<'a> CertificateVerify<'a> {
    /// The context string of a server signature.
    pub(crate) const SERVER_CONTEXT: &'static [u8] = b"TLS 1.3, server CertificateVerify";

    /// The context string of a client signature.
    pub(crate) const CLIENT_CONTEXT: &'static [u8] = b"TLS 1.3, client CertificateVerify";

    /// Parses a body.
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut reader = Reader::new(body);
        let scheme = SignatureScheme(reader.u16()?);
        let signature = reader.vector(Width::U16, 0, 0xffff, 1)?.rest();
        reader.finish()?;
        Ok(Self { scheme, signature })
    }

    /// The framed message carrying a signature under a scheme.
    pub(crate) fn encode(scheme: SignatureScheme, signature: &[u8]) -> Vec<u8> {
        HandshakeType::CERTIFICATE_VERIFY.frame(|body| {
            body.u16(scheme.0);
            body.vector(Width::U16, |value| value.bytes(signature));
        })
    }

    /// The content the signature covers.
    ///
    /// ```text
    /// 0x20 * 64 || context string || 0x00 || transcript hash
    /// ```
    ///
    /// The padding and the role-specific string keep a signature from serving another purpose.
    pub(crate) fn signed_content(context: &[u8], transcript_hash: &[u8; 32]) -> Vec<u8> {
        [&PAD[..], context, &[0], transcript_hash].concat()
    }
}
