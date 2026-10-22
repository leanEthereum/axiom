//! The Certificate message, per RFC 8446, section 4.4.2.

use super::HandshakeType;
use crate::tls::{
    TlsError,
    codec::{Reader, Width},
};

/// One entry of a certificate list: the DER certificate and its extensions block.
pub(crate) type CertificateEntry<'a> = (&'a [u8], &'a [u8]);

/// A certificate chain.
///
/// ```text
/// certificate_request_context <0..2^8-1>
/// certificate_list <0..2^24-1> of { cert_data <1..2^24-1>, extensions <0..2^16-1> }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateMessage<'a> {
    /// The context, which echoes the request's.
    pub(crate) context: &'a [u8],
    /// The entries, end-entity first.
    pub(crate) entries: Vec<CertificateEntry<'a>>,
}

impl<'a> CertificateMessage<'a> {
    /// Parses a body.
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self, TlsError> {
        let mut reader = Reader::new(body);
        let context = reader.vector(Width::U8, 0, 0xff, 1)?.rest();
        let mut list = reader.vector(Width::U24, 0, 0xff_ffff, 1)?;
        reader.finish()?;
        let mut entries = Vec::new();
        while !list.is_empty() {
            let certificate = list.vector(Width::U24, 1, 0xff_ffff, 1)?.rest();
            let extensions = list.vector(Width::U16, 0, 0xffff, 1)?.rest();
            entries.push((certificate, extensions));
        }
        Ok(Self { context, entries })
    }

    /// The framed message this stack sends: an empty context and one certificate.
    pub(crate) fn encode(certificate: &[u8]) -> Vec<u8> {
        HandshakeType::CERTIFICATE.frame(|body| {
            body.vector(Width::U8, |_| {});
            body.vector(Width::U24, |list| {
                list.vector(Width::U24, |entry| entry.bytes(certificate));
                list.vector(Width::U16, |_| {});
            });
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_parses_back() {
        let raw = CertificateMessage::encode(&[0x30, 0x00]);
        assert_eq!(
            CertificateMessage::parse(&raw[4..]),
            Ok(CertificateMessage {
                context: &[],
                entries: vec![(&[0x30, 0x00][..], &[][..])],
            })
        );
    }
}
