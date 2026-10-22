//! The TLS 1.2 handshake messages that differ from TLS 1.3's, per RFC 5246 and RFC 8422.

use crate::{
    NamedGroup, ProtocolError, SignatureScheme,
    codec::{Reader, Width},
    message::HandshakeType,
};

/// The ECCurveType of a named curve, per RFC 8422, section 5.4.
const NAMED_CURVE: u8 = 3;

/// Bytes of TLS 1.2 Finished verify data, per RFC 5246, section 7.4.9.
pub(crate) const VERIFY_DATA_LEN: usize = 12;

/// A TLS 1.2 certificate chain: no request context, no per-entry extensions.
///
/// ```text
/// certificate_list <0..2^24-1> of ASN.1Cert <1..2^24-1>
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Certificate12<'a> {
    /// The DER certificates, the server's first.
    pub(crate) chain: Vec<&'a [u8]>,
}

impl<'a> Certificate12<'a> {
    /// Parses a body.
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut reader = Reader::new(body);
        let mut list = reader.vector(Width::U24, 0, 0xff_ffff, 1)?;
        reader.finish()?;
        let mut chain = Vec::new();
        while !list.is_empty() {
            chain.push(list.vector(Width::U24, 1, 0xff_ffff, 1)?.rest());
        }
        Ok(Self { chain })
    }

    /// The framed empty chain a client sends when asked for a certificate it does not have.
    pub(crate) fn encode_empty() -> Vec<u8> {
        HandshakeType::CERTIFICATE.frame(|body| body.vector(Width::U24, |_| {}))
    }
}

/// An ECDHE ServerKeyExchange: the server's ephemeral key, signed.
///
/// ```text
/// ServerECDHParams { curve_type: u8 = 3, namedcurve: u16, point <1..2^8-1> }
/// signed_params { algorithm: u16, signature <0..2^16-1> }
/// ```
///
/// The signature covers client_random || server_random || ServerECDHParams.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerKeyExchange<'a> {
    /// The encoded ServerECDHParams, as signed.
    pub(crate) params: &'a [u8],
    /// The group of the server's key.
    pub(crate) group: NamedGroup,
    /// The server's public value.
    pub(crate) public: &'a [u8],
    /// The signature scheme.
    pub(crate) scheme: SignatureScheme,
    /// The signature.
    pub(crate) signature: &'a [u8],
}

impl<'a> ServerKeyExchange<'a> {
    /// Parses a body, refusing explicit curves.
    pub(crate) fn parse(body: &'a [u8]) -> Result<Self, ProtocolError> {
        let mut reader = Reader::new(body);
        let start = reader;
        let curve_type = reader.u8()?;
        if curve_type != NAMED_CURVE {
            return Err(ProtocolError::UnsupportedCurveType(curve_type));
        }
        let group = NamedGroup(reader.u16()?);
        let public = reader.vector(Width::U8, 1, 0xff, 1)?.rest();
        let params = &start.remaining()[..4 + public.len()];
        let scheme = SignatureScheme(reader.u16()?);
        let signature = reader.vector(Width::U16, 0, 0xffff, 1)?.rest();
        reader.finish()?;
        Ok(Self {
            params,
            group,
            public,
            scheme,
            signature,
        })
    }
}

/// A TLS 1.2 CertificateRequest, checked for structure and otherwise ignored.
///
/// ```text
/// certificate_types <1..2^8-1>, supported_signature_algorithms <2..2^16-2>,
/// certificate_authorities <0..2^16-1>
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CertificateRequest12;

impl CertificateRequest12 {
    /// Checks a body's structure.
    pub(crate) fn check(body: &[u8]) -> Result<(), ProtocolError> {
        let mut reader = Reader::new(body);
        reader.vector(Width::U8, 1, 0xff, 1)?;
        reader.vector(Width::U16, 2, 0xfffe, 2)?;
        reader.vector(Width::U16, 0, 0xffff, 1)?;
        reader.finish()
    }
}

/// The client's ECDHE public value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClientKeyExchange;

impl ClientKeyExchange {
    /// The framed message carrying a public value.
    pub(crate) fn encode(public: &[u8]) -> Vec<u8> {
        HandshakeType::CLIENT_KEY_EXCHANGE.frame(|body| {
            body.vector(Width::U8, |point| point.bytes(public));
        })
    }
}

/// The TLS 1.2 Finished message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Finished12;

impl Finished12 {
    /// Parses a body of exactly 12 bytes.
    pub(crate) fn parse(body: &[u8]) -> Result<[u8; VERIFY_DATA_LEN], ProtocolError> {
        let mut reader = Reader::new(body);
        let verify_data = reader.array()?;
        reader.finish()?;
        Ok(verify_data)
    }

    /// The framed message.
    pub(crate) fn encode(verify_data: &[u8; VERIFY_DATA_LEN]) -> Vec<u8> {
        HandshakeType::FINISHED.frame(|body| body.bytes(verify_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_key_exchange_fields() {
        // named_curve, x25519, a 2-byte point, ecdsa_secp256r1_sha256, a 1-byte signature.
        let body = [
            0x03, 0x00, 0x1d, 0x02, 0xaa, 0xbb, 0x04, 0x03, 0x00, 0x01, 0xcc,
        ];
        let exchange = ServerKeyExchange::parse(&body).unwrap();
        assert_eq!(exchange.params, &body[..6]);
        assert_eq!(exchange.group, NamedGroup::X25519);
        assert_eq!(exchange.public, &[0xaa, 0xbb]);
        assert_eq!(exchange.scheme, SignatureScheme::ECDSA_SECP256R1_SHA256);
        assert_eq!(exchange.signature, &[0xcc]);

        // Mutation: explicit_prime curve type 1.
        let mut explicit = body;
        explicit[0] = 1;
        assert_eq!(
            ServerKeyExchange::parse(&explicit),
            Err(ProtocolError::UnsupportedCurveType(1))
        );
    }

    #[test]
    fn chains_and_requests() {
        // Two certificates of one and two bytes.
        let body = [0, 0, 9, 0, 0, 1, 0xaa, 0, 0, 2, 0xbb, 0xcc];
        assert_eq!(
            Certificate12::parse(&body),
            Ok(Certificate12 {
                chain: vec![&[0xaa][..], &[0xbb, 0xcc][..]]
            })
        );
        assert_eq!(Certificate12::encode_empty(), [11, 0, 0, 3, 0, 0, 0]);
        // ecdsa_sign, ecdsa_secp256r1_sha256, no authorities.
        assert_eq!(
            CertificateRequest12::check(&[1, 64, 0, 2, 4, 3, 0, 0]),
            Ok(())
        );
    }
}
